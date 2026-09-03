package ssh

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestFullDuplexCopyStopsWhenContextIsCancelledAfterOneStreamEnds(t *testing.T) {
	left, leftPeer := net.Pipe()
	rightConn, rightPeer := net.Pipe()
	right := &testCloseWriteReadWriteCloser{ReadWriteCloser: rightConn}
	t.Cleanup(func() {
		closeQuietly(leftPeer)
		closeQuietly(rightPeer)
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	streamEnded := make(chan bool, 2)
	result := make(chan error, 1)
	go func() {
		result <- FullDuplexCopy(ctx, left, right, &FullDuplexCopyOpts{
			OnStreamEnd: func(isL2r bool, _ error) {
				streamEnded <- isL2r
			},
		})
	}()
	closeQuietly(leftPeer)
	select {
	case isL2r := <-streamEnded:
		require.True(t, isL2r)
	case <-time.After(time.Second):
		t.Fatal("first copy stream did not finish")
	}
	select {
	case err := <-result:
		t.Fatalf("copy finished before context cancellation: %v", err)
	default:
	}
	cancel()

	select {
	case err := <-result:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("copy did not stop after context cancellation")
	}
}

func TestFullDuplexCopyReturnsErrorFromSecondStream(t *testing.T) {
	leftRead := make(chan struct{})
	releaseRight := make(chan struct{})
	expected := errors.New("copy failed")
	left := &testReadWriteCloser{
		Reader: &signallingEOFReader{read: leftRead},
		Writer: io.Discard,
	}
	right := &testReadWriteCloser{
		Reader: &delayedErrorReader{release: releaseRight, err: expected},
		Writer: io.Discard,
	}

	result := make(chan error, 1)
	go func() {
		result <- FullDuplexCopy(context.Background(), left, right, nil)
	}()
	<-leftRead
	close(releaseRight)

	select {
	case err := <-result:
		require.ErrorIs(t, err, expected)
	case <-time.After(time.Second):
		t.Fatal("copy did not finish")
	}
}

func TestFullDuplexCopyClosesBothStreamsWithoutCloseWrite(t *testing.T) {
	blockingReadStarted := make(chan struct{})
	leftClosed := make(chan struct{})
	rightClosed := make(chan struct{})
	blockingReadDone := make(chan struct{})
	left := &testReadWriteCloser{
		Reader:  &delayedErrorReader{release: blockingReadStarted, err: io.EOF},
		Writer:  io.Discard,
		onClose: func() { close(leftClosed) },
	}
	right := &testReadWriteCloser{
		Reader: &closeBlockedReader{
			started: blockingReadStarted,
			closed:  rightClosed,
			done:    blockingReadDone,
		},
		Writer:  io.Discard,
		onClose: func() { close(rightClosed) },
	}

	result := make(chan error, 1)
	go func() {
		result <- FullDuplexCopy(context.Background(), left, right, nil)
	}()

	select {
	case err := <-result:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("copy did not finish after one direction reached EOF")
	}
	for name, closed := range map[string]<-chan struct{}{
		"left stream":            leftClosed,
		"right stream":           rightClosed,
		"blocked copy goroutine": blockingReadDone,
	} {
		select {
		case <-closed:
		case <-time.After(time.Second):
			t.Errorf("%s was not closed", name)
		}
	}
}

func TestFullDuplexCopyHalfClosesStreamsWithCloseWrite(t *testing.T) {
	left := newHalfCloseReadWriteCloser()
	right := newHalfCloseReadWriteCloser()

	require.NoError(t, FullDuplexCopy(context.Background(), left, right, nil))
	for name, stream := range map[string]*halfCloseReadWriteCloser{
		"left stream":  left,
		"right stream": right,
	} {
		select {
		case <-stream.writeClosed:
		default:
			t.Errorf("%s was not half-closed", name)
		}
		select {
		case <-stream.closed:
			t.Errorf("%s was fully closed", name)
		default:
		}
	}
}

func TestFullDuplexCopyCallsOnStartBeforeStreamCallbacks(t *testing.T) {
	started := make(chan struct{})
	ended := make(chan struct{})
	left := &testReadWriteCloser{Reader: bytes.NewReader(nil), Writer: io.Discard}
	right := &testReadWriteCloser{Reader: bytes.NewReader(nil), Writer: io.Discard}
	err := FullDuplexCopy(context.Background(), left, right, &FullDuplexCopyOpts{
		OnStart: func() { close(started) },
		OnEnd:   func(int64, int64, time.Duration, error, *bool) { close(ended) },
		OnStreamStart: func(bool) {
			select {
			case <-started:
			default:
				t.Error("stream callback ran before OnStart")
			}
		},
	})
	require.NoError(t, err)
	select {
	case <-ended:
	case <-time.After(time.Second):
		t.Fatal("observer callbacks did not complete")
	}
}

func TestFullDuplexCopyDoesNotWaitForBlockingObserver(t *testing.T) {
	blocked := make(chan struct{})
	left := &testReadWriteCloser{Reader: bytes.NewReader(nil), Writer: io.Discard}
	right := &testReadWriteCloser{Reader: bytes.NewReader(nil), Writer: io.Discard}
	result := make(chan error, 1)
	go func() {
		result <- FullDuplexCopy(context.Background(), left, right, &FullDuplexCopyOpts{
			OnStreamStart: func(bool) { <-blocked },
		})
	}()
	select {
	case err := <-result:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("blocking observer stalled FullDuplexCopy")
	}
	close(blocked)
}

type testReadWriteCloser struct {
	io.Reader
	io.Writer
	onClose func()
}

func (c *testReadWriteCloser) Close() error {
	if c.onClose != nil {
		c.onClose()
	}
	return nil
}

type testCloseWriteReadWriteCloser struct {
	io.ReadWriteCloser
}

func (*testCloseWriteReadWriteCloser) CloseWrite() error {
	return nil
}

type halfCloseReadWriteCloser struct {
	io.Reader
	io.Writer
	writeClosed chan struct{}
	closed      chan struct{}
}

func newHalfCloseReadWriteCloser() *halfCloseReadWriteCloser {
	return &halfCloseReadWriteCloser{
		Reader:      bytes.NewReader(nil),
		Writer:      io.Discard,
		writeClosed: make(chan struct{}),
		closed:      make(chan struct{}),
	}
}

func (c *halfCloseReadWriteCloser) CloseWrite() error {
	close(c.writeClosed)
	return nil
}

func (c *halfCloseReadWriteCloser) Close() error {
	close(c.closed)
	return nil
}

type signallingEOFReader struct {
	read chan<- struct{}
}

func (r *signallingEOFReader) Read([]byte) (int, error) {
	close(r.read)
	return 0, io.EOF
}

type delayedErrorReader struct {
	release <-chan struct{}
	err     error
}

func (r *delayedErrorReader) Read([]byte) (int, error) {
	<-r.release
	return 0, r.err
}

type closeBlockedReader struct {
	started chan<- struct{}
	closed  <-chan struct{}
	done    chan<- struct{}
	once    sync.Once
}

func (r *closeBlockedReader) Read([]byte) (int, error) {
	r.once.Do(func() { close(r.started) })
	<-r.closed
	close(r.done)
	return 0, io.ErrClosedPipe
}
