package ssh

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestFullDuplexCopyStopsWhenContextIsCancelledAfterOneStreamEnds(t *testing.T) {
	left, leftPeer := net.Pipe()
	right, rightPeer := net.Pipe()
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
}

func (*testReadWriteCloser) Close() error {
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
