package ssh

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestServeGracefullyDrainsResourcesWithoutWaitingForHandler(t *testing.T) {
	type contextKey string
	const key contextKey = "scope-value"

	handlerStarted := make(chan Context, 1)
	releaseHandler := make(chan struct{})
	var gracefulCalls atomic.Int32
	srv := &Server{
		GracefulShutdownHandler: func(ctx context.Context) (time.Duration, error) {
			gracefulCalls.Add(1)
			require.ErrorIs(t, context.Cause(ctx), context.Canceled)
			return time.Second, nil
		},
		Handler: func(session Session) error {
			handlerStarted <- session.Context()
			<-releaseHandler
			return nil
		},
	}
	listener := newLocalListener()
	parent := context.WithValue(context.Background(), key, "value")
	ctx, cancel := context.WithCancel(parent)
	serveDone := make(chan error, 1)
	go func() { serveDone <- srv.Serve(ctx, listener) }()

	session, client, cleanup := newClientSession(t, listener.Addr().String(), nil)
	defer cleanup()
	runDone := make(chan error, 1)
	go func() { runDone <- session.Run("") }()
	connectionCtx := <-handlerStarted
	require.Equal(t, "value", connectionCtx.Value(key))

	cancel()
	select {
	case <-connectionCtx.Done():
		t.Fatal("connection context was canceled during the graceful period")
	case <-time.After(20 * time.Millisecond):
	}
	select {
	case err := <-serveDone:
		t.Fatalf("Serve returned before the connection drained: %v", err)
	case <-time.After(20 * time.Millisecond):
	}

	require.NoError(t, client.Close())
	select {
	case err := <-serveDone:
		require.ErrorIs(t, err, context.Canceled)
		require.NotErrorIs(t, err, ErrGracefulShutdownTimeout)
	case <-time.After(time.Second):
		t.Fatal("Serve waited for the blocked user handler after resources were closed")
	}
	require.Equal(t, int32(1), gracefulCalls.Load())

	close(releaseHandler)
	<-runDone
}

func TestServeGracefulTimeoutForcesConnection(t *testing.T) {
	expected := errors.New("stop requested")
	period := 20 * time.Millisecond
	connectionEntered := make(chan struct{})
	var gracefulCalls atomic.Int32
	var callbackContext context.Context
	srv := &Server{
		ConnCallback: func(_ Context, conn net.Conn) (net.Conn, error) {
			close(connectionEntered)
			return conn, nil
		},
		GracefulShutdownHandler: func(ctx context.Context) (time.Duration, error) {
			gracefulCalls.Add(1)
			callbackContext = ctx
			return period, nil
		},
	}
	listener := newLocalListener()
	ctx, cancel := context.WithCancelCause(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- srv.Serve(ctx, listener) }()

	conn, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	defer closeQuietly(conn)
	<-connectionEntered

	started := time.Now()
	cancel(expected)
	err = <-serveDone
	require.ErrorIs(t, err, expected)
	require.ErrorIs(t, err, ErrGracefulShutdownTimeout)
	require.GreaterOrEqual(t, time.Since(started), period)
	require.Equal(t, ctx, callbackContext)
	require.Equal(t, int32(1), gracefulCalls.Load())

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(time.Second)))
	_, err = conn.Read(make([]byte, 1))
	if netErr, ok := errors.AsType[net.Error](err); ok {
		require.False(t, netErr.Timeout(), "connection was not force-closed")
	}
}

func TestServeScopesAreIndependentAndReusable(t *testing.T) {
	connected := make(chan struct{}, 3)
	srv := &Server{ConnCallback: func(_ Context, conn net.Conn) (net.Conn, error) {
		connected <- struct{}{}
		return conn, nil
	}}
	firstListener := newLocalListener()
	secondListener := newLocalListener()
	firstCtx, cancelFirst := context.WithCancel(context.Background())
	secondCtx, cancelSecond := context.WithCancel(context.Background())
	firstDone := make(chan error, 1)
	secondDone := make(chan error, 1)
	go func() { firstDone <- srv.Serve(firstCtx, firstListener) }()
	go func() { secondDone <- srv.Serve(secondCtx, secondListener) }()

	firstConn, err := net.Dial("tcp", firstListener.Addr().String())
	require.NoError(t, err)
	defer closeQuietly(firstConn)
	secondConn, err := net.Dial("tcp", secondListener.Addr().String())
	require.NoError(t, err)
	defer closeQuietly(secondConn)
	<-connected
	<-connected

	cancelFirst()
	require.ErrorIs(t, <-firstDone, context.Canceled)
	select {
	case err := <-secondDone:
		t.Fatalf("canceling one scope stopped another scope: %v", err)
	default:
	}

	additionalConn, err := net.Dial("tcp", secondListener.Addr().String())
	require.NoError(t, err)
	defer closeQuietly(additionalConn)
	<-connected
	cancelSecond()
	require.ErrorIs(t, <-secondDone, context.Canceled)

	thirdListener := newLocalListener()
	thirdCtx, cancelThird := context.WithCancel(context.Background())
	thirdDone := make(chan error, 1)
	go func() { thirdDone <- srv.Serve(thirdCtx, thirdListener) }()
	thirdConn, err := net.Dial("tcp", thirdListener.Addr().String())
	require.NoError(t, err)
	defer closeQuietly(thirdConn)
	<-connected
	cancelThird()
	require.ErrorIs(t, <-thirdDone, context.Canceled)
}

func TestMaxStartupsIsIndependentPerServe(t *testing.T) {
	contexts := make(chan *serveContext, 2)
	srv := &Server{
		MaxStartups: &MaxStartupsConfig{Start: 1, Full: 1},
		ConnCallback: func(ctx Context, conn net.Conn) (net.Conn, error) {
			serve, _ := ctx.Value(contextKeyServeContext).(*serveContext)
			contexts <- serve
			return conn, nil
		},
	}
	firstListener := newLocalListener()
	secondListener := newLocalListener()
	firstCtx, cancelFirst := context.WithCancel(context.Background())
	secondCtx, cancelSecond := context.WithCancel(context.Background())
	firstDone := make(chan error, 1)
	secondDone := make(chan error, 1)
	go func() { firstDone <- srv.Serve(firstCtx, firstListener) }()
	go func() { secondDone <- srv.Serve(secondCtx, secondListener) }()

	first, err := net.Dial("tcp", firstListener.Addr().String())
	require.NoError(t, err)
	defer closeQuietly(first)
	firstServe := <-contexts
	second, err := net.Dial("tcp", secondListener.Addr().String())
	require.NoError(t, err)
	defer closeQuietly(second)
	secondServe := <-contexts
	require.NotNil(t, firstServe)
	require.NotNil(t, secondServe)
	require.NotSame(t, firstServe, secondServe)
	firstServe.mu.Lock()
	require.Equal(t, 1, firstServe.startups)
	firstServe.mu.Unlock()
	secondServe.mu.Lock()
	require.Equal(t, 1, secondServe.startups)
	secondServe.mu.Unlock()

	overflow, err := net.Dial("tcp", firstListener.Addr().String())
	require.NoError(t, err)
	defer closeQuietly(overflow)
	require.NoError(t, overflow.SetReadDeadline(time.Now().Add(time.Second)))
	_, err = overflow.Read(make([]byte, 1))
	require.Error(t, err)
	if netErr, ok := errors.AsType[net.Error](err); ok {
		require.False(t, netErr.Timeout(), "connection was not rejected at the per-Serve startup limit")
	}

	cancelFirst()
	cancelSecond()
	require.ErrorIs(t, <-firstDone, context.Canceled)
	require.ErrorIs(t, <-secondDone, context.Canceled)
}

func TestServeReturnsAcceptAndListenerCleanupErrors(t *testing.T) {
	acceptErr := errors.New("accept failed")
	closeErr := errors.New("listener close failed")
	listener := &failingListener{acceptErr: acceptErr, closeErr: closeErr}

	err := (&Server{}).Serve(context.Background(), listener)
	require.ErrorIs(t, err, acceptErr)
	require.ErrorIs(t, err, closeErr)
	require.NotErrorIs(t, err, ErrGracefulShutdownTimeout)
	require.Equal(t, int32(1), listener.closeCalls.Load())
}

func TestServeInitializationFailureDoesNotCloseListenerTwice(t *testing.T) {
	srv := &Server{RequireHostSigners: true}
	listener := &closeNotifyingListener{
		Listener: newLocalListener(),
		closed:   make(chan struct{}),
	}
	err := srv.Serve(context.Background(), listener)
	require.ErrorIs(t, err, ErrServerHostSignerRequired)
	<-listener.closed
	require.Equal(t, int32(1), listener.closeCalls.Load())
}

func TestServeCancellationWhileWaitingForPreparationClosesListener(t *testing.T) {
	srv := &Server{}
	srv.prepareOnce.Do(func() {})
	srv.prepareDone = make(chan struct{})
	listener := &closeNotifyingListener{
		Listener: newLocalListener(),
		closed:   make(chan struct{}),
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	require.ErrorIs(t, srv.Serve(ctx, listener), context.Canceled)
	select {
	case <-listener.closed:
	case <-time.After(time.Second):
		t.Fatal("canceled Serve did not close its listener while preparation was pending")
	}
}

func TestHandleConnCancellationWhileWaitingForPreparationClosesConnection(t *testing.T) {
	srv := &Server{}
	srv.prepareOnce.Do(func() {})
	srv.prepareDone = make(chan struct{})
	serverConn, clientConn := net.Pipe()
	defer closeQuietly(clientConn)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	require.ErrorIs(t, srv.HandleConn(ctx, serverConn), context.Canceled)
	_ = clientConn.SetReadDeadline(time.Now().Add(time.Second))
	_, err := clientConn.Read(make([]byte, 1))
	require.Error(t, err)
}

func TestConnectionResourceAcquisitionBlocksCleanupUntilRegistration(t *testing.T) {
	ctx, cancel := newContext(nil)
	defer cancel()
	resources := &connectionResources{}
	ctx.SetValue(contextKeyConnectionResources, resources)
	finishAcquisition, ok := beginConnectionResourceAcquisition(ctx)
	require.True(t, ok)
	cleanupDone := make(chan struct{})
	go func() {
		resources.closeAll()
		close(cleanupDone)
	}()
	require.Eventually(t, func() bool {
		resources.mu.Lock()
		defer resources.mu.Unlock()
		return resources.closed
	}, time.Second, time.Millisecond)
	select {
	case <-cleanupDone:
		t.Fatal("cleanup returned before pending resource registration")
	default:
	}

	resourceClosed := make(chan struct{})
	finishAcquisition(func() { close(resourceClosed) })
	select {
	case <-cleanupDone:
	case <-time.After(time.Second):
		t.Fatal("cleanup did not return after resource registration")
	}
	select {
	case <-resourceClosed:
	default:
		t.Fatal("resource was not closed before cleanup returned")
	}
}

func TestServeClosesRegisteredResourcesBeforeReturning(t *testing.T) {
	resourceListener := newLocalListener()
	resourceAddr := resourceListener.Addr().String()
	resourceRegistered := make(chan struct{})
	releaseHandler := make(chan struct{})
	srv := &Server{Handler: func(session Session) error {
		unregister := registerConnectionResource(session.Context(), func() { closeQuietly(resourceListener) })
		defer unregister()
		close(resourceRegistered)
		<-releaseHandler
		return nil
	}}
	listener := newLocalListener()
	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- srv.Serve(ctx, listener) }()

	session, _, cleanup := newClientSession(t, listener.Addr().String(), nil)
	defer cleanup()
	runDone := make(chan error, 1)
	go func() { runDone <- session.Run("") }()
	<-resourceRegistered
	cancel()
	require.ErrorIs(t, <-serveDone, context.Canceled)

	rebound, err := net.Listen("tcp", resourceAddr)
	require.NoError(t, err)
	closeQuietly(rebound)
	close(releaseHandler)
	<-runDone
}

func TestHandleConnImmediateShutdownReturnsCauseAndCleanupError(t *testing.T) {
	shutdownCause := errors.New("stop connection")
	cleanupErr := errors.New("close failed")
	callbackEntered := make(chan Context, 1)
	releaseCallback := make(chan struct{})
	callbackReleased := false
	defer func() {
		if !callbackReleased {
			close(releaseCallback)
		}
	}()
	callbackDone := make(chan struct{})
	var gracefulCalls atomic.Int32
	var failureCalls atomic.Int32
	srv := &Server{
		GracefulShutdownHandler: func(context.Context) (time.Duration, error) {
			gracefulCalls.Add(1)
			return -time.Second, nil
		},
		ConnCallback: func(ctx Context, conn net.Conn) (net.Conn, error) {
			callbackEntered <- ctx
			<-releaseCallback
			close(callbackDone)
			return conn, nil
		},
		ConnectionFailedCallback: func(Context, net.Conn, error) error {
			failureCalls.Add(1)
			return nil
		},
	}
	serverConn, clientConn := net.Pipe()
	defer closeQuietly(clientConn)
	conn := &closeErrorConn{Conn: serverConn, err: cleanupErr}
	ctx, cancel := context.WithCancelCause(context.Background())
	handleDone := make(chan error, 1)
	go func() { handleDone <- srv.HandleConn(ctx, conn) }()
	var connectionCtx Context
	select {
	case connectionCtx = <-callbackEntered:
	case <-time.After(time.Second):
		t.Fatal("connection callback did not start")
	}

	cancel(shutdownCause)
	var err error
	select {
	case err = <-handleDone:
	case <-time.After(time.Second):
		t.Fatal("HandleConn did not return after context cancellation")
	}
	require.ErrorIs(t, err, shutdownCause)
	require.ErrorIs(t, err, cleanupErr)
	require.NotErrorIs(t, err, ErrGracefulShutdownTimeout)
	require.ErrorIs(t, context.Cause(connectionCtx), shutdownCause)
	require.Equal(t, int32(1), gracefulCalls.Load())
	require.Zero(t, failureCalls.Load())
	close(releaseCallback)
	callbackReleased = true
	select {
	case <-callbackDone:
	case <-time.After(time.Second):
		t.Fatal("connection callback did not finish")
	}
}

type failingListener struct {
	acceptErr  error
	closeErr   error
	closeCalls atomic.Int32
}

func (l *failingListener) Accept() (net.Conn, error) { return nil, l.acceptErr }
func (l *failingListener) Close() error {
	l.closeCalls.Add(1)
	return l.closeErr
}
func (l *failingListener) Addr() net.Addr { return testAddr("failing") }

type closeNotifyingListener struct {
	net.Listener
	closed     chan struct{}
	once       atomic.Bool
	closeCalls atomic.Int32
}

type closeErrorConn struct {
	net.Conn
	err error
}

func (c *closeErrorConn) Close() error {
	closeQuietly(c.Conn)
	return c.err
}

func (l *closeNotifyingListener) Close() error {
	l.closeCalls.Add(1)
	if l.once.CompareAndSwap(false, true) {
		close(l.closed)
	}
	return l.Listener.Close()
}
