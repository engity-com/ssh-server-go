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
		GracefulShutdownHandler: func(ctx context.Context) time.Duration {
			gracefulCalls.Add(1)
			require.ErrorIs(t, context.Cause(ctx), context.Canceled)
			return time.Second
		},
		Handler: func(session Session) {
			handlerStarted <- session.Context()
			<-releaseHandler
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
	var gracefulCalls atomic.Int32
	var callbackContext context.Context
	srv := &Server{
		GracefulShutdownHandler: func(ctx context.Context) time.Duration {
			gracefulCalls.Add(1)
			callbackContext = ctx
			return period
		},
	}
	listener := newLocalListener()
	ctx, cancel := context.WithCancelCause(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- srv.Serve(ctx, listener) }()

	conn, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	defer closeQuietly(conn)
	require.Eventually(t, func() bool {
		return activeConnectionCount(srv) == 1
	}, time.Second, time.Millisecond)

	started := time.Now()
	cancel(expected)
	err = <-serveDone
	require.ErrorIs(t, err, expected)
	require.ErrorIs(t, err, ErrGracefulShutdownTimeout)
	require.GreaterOrEqual(t, time.Since(started), period)
	require.Equal(t, ctx, callbackContext)
	require.Equal(t, int32(1), gracefulCalls.Load())
	require.Zero(t, activeConnectionCount(srv))
	srv.mu.RLock()
	require.Zero(t, srv.startups)
	srv.mu.RUnlock()

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(time.Second)))
	_, err = conn.Read(make([]byte, 1))
	if netErr, ok := errors.AsType[net.Error](err); ok {
		require.False(t, netErr.Timeout(), "connection was not force-closed")
	}
}

func TestServeScopesAreIndependentAndReusable(t *testing.T) {
	srv := &Server{}
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
	require.Eventually(t, func() bool {
		return activeConnectionCount(srv) == 2
	}, time.Second, time.Millisecond)

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
	require.Eventually(t, func() bool {
		return activeConnectionCount(srv) == 2
	}, time.Second, time.Millisecond)
	cancelSecond()
	require.ErrorIs(t, <-secondDone, context.Canceled)

	thirdListener := newLocalListener()
	thirdCtx, cancelThird := context.WithCancel(context.Background())
	thirdDone := make(chan error, 1)
	go func() { thirdDone <- srv.Serve(thirdCtx, thirdListener) }()
	thirdConn, err := net.Dial("tcp", thirdListener.Addr().String())
	require.NoError(t, err)
	defer closeQuietly(thirdConn)
	require.Eventually(t, func() bool {
		return activeConnectionCount(srv) == 1
	}, time.Second, time.Millisecond)
	cancelThird()
	require.ErrorIs(t, <-thirdDone, context.Canceled)
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

func TestServeCancellationClosesListenerDuringInitialization(t *testing.T) {
	srv := &Server{}
	listener := &closeNotifyingListener{
		Listener: newLocalListener(),
		closed:   make(chan struct{}),
	}
	srv.configMu.Lock()
	configLocked := true
	defer func() {
		if configLocked {
			srv.configMu.Unlock()
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- srv.Serve(ctx, listener) }()
	require.Eventually(t, func() bool {
		srv.mu.RLock()
		defer srv.mu.RUnlock()
		return len(srv.scopes) == 1
	}, time.Second, time.Millisecond)

	cancel()
	select {
	case <-listener.closed:
	case <-time.After(time.Second):
		t.Fatal("context cancellation did not close the listener during initialization")
	}
	srv.configMu.Unlock()
	configLocked = false
	require.ErrorIs(t, <-serveDone, context.Canceled)
	require.Equal(t, int32(1), listener.closeCalls.Load())
}

func TestServeInitializationFailureDoesNotCloseListenerTwice(t *testing.T) {
	srv := &Server{RequireHostSigners: true}
	listener := &closeNotifyingListener{
		Listener: newLocalListener(),
		closed:   make(chan struct{}),
	}
	srv.configMu.Lock()
	configLocked := true
	defer func() {
		if configLocked {
			srv.configMu.Unlock()
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- srv.Serve(ctx, listener) }()
	require.Eventually(t, func() bool {
		srv.mu.RLock()
		defer srv.mu.RUnlock()
		return len(srv.scopes) == 1
	}, time.Second, time.Millisecond)

	cancel()
	<-listener.closed
	srv.configMu.Unlock()
	configLocked = false
	require.ErrorIs(t, <-serveDone, ErrServerHostSignerRequired)
	require.Equal(t, int32(1), listener.closeCalls.Load())
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
	srv := &Server{Handler: func(session Session) {
		unregister := registerConnectionResource(session.Context(), func() { closeQuietly(resourceListener) })
		defer unregister()
		close(resourceRegistered)
		<-releaseHandler
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
		GracefulShutdownHandler: func(context.Context) time.Duration {
			gracefulCalls.Add(1)
			return -time.Second
		},
		ConnCallback: func(ctx Context, conn net.Conn) net.Conn {
			callbackEntered <- ctx
			<-releaseCallback
			close(callbackDone)
			return conn
		},
		ConnectionFailedCallback: func(net.Conn, error) {
			failureCalls.Add(1)
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
	require.NoError(t, srv.SetOption(NoPty()))

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
