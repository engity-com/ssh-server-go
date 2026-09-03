package ssh

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"
)

type callbackErrorEvent struct {
	scope     ErrorScope
	operation ErrorOperation
	err       error
}

type closeCountingConn struct {
	net.Conn
	closes atomic.Int32
}

func (c *closeCountingConn) Close() error {
	c.closes.Add(1)
	return c.Conn.Close()
}

func runFailedHandshake(t *testing.T, srv *Server, config *gossh.ClientConfig) (error, error) {
	t.Helper()
	listener := newLocalListener()
	defer closeQuietly(listener)
	serverDone := make(chan error, 1)
	go func() {
		serverConn, err := listener.Accept()
		if err == nil {
			err = srv.HandleConn(context.Background(), serverConn)
		}
		serverDone <- err
	}()
	if config == nil {
		config = &gossh.ClientConfig{User: "testuser"}
	}
	if config.HostKeyCallback == nil {
		config.HostKeyCallback = gossh.InsecureIgnoreHostKey()
	}
	clientConn, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatalf("dial test server: %v", err)
		return nil, err
	}
	_ = clientConn.SetDeadline(time.Now().Add(time.Second))
	_, _, _, clientErr := gossh.NewClientConn(clientConn, listener.Addr().String(), config)
	closeQuietly(clientConn)
	select {
	case serverErr := <-serverDone:
		return serverErr, clientErr
	case <-time.After(time.Second):
		t.Fatal("server handshake did not stop after callback failure")
		return nil, clientErr
	}
}

func TestConnCallbackErrorUsesConnectionErrorHandling(t *testing.T) {
	expected := errors.New("initialize connection")
	reported := make(chan callbackErrorEvent, 1)
	srv := &Server{
		ConnCallback: func(Context, net.Conn) (net.Conn, error) {
			return nil, expected
		},
		ErrorHandler: func(_ context.Context, scope ErrorScope, operation ErrorOperation, err error, _ ErrorResponder, _ ErrorHandler) (bool, error) {
			reported <- callbackErrorEvent{scope, operation, err}
			return false, err
		},
	}

	serverErr, clientErr := runFailedHandshake(t, srv, nil)
	require.ErrorIs(t, serverErr, expected)
	require.Error(t, clientErr)
	event := <-reported
	require.Equal(t, ErrorScopeConnection, event.scope)
	require.Equal(t, ErrorOperationHandshake, event.operation)
	require.ErrorIs(t, event.err, expected)
}

func TestServerConfigCallbackErrorUsesConnectionErrorHandling(t *testing.T) {
	expected := errors.New("configure connection")
	var received net.Conn
	srv := &Server{ServerConfigCallback: func(_ Context, conn net.Conn, _ *gossh.ServerConfig) error {
		received = conn
		return expected
	}}

	serverErr, clientErr := runFailedHandshake(t, srv, nil)
	require.ErrorIs(t, serverErr, expected)
	require.Error(t, clientErr)
	require.NotNil(t, received)
}

func TestBannerHandlerErrorAbortsHandshakeWithOriginalError(t *testing.T) {
	expected := errors.New("resolve banner")
	var metadataUser, contextUser string
	srv := &Server{
		BannerHandler: func(ctx Context, conn gossh.ConnMetadata) (string, error) {
			metadataUser = conn.User()
			contextUser = ctx.User()
			return "", expected
		},
		PasswordHandler: func(Context, gossh.ConnMetadata, string) (bool, error) {
			return true, nil
		},
	}

	serverErr, clientErr := runFailedHandshake(t, srv, &gossh.ClientConfig{
		User: "banner-user",
		Auth: []gossh.AuthMethod{gossh.Password("password")},
	})
	require.ErrorIs(t, serverErr, expected)
	require.Error(t, clientErr)
	require.Equal(t, "banner-user", metadataUser)
	require.Equal(t, metadataUser, contextUser)
}

func TestAuthenticationHandlerErrorAbortsHandshake(t *testing.T) {
	expected := errors.New("authentication backend unavailable")
	var metadataUser, contextUser string
	srv := &Server{PasswordHandler: func(ctx Context, conn gossh.ConnMetadata, _ string) (bool, error) {
		metadataUser = conn.User()
		contextUser = ctx.User()
		return true, expected
	}}

	serverErr, clientErr := runFailedHandshake(t, srv, &gossh.ClientConfig{
		User: "auth-user",
		Auth: []gossh.AuthMethod{gossh.Password("password")},
	})
	require.ErrorIs(t, serverErr, expected)
	require.Error(t, clientErr)
	require.Equal(t, "auth-user", metadataUser)
	require.Equal(t, metadataUser, contextUser)
}

func TestPublicKeyHandlerErrorAbortsHandshake(t *testing.T) {
	expected := errors.New("public-key backend unavailable")
	signer, err := generateSigner()
	require.NoError(t, err)
	srv := &Server{PublicKeyHandler: func(Context, gossh.ConnMetadata, PublicKey) (bool, error) {
		return true, expected
	}}

	serverErr, clientErr := runFailedHandshake(t, srv, &gossh.ClientConfig{
		User: "auth-user",
		Auth: []gossh.AuthMethod{gossh.PublicKeys(signer)},
	})
	require.ErrorIs(t, serverErr, expected)
	require.Error(t, clientErr)
}

func TestKeyboardInteractiveHandlerErrorAbortsHandshake(t *testing.T) {
	expected := errors.New("keyboard-interactive backend unavailable")
	srv := &Server{KeyboardInteractiveHandler: func(Context, gossh.ConnMetadata, gossh.KeyboardInteractiveChallenge) (bool, error) {
		return true, expected
	}}

	serverErr, clientErr := runFailedHandshake(t, srv, &gossh.ClientConfig{
		User: "auth-user",
		Auth: []gossh.AuthMethod{gossh.KeyboardInteractive(func(string, string, []string, []bool) ([]string, error) {
			return nil, nil
		})},
	})
	require.ErrorIs(t, serverErr, expected)
	require.Error(t, clientErr)
}

func TestSessionCallbackErrorCanPreserveSession(t *testing.T) {
	expected := errors.New("PTY policy unavailable")
	reported := make(chan callbackErrorEvent, 1)
	callbackUser := make(chan string, 1)
	session, _, cleanup := newTestSession(t, &Server{
		Handler: func(Session) error { return nil },
		PtyCallback: func(_ Context, sess Session, _ Pty) (bool, error) {
			callbackUser <- sess.User()
			return true, expected
		},
		ErrorHandler: func(_ context.Context, scope ErrorScope, operation ErrorOperation, err error, respond ErrorResponder, _ ErrorHandler) (bool, error) {
			reported <- callbackErrorEvent{scope, operation, err}
			if responseErr := respond([]byte("PTY policy unavailable\n"), false); responseErr != nil {
				return false, responseErr
			}
			return true, nil
		},
	}, nil)
	defer cleanup()

	var stderr bytes.Buffer
	session.Stderr = &stderr
	ok, err := session.SendRequest("pty-req", true, marshalPtyRequest("xterm", Window{Width: 80, Height: 24}, []byte{0}))
	require.NoError(t, err)
	require.False(t, ok)
	require.Equal(t, "testuser", <-callbackUser)
	event := <-reported
	require.Equal(t, ErrorScopeSession, event.scope)
	require.Equal(t, ErrorOperationHandle, event.operation)
	require.ErrorIs(t, event.err, expected)
	require.NoError(t, session.Run("success"))
	require.Equal(t, "PTY policy unavailable\n", stderr.String())
}

func TestSessionRequestCallbackErrorUsesSessionErrorHandling(t *testing.T) {
	expected := errors.New("session policy unavailable")
	reported := make(chan callbackErrorEvent, 1)
	session, _, cleanup := newTestSession(t, &Server{
		Handler: func(Session) error { return nil },
		SessionRequestCallback: func(Session, string) (bool, error) {
			return true, expected
		},
		ErrorHandler: func(_ context.Context, scope ErrorScope, operation ErrorOperation, err error, _ ErrorResponder, _ ErrorHandler) (bool, error) {
			reported <- callbackErrorEvent{scope, operation, err}
			return false, nil
		},
	}, nil)
	defer cleanup()

	require.Error(t, session.Shell())
	event := <-reported
	require.Equal(t, ErrorScopeSession, event.scope)
	require.Equal(t, ErrorOperationHandle, event.operation)
	require.ErrorIs(t, event.err, expected)
}

func TestAgentForwardingCallbackErrorUsesSessionErrorHandling(t *testing.T) {
	expected := errors.New("agent policy unavailable")
	reported := make(chan callbackErrorEvent, 1)
	session, _, cleanup := newTestSession(t, &Server{
		Handler: func(Session) error { return nil },
		AgentForwardingCallback: func(Context, Session) (bool, error) {
			return true, expected
		},
		ErrorHandler: func(_ context.Context, scope ErrorScope, operation ErrorOperation, err error, _ ErrorResponder, _ ErrorHandler) (bool, error) {
			reported <- callbackErrorEvent{scope, operation, err}
			return true, nil
		},
	}, nil)
	defer cleanup()

	ok, err := session.SendRequest(agentRequestType, true, nil)
	require.NoError(t, err)
	require.False(t, ok)
	event := <-reported
	require.Equal(t, ErrorScopeSession, event.scope)
	require.Equal(t, ErrorOperationHandle, event.operation)
	require.ErrorIs(t, event.err, expected)
	require.NoError(t, session.Run("success"))
}

func TestForwardingCallbackErrorUsesForwardingErrorHandling(t *testing.T) {
	expected := errors.New("forwarding policy unavailable")
	reported := make(chan callbackErrorEvent, 1)
	callbackUsers := make(chan [2]string, 1)
	_, client, cleanup := newTestSession(t, &Server{
		Handler: func(Session) error { return nil },
		LocalPortForwardingCallback: func(ctx Context, conn gossh.ConnMetadata, _ string, _ uint32) (bool, error) {
			callbackUsers <- [2]string{ctx.User(), conn.User()}
			return true, expected
		},
		ErrorHandler: func(_ context.Context, scope ErrorScope, operation ErrorOperation, err error, _ ErrorResponder, _ ErrorHandler) (bool, error) {
			reported <- callbackErrorEvent{scope, operation, err}
			return true, nil
		},
	}, nil)
	defer cleanup()

	_, err := client.Dial("tcp", "127.0.0.1:1")
	require.Error(t, err)
	users := <-callbackUsers
	require.Equal(t, users[0], users[1])
	event := <-reported
	require.Equal(t, ErrorScopeForwarding, event.scope)
	require.Equal(t, ErrorOperationHandle, event.operation)
	require.ErrorIs(t, event.err, expected)
}

func TestConnectionFailedCallbackErrorIsJoinedBeforeDispatch(t *testing.T) {
	connectionErr := errors.New("initialize connection")
	callbackErr := errors.New("report connection failure")
	reported := make(chan error, 1)
	type failureObservation struct {
		ctx Context
		err error
	}
	callback := make(chan failureObservation, 1)
	srv := &Server{
		ConnCallback: func(Context, net.Conn) (net.Conn, error) { return nil, connectionErr },
		ConnectionFailedCallback: func(ctx Context, _ net.Conn, err error) error {
			callback <- failureObservation{ctx, err}
			return callbackErr
		},
		ErrorHandler: func(_ context.Context, _ ErrorScope, _ ErrorOperation, err error, _ ErrorResponder, _ ErrorHandler) (bool, error) {
			reported <- err
			return false, nil
		},
	}
	listener := newLocalListener()
	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- srv.Serve(ctx, listener) }()
	conn, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	closeQuietly(conn)

	combined := <-reported
	require.ErrorIs(t, combined, connectionErr)
	require.ErrorIs(t, combined, callbackErr)
	failure := <-callback
	require.NotNil(t, failure.ctx)
	require.ErrorIs(t, failure.err, connectionErr)
	cancel()
	require.ErrorIs(t, <-serveDone, context.Canceled)
}

func TestDisconnectCallbackErrorUsesConnectionErrorHandling(t *testing.T) {
	expected := errors.New("disconnect reporting failed")
	reported := make(chan callbackErrorEvent, 1)
	type disconnectObservation struct {
		ctxErr  error
		hasConn bool
	}
	disconnected := make(chan disconnectObservation, 1)
	session, client, cleanup := newTestSession(t, &Server{
		Handler: func(Session) error { return nil },
		DisconnectCallback: func(ctx Context, conn net.Conn) error {
			disconnected <- disconnectObservation{ctx.Err(), conn != nil}
			return expected
		},
		ErrorHandler: func(_ context.Context, scope ErrorScope, operation ErrorOperation, err error, _ ErrorResponder, _ ErrorHandler) (bool, error) {
			reported <- callbackErrorEvent{scope, operation, err}
			return false, nil
		},
	}, nil)
	closeQuietly(session)
	closeQuietly(client)
	cleanup()
	observation := <-disconnected
	require.Error(t, observation.ctxErr)
	require.True(t, observation.hasConn)
	event := <-reported
	require.Equal(t, ErrorScopeConnection, event.scope)
	require.Equal(t, ErrorOperationHandle, event.operation)
	require.ErrorIs(t, event.err, expected)
}

func TestHandleConnReturnsDisconnectCallbackError(t *testing.T) {
	expected := errors.New("disconnect reporting failed")
	srv := &Server{DisconnectCallback: func(Context, net.Conn) error { return expected }}
	listener := newLocalListener()
	defer closeQuietly(listener)
	serverDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			err = srv.HandleConn(context.Background(), conn)
		}
		serverDone <- err
	}()
	client, err := gossh.Dial("tcp", listener.Addr().String(), &gossh.ClientConfig{
		User:            "testuser",
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
	})
	require.NoError(t, err)
	require.NoError(t, client.Close())
	require.ErrorIs(t, <-serverDone, expected)
}

func TestGracefulShutdownHandlerErrorIsReturned(t *testing.T) {
	expected := errors.New("resolve shutdown period")
	shutdownCause := errors.New("shutdown requested")
	connectionContext := make(chan Context, 1)
	srv := &Server{
		GracefulShutdownHandler: func(context.Context) (time.Duration, error) {
			return time.Second, expected
		},
		ConnCallback: func(ctx Context, conn net.Conn) (net.Conn, error) {
			connectionContext <- ctx
			return conn, nil
		},
	}
	listener := newLocalListener()
	ctx, cancel := context.WithCancelCause(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- srv.Serve(ctx, listener) }()
	conn, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	defer closeQuietly(conn)
	connectionCtx := <-connectionContext
	cancel(shutdownCause)

	err = <-serveDone
	require.ErrorIs(t, err, shutdownCause)
	require.ErrorIs(t, err, expected)
	require.ErrorIs(t, context.Cause(connectionCtx), shutdownCause)
	require.ErrorIs(t, context.Cause(connectionCtx), expected)
}

func TestForceClosesOnlyCurrentConnectionOwner(t *testing.T) {
	base, peer := net.Pipe()
	defer closeQuietly(peer)
	original := &closeCountingConn{Conn: base}
	wrapper := &closeCountingConn{Conn: original}
	scope := newServeContext(new(Server), context.Background(), nil)
	active := scope.trackConnection(original)
	require.NotNil(t, active)
	require.True(t, scope.updateConnection(active, wrapper))

	require.NoError(t, scope.force(context.Canceled))
	require.Equal(t, int32(1), wrapper.closes.Load())
	require.Equal(t, int32(1), original.closes.Load())
}
