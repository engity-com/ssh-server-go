package ssh

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"
)

func newTestSessionWithOptions(t *testing.T, srv *Server, cfg *gossh.ClientConfig, options ...Option) (*gossh.Session, *gossh.Client, func()) {
	for _, option := range options {
		if err := srv.SetOption(option); err != nil {
			t.Fatal(err)
		}
	}
	return newTestSession(t, srv, cfg)
}

func TestPasswordAuth(t *testing.T) {
	t.Parallel()
	testUser := "testuser"
	testPass := "testpass"
	session, _, cleanup := newTestSessionWithOptions(t, &Server{
		Handler: func(s Session) error {
			return nil
			// noop
		},
	}, &gossh.ClientConfig{
		User: testUser,
		Auth: []gossh.AuthMethod{
			gossh.Password(testPass),
		},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
	}, PasswordAuth(func(ctx Context, _ gossh.ConnMetadata, password string) (bool, error) {
		if ctx.User() != testUser {
			t.Fatalf("user = %#v; want %#v", ctx.User(), testUser)
		}
		if password != testPass {
			t.Fatalf("user = %#v; want %#v", password, testPass)
		}
		return true, nil
	}))
	defer cleanup()
	if err := session.Run(""); err != nil {
		t.Fatal(err)
	}
}

func TestPasswordAuthBadPass(t *testing.T) {
	t.Parallel()
	l := newLocalListener()
	srv := &Server{Handler: func(s Session) error { return nil }}
	if err := srv.SetOption(PasswordAuth(func(ctx Context, _ gossh.ConnMetadata, password string) (bool, error) {
		return false, nil
	})); err != nil {
		t.Fatal(err)
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- srv.serveOnce(l) }()
	_, err := gossh.Dial("tcp", l.Addr().String(), &gossh.ClientConfig{
		User: "testuser",
		Auth: []gossh.AuthMethod{
			gossh.Password("testpass"),
		},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		if !strings.Contains(err.Error(), "unable to authenticate") {
			t.Fatal(err)
		}
	}
	if err := <-serveDone; err == nil {
		t.Fatal("HandleConn() error = nil; want authentication failure")
	}
}

type wrappedConn struct {
	net.Conn
	written int32
}

func (c *wrappedConn) Write(p []byte) (n int, err error) {
	n, err = c.Conn.Write(p)
	atomic.AddInt32(&(c.written), int32(n))
	return
}

func TestConnWrapping(t *testing.T) {
	t.Parallel()
	var wrapped *wrappedConn
	session, _, cleanup := newTestSessionWithOptions(t, &Server{
		Handler: func(s Session) error {
			return nil
			// nothing
		},
	}, &gossh.ClientConfig{
		User: "testuser",
		Auth: []gossh.AuthMethod{
			gossh.Password("testpass"),
		},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
	}, PasswordAuth(func(ctx Context, _ gossh.ConnMetadata, password string) (bool, error) {
		return true, nil
	}), WrapConn(func(ctx Context, conn net.Conn) (net.Conn, error) {
		wrapped = &wrappedConn{conn, 0}
		return wrapped, nil
	}))
	defer cleanup()
	if err := session.Shell(); err != nil {
		t.Fatal(err)
	}
	if atomic.LoadInt32(&(wrapped.written)) == 0 {
		t.Fatal("wrapped connection not written to")
	}
}

func TestNewGracefulShutdownTimeoutHandler(t *testing.T) {
	timeout := 3 * time.Second
	handler := NewGracefulShutdownTimeoutHandler(timeout)
	actual, err := handler(context.Background())
	require.NoError(t, err)
	require.Equal(t, timeout, actual)
}

func TestWithGracefulShutdownHandler(t *testing.T) {
	handler := NewGracefulShutdownTimeoutHandler(time.Second)
	srv := &Server{}
	require.NoError(t, srv.SetOption(WithGracefulShutdownHandler(handler)))
	actual, err := srv.GracefulShutdownHandler(context.Background())
	require.NoError(t, err)
	require.Equal(t, time.Second, actual)
}

func TestWithErrorHandler(t *testing.T) {
	called := false
	handler := func(context.Context, ErrorScope, ErrorOperation, error, ErrorResponder, ErrorHandler) (bool, error) {
		called = true
		return true, nil
	}
	srv := &Server{}
	require.NoError(t, srv.SetOption(WithErrorHandler(handler)))
	require.NotNil(t, srv.ErrorHandler)
	_, err := srv.ErrorHandler(context.Background(), ErrorScopeServer, ErrorOperationAccept, errors.New("test"), nil, nil)
	require.NoError(t, err)
	require.True(t, called)
}

func TestWithGracefulShutdownTimeout(t *testing.T) {
	srv := &Server{}
	require.NoError(t, srv.SetOption(WithGracefulShutdownTimeout(2*time.Second)))
	actual, err := srv.GracefulShutdownHandler(context.Background())
	require.NoError(t, err)
	require.Equal(t, 2*time.Second, actual)
}
