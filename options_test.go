package ssh

import (
	"context"
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
		Handler: func(s Session) {
			// noop
		},
	}, &gossh.ClientConfig{
		User: testUser,
		Auth: []gossh.AuthMethod{
			gossh.Password(testPass),
		},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
	}, PasswordAuth(func(ctx Context, password string) bool {
		if ctx.User() != testUser {
			t.Fatalf("user = %#v; want %#v", ctx.User(), testUser)
		}
		if password != testPass {
			t.Fatalf("user = %#v; want %#v", password, testPass)
		}
		return true
	}))
	defer cleanup()
	if err := session.Run(""); err != nil {
		t.Fatal(err)
	}
}

func TestPasswordAuthBadPass(t *testing.T) {
	t.Parallel()
	l := newLocalListener()
	srv := &Server{Handler: func(s Session) {}}
	if err := srv.SetOption(PasswordAuth(func(ctx Context, password string) bool {
		return false
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
		Handler: func(s Session) {
			// nothing
		},
	}, &gossh.ClientConfig{
		User: "testuser",
		Auth: []gossh.AuthMethod{
			gossh.Password("testpass"),
		},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
	}, PasswordAuth(func(ctx Context, password string) bool {
		return true
	}), WrapConn(func(ctx Context, conn net.Conn) net.Conn {
		wrapped = &wrappedConn{conn, 0}
		return wrapped
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
	require.Equal(t, timeout, handler(context.Background()))
}

func TestWithGracefulShutdownHandler(t *testing.T) {
	handler := NewGracefulShutdownTimeoutHandler(time.Second)
	srv := &Server{}
	require.NoError(t, srv.SetOption(WithGracefulShutdownHandler(handler)))
	require.Equal(t, time.Second, srv.GracefulShutdownHandler(context.Background()))
}

func TestWithGracefulShutdownTimeout(t *testing.T) {
	srv := &Server{}
	require.NoError(t, srv.SetOption(WithGracefulShutdownTimeout(2*time.Second)))
	require.Equal(t, 2*time.Second, srv.GracefulShutdownHandler(context.Background()))
}
