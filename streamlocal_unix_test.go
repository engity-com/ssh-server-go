//go:build unix

package ssh

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestDirectStreamLocalForwardingWithUnixSocket(t *testing.T) {
	path := streamLocalSocketPath(t)
	listener, err := net.Listen("unix", path)
	require.NoError(t, err)
	defer closeQuietly(listener)
	target := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			target <- conn
		}
	}()

	_, client, cleanup := newTestSession(t, &Server{
		Handler: func(Session) {},
		LocalUnixForwardingCallback: func(ctx Context, socketPath string) (net.Conn, error) {
			if socketPath != path {
				return nil, ErrServerPermissionDenied
			}
			var dialer net.Dialer
			return dialer.DialContext(ctx, "unix", socketPath)
		},
	}, nil)
	defer cleanup()

	forwarded, err := client.Dial("unix", path)
	require.NoError(t, err)
	defer closeQuietly(forwarded)
	var targetConn net.Conn
	select {
	case targetConn = <-target:
		defer closeQuietly(targetConn)
	case <-time.After(time.Second):
		t.Fatal("Unix socket did not accept forwarded connection")
	}
	assertStreamLocalExchange(t, forwarded, targetConn)
}

func TestReverseStreamLocalForwardingWithUnixSocket(t *testing.T) {
	path := streamLocalSocketPath(t)
	handler := &ForwardedUnixHandler{}
	_, client, cleanup := newTestSession(t, &Server{
		Handler: func(Session) {},
		ReverseUnixForwardingCallback: func(_ Context, socketPath string) (net.Listener, error) {
			if socketPath != path {
				return nil, ErrServerPermissionDenied
			}
			return net.Listen("unix", socketPath)
		},
		RequestHandlers: streamLocalRequestHandlers(handler),
	}, nil)
	defer cleanup()

	forwarded, err := client.ListenUnix(path)
	require.NoError(t, err)
	defer closeQuietly(forwarded)
	dialer := net.Dialer{}
	serverConn, err := dialer.DialContext(context.Background(), "unix", path)
	require.NoError(t, err)
	defer closeQuietly(serverConn)
	clientConn := acceptStreamLocal(t, forwarded)
	defer closeQuietly(clientConn)
	assertStreamLocalExchange(t, clientConn, serverConn)
}

func streamLocalSocketPath(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if runtime.GOOS == "darwin" {
		var err error
		dir, err = os.MkdirTemp("/tmp", "ssh-streamlocal-")
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, os.RemoveAll(dir)) })
	}
	return filepath.Join(dir, "socket")
}
