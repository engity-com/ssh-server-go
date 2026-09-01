package ssh

import (
	"bytes"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"
)

var sampleServerResponse = []byte("Hello world")

func sampleSocketServer() net.Listener {
	l := newLocalListener()

	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		if _, err := conn.Write(sampleServerResponse); err != nil {
			return
		}
		closeQuietly(conn)
	}()

	return l
}

func newTestSessionWithForwarding(t *testing.T, forwardingEnabled bool) (net.Listener, *gossh.Client, func()) {
	l := sampleSocketServer()

	_, client, cleanup := newTestSession(t, &Server{
		Handler: func(s Session) {},
		LocalPortForwardingCallback: func(ctx Context, destinationHost string, destinationPort uint32) bool {
			addr := net.JoinHostPort(destinationHost, strconv.FormatInt(int64(destinationPort), 10))
			if addr != l.Addr().String() {
				panic("unexpected destinationHost: " + addr)
			}
			return forwardingEnabled
		},
	}, nil)

	return l, client, func() {
		cleanup()
		closeQuietly(l)
	}
}

func TestLocalPortForwardingWorks(t *testing.T) {
	t.Parallel()

	l, client, cleanup := newTestSessionWithForwarding(t, true)
	defer cleanup()

	conn, err := client.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatalf("Error connecting to %v: %v", l.Addr().String(), err)
	}
	result, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(result, sampleServerResponse) {
		t.Fatalf("result = %#v; want %#v", result, sampleServerResponse)
	}
}

func TestLocalPortForwardingRespectsCallback(t *testing.T) {
	t.Parallel()

	l, client, cleanup := newTestSessionWithForwarding(t, false)
	defer cleanup()

	_, err := client.Dial("tcp", l.Addr().String())
	if err == nil {
		t.Fatalf("Expected error connecting to %v but it succeeded", l.Addr().String())
	}
	if !strings.Contains(err.Error(), "port forwarding is disabled") {
		t.Fatalf("Expected permission error but got %#v", err)
	}
}

func TestLocalPortForwardingHidesDialError(t *testing.T) {
	target := newLocalListener()
	addr := target.Addr().String()
	closeQuietly(target)
	_, client, cleanup := newTestSession(t, &Server{
		Handler:                     func(Session) {},
		LocalPortForwardingCallback: func(Context, string, uint32) bool { return true },
	}, nil)
	defer cleanup()

	_, err := client.Dial("tcp", addr)
	require.Error(t, err)
	require.Contains(t, err.Error(), "connection failed")
	require.NotContains(t, strings.ToLower(err.Error()), "refused")
}

func TestRemotePortZeroForwardIsRemovedOnCancel(t *testing.T) {
	handler := &ForwardedTCPHandler{}
	session, client, cleanup := newTestSession(t, &Server{
		Handler:                       func(Session) {},
		ReversePortForwardingCallback: func(Context, string, uint32) bool { return true },
		RequestHandlers: map[string]RequestHandler{
			"tcpip-forward":        handler.HandleSSHRequest,
			"cancel-tcpip-forward": handler.HandleSSHRequest,
		},
	}, nil)
	defer cleanup()
	defer closeQuietly(session)

	listener, err := client.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	handler.Lock()
	require.Len(t, handler.forwards, 1)
	handler.Unlock()
	require.NoError(t, listener.Close())
	require.Eventually(t, func() bool {
		handler.Lock()
		defer handler.Unlock()
		return len(handler.forwards) == 0
	}, time.Second, time.Millisecond)
}

func TestRemoteForwardListenerLimit(t *testing.T) {
	maxForwards := 1
	handler := &ForwardedTCPHandler{}
	session, client, cleanup := newTestSession(t, &Server{
		Handler:                         func(Session) {},
		MaxReverseForwardsPerConnection: &maxForwards,
		ReversePortForwardingCallback:   func(Context, string, uint32) bool { return true },
		RequestHandlers: map[string]RequestHandler{
			"tcpip-forward":        handler.HandleSSHRequest,
			"cancel-tcpip-forward": handler.HandleSSHRequest,
		},
	}, nil)
	defer cleanup()
	defer closeQuietly(session)

	first, err := client.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	_, err = client.Listen("tcp", "127.0.0.1:0")
	require.Error(t, err)
	require.NoError(t, first.Close())

	var second net.Listener
	require.Eventually(t, func() bool {
		second, err = client.Listen("tcp", "127.0.0.1:0")
		return err == nil
	}, time.Second, time.Millisecond)
	closeQuietly(second)
}
