package ssh

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"
)

type streamLocalTestListener struct {
	connections chan net.Conn
	accepted    chan struct{}
	closed      chan struct{}
	closeOnce   sync.Once
}

func newStreamLocalTestListener() *streamLocalTestListener {
	return &streamLocalTestListener{
		connections: make(chan net.Conn, 1),
		accepted:    make(chan struct{}, 1),
		closed:      make(chan struct{}),
	}
}

func (l *streamLocalTestListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.connections:
		select {
		case l.accepted <- struct{}{}:
		default:
		}
		return conn, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *streamLocalTestListener) Close() error {
	l.closeOnce.Do(func() { close(l.closed) })
	return nil
}

func (l *streamLocalTestListener) Addr() net.Addr {
	return streamLocalTestAddr("streamlocal-test")
}

func (l *streamLocalTestListener) connect(t *testing.T) net.Conn {
	t.Helper()
	accepted, peer := net.Pipe()
	select {
	case l.connections <- accepted:
		return peer
	case <-l.closed:
		closeQuietly(accepted)
		closeQuietly(peer)
		t.Fatal("listener closed before connection was accepted")
		return nil
	case <-time.After(time.Second):
		closeQuietly(accepted)
		closeQuietly(peer)
		t.Fatal("listener did not accept connection")
		return nil
	}
}

type streamLocalTestAddr string

func (a streamLocalTestAddr) Network() string { return "unix" }
func (a streamLocalTestAddr) String() string  { return string(a) }

func streamLocalRequestHandlers(handler *ForwardedUnixHandler) map[string]RequestHandler {
	return map[string]RequestHandler{
		"streamlocal-forward@openssh.com":        handler.HandleSSHRequest,
		"cancel-streamlocal-forward@openssh.com": handler.HandleSSHRequest,
	}
}

func TestDirectStreamLocalForwarding(t *testing.T) {
	const socketPath = "/virtual/direct.sock"
	forward, peer := net.Pipe()
	defer closeQuietly(peer)
	callbackPath := make(chan string, 1)
	_, client, cleanup := newTestSession(t, &Server{
		Handler: func(Session) {},
		LocalUnixForwardingCallback: func(_ Context, path string) (net.Conn, error) {
			callbackPath <- path
			return forward, nil
		},
	}, nil)
	defer cleanup()

	conn, err := client.Dial("unix", socketPath)
	require.NoError(t, err)
	defer closeQuietly(conn)
	require.Equal(t, socketPath, <-callbackPath)

	request := []byte("request")
	response := []byte("response")
	writeResult := make(chan error, 1)
	go func() {
		_, err := conn.Write(request)
		writeResult <- err
	}()
	gotRequest := make([]byte, len(request))
	_, err = io.ReadFull(peer, gotRequest)
	require.NoError(t, err)
	require.Equal(t, request, gotRequest)
	require.NoError(t, <-writeResult)

	go func() {
		_, err := peer.Write(response)
		writeResult <- err
	}()
	gotResponse := make([]byte, len(response))
	_, err = io.ReadFull(conn, gotResponse)
	require.NoError(t, err)
	require.Equal(t, response, gotResponse)
	require.NoError(t, <-writeResult)
}

func TestDirectStreamLocalForwardingRejectsAndHidesErrors(t *testing.T) {
	const secret = "private backend detail"
	tests := map[string]struct {
		callback LocalUnixForwardingCallback
		message  string
	}{
		"disabled": {
			message: "unix forwarding is disabled",
		},
		"denied": {
			callback: func(Context, string) (net.Conn, error) { return nil, ErrServerPermissionDenied },
			message:  "unix forwarding is denied",
		},
		"failed": {
			callback: func(Context, string) (net.Conn, error) { return nil, errors.New(secret) },
			message:  "connection failed",
		},
		"nil connection": {
			callback: func(Context, string) (net.Conn, error) { return nil, nil },
			message:  "connection failed",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			_, client, cleanup := newTestSession(t, &Server{
				Handler:                     func(Session) {},
				LocalUnixForwardingCallback: tt.callback,
			}, nil)
			defer cleanup()

			_, err := client.Dial("unix", "/virtual/rejected.sock")
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.message)
			require.NotContains(t, err.Error(), secret)
		})
	}
}

func TestDirectStreamLocalRejectsMalformedPayloadBeforeCallback(t *testing.T) {
	var callbackCalls atomic.Int64
	_, client, cleanup := newTestSession(t, &Server{
		Handler: func(Session) {},
		LocalUnixForwardingCallback: func(Context, string) (net.Conn, error) {
			callbackCalls.Add(1)
			return nil, nil
		},
	}, nil)
	defer cleanup()

	_, _, err := client.OpenChannel("direct-streamlocal@openssh.com", []byte{0, 0, 0, 10, 'x'})
	require.Error(t, err)
	require.Zero(t, callbackCalls.Load())
}

func TestReverseStreamLocalForwardingAndCancel(t *testing.T) {
	const socketPath = "/virtual/reverse.sock"
	serverListener := newStreamLocalTestListener()
	callbackPath := make(chan string, 1)
	handler := &ForwardedUnixHandler{}
	_, client, cleanup := newTestSession(t, &Server{
		Handler: func(Session) {},
		ReverseUnixForwardingCallback: func(_ Context, path string) (net.Listener, error) {
			callbackPath <- path
			return serverListener, nil
		},
		RequestHandlers: streamLocalRequestHandlers(handler),
	}, nil)
	defer cleanup()

	clientListener, err := client.ListenUnix(socketPath)
	require.NoError(t, err)
	require.Equal(t, socketPath, <-callbackPath)
	serverConn := serverListener.connect(t)
	defer closeQuietly(serverConn)
	clientConn := acceptStreamLocal(t, clientListener)
	defer closeQuietly(clientConn)

	require.NoError(t, clientListener.Close())
	require.Eventually(t, func() bool {
		select {
		case <-serverListener.closed:
			return true
		default:
			return false
		}
	}, time.Second, time.Millisecond)

	assertStreamLocalExchange(t, clientConn, serverConn)
	handler.Lock()
	require.Empty(t, handler.forwards)
	handler.Unlock()
}

func TestReverseStreamLocalWaitsForSuccessfulReply(t *testing.T) {
	serverListener := newStreamLocalTestListener()
	serverConn := serverListener.connect(t)
	defer closeQuietly(serverConn)
	handler := &ForwardedUnixHandler{}
	_, client, cleanup := newTestSession(t, &Server{
		Handler: func(Session) {},
		ReverseUnixForwardingCallback: func(Context, string) (net.Listener, error) {
			return serverListener, nil
		},
		RequestHandlers: streamLocalRequestHandlers(handler),
	}, nil)
	defer cleanup()

	clientListener, err := client.ListenUnix("/virtual/immediate.sock")
	require.NoError(t, err)
	defer closeQuietly(clientListener)
	clientConn := acceptStreamLocal(t, clientListener)
	defer closeQuietly(clientConn)
	assertStreamLocalExchange(t, clientConn, serverConn)
}

func TestReverseStreamLocalForwardingRejectsCallbackErrors(t *testing.T) {
	tests := map[string]ReverseUnixForwardingCallback{
		"denied": func(Context, string) (net.Listener, error) {
			return nil, ErrServerPermissionDenied
		},
		"failed": func(Context, string) (net.Listener, error) {
			return nil, errors.New("private listener detail")
		},
		"nil listener": func(Context, string) (net.Listener, error) {
			return nil, nil
		},
	}
	for name, callback := range tests {
		t.Run(name, func(t *testing.T) {
			handler := &ForwardedUnixHandler{}
			_, client, cleanup := newTestSession(t, &Server{
				Handler:                       func(Session) {},
				ReverseUnixForwardingCallback: callback,
				RequestHandlers:               streamLocalRequestHandlers(handler),
			}, nil)
			defer cleanup()

			_, err := client.ListenUnix("/virtual/rejected.sock")
			require.Error(t, err)
			handler.Lock()
			require.Empty(t, handler.forwards)
			handler.Unlock()
		})
	}
}

func TestReverseStreamLocalForwardingIsConnectionScoped(t *testing.T) {
	const socketPath = "/virtual/shared.sock"
	handler := &ForwardedUnixHandler{}
	listeners := make(chan *streamLocalTestListener, 2)
	newServer := func() (*gossh.Client, func()) {
		_, client, cleanup := newTestSession(t, &Server{
			Handler: func(Session) {},
			ReverseUnixForwardingCallback: func(Context, string) (net.Listener, error) {
				listener := newStreamLocalTestListener()
				listeners <- listener
				return listener, nil
			},
			RequestHandlers: streamLocalRequestHandlers(handler),
		}, nil)
		return client, cleanup
	}
	client1, cleanup1 := newServer()
	defer cleanup1()
	client2, cleanup2 := newServer()
	defer cleanup2()

	forward1, err := client1.ListenUnix(socketPath)
	require.NoError(t, err)
	serverListener1 := <-listeners
	forward2, err := client2.ListenUnix(socketPath)
	require.NoError(t, err)
	serverListener2 := <-listeners

	require.NoError(t, forward1.Close())
	require.Eventually(t, func() bool {
		select {
		case <-serverListener1.closed:
			return true
		default:
			return false
		}
	}, time.Second, time.Millisecond)
	select {
	case <-serverListener2.closed:
		t.Fatal("canceling one connection closed another connection's listener")
	default:
	}
	require.NoError(t, forward2.Close())
}

func TestReverseStreamLocalRejectsDuplicatePathOnSameConnection(t *testing.T) {
	var callbackCalls atomic.Int64
	handler := &ForwardedUnixHandler{}
	_, client, cleanup := newTestSession(t, &Server{
		Handler: func(Session) {},
		ReverseUnixForwardingCallback: func(Context, string) (net.Listener, error) {
			callbackCalls.Add(1)
			return newStreamLocalTestListener(), nil
		},
		RequestHandlers: streamLocalRequestHandlers(handler),
	}, nil)
	defer cleanup()

	first, err := client.ListenUnix("/virtual/duplicate.sock")
	require.NoError(t, err)
	defer closeQuietly(first)
	_, err = client.ListenUnix("/virtual/duplicate.sock")
	require.Error(t, err)
	require.Equal(t, int64(1), callbackCalls.Load())
}

func TestReverseStreamLocalCancelStopsPendingOpenBeforePathReuse(t *testing.T) {
	const socketPath = "/virtual/reused.sock"
	handler := &ForwardedUnixHandler{}
	listeners := make(chan *streamLocalTestListener, 2)
	cancelReceived := make(chan struct{})
	releaseCancel := make(chan struct{})
	var cancelOnce sync.Once
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseCancel) }) }
	defer release()
	requestHandlers := streamLocalRequestHandlers(handler)
	requestHandlers["cancel-streamlocal-forward@openssh.com"] = func(ctx Context, srv *Server, req *gossh.Request) (bool, []byte) {
		cancelOnce.Do(func() { close(cancelReceived) })
		<-releaseCancel
		return handler.HandleSSHRequest(ctx, srv, req)
	}
	_, client, cleanup := newTestSession(t, &Server{
		Handler: func(Session) {},
		ReverseUnixForwardingCallback: func(Context, string) (net.Listener, error) {
			listener := newStreamLocalTestListener()
			listeners <- listener
			return listener, nil
		},
		RequestHandlers: requestHandlers,
	}, nil)
	defer cleanup()

	first, err := client.ListenUnix(socketPath)
	require.NoError(t, err)
	firstServerListener := <-listeners
	closeResult := make(chan error, 1)
	go func() { closeResult <- first.Close() }()
	select {
	case <-cancelReceived:
	case <-time.After(time.Second):
		t.Fatal("cancel request was not received")
	}
	oldPeer := firstServerListener.connect(t)
	defer closeQuietly(oldPeer)
	select {
	case <-firstServerListener.accepted:
	case <-time.After(time.Second):
		t.Fatal("old listener did not accept pending connection")
	}
	release()
	require.NoError(t, <-closeResult)
	readResult := make(chan error, 1)
	go func() {
		_, err := oldPeer.Read(make([]byte, 1))
		readResult <- err
	}()
	select {
	case err = <-readResult:
		require.Error(t, err)
	case <-time.After(time.Second):
		t.Fatal("old pending connection was not closed")
	}

	var second net.Listener
	require.Eventually(t, func() bool {
		second, err = client.ListenUnix(socketPath)
		return err == nil
	}, time.Second, time.Millisecond)
	defer closeQuietly(second)
	secondServerListener := <-listeners
	newPeer := secondServerListener.connect(t)
	defer closeQuietly(newPeer)
	newClientConn := acceptStreamLocal(t, second)
	defer closeQuietly(newClientConn)
	assertStreamLocalExchange(t, newClientConn, newPeer)
}

func TestReverseStreamLocalAndTCPShareForwardLimit(t *testing.T) {
	maxForwards := 1
	tcpHandler := &ForwardedTCPHandler{}
	unixHandler := &ForwardedUnixHandler{}
	var unixCallbackCalls atomic.Int64
	requestHandlers := streamLocalRequestHandlers(unixHandler)
	requestHandlers["tcpip-forward"] = tcpHandler.HandleSSHRequest
	requestHandlers["cancel-tcpip-forward"] = tcpHandler.HandleSSHRequest
	_, client, cleanup := newTestSession(t, &Server{
		Handler:                         func(Session) {},
		MaxReverseForwardsPerConnection: &maxForwards,
		ReversePortForwardingCallback:   func(Context, string, uint32) bool { return true },
		ReverseUnixForwardingCallback: func(Context, string) (net.Listener, error) {
			unixCallbackCalls.Add(1)
			return newStreamLocalTestListener(), nil
		},
		RequestHandlers: requestHandlers,
	}, nil)
	defer cleanup()

	tcpListener, err := client.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	_, err = client.ListenUnix("/virtual/limited.sock")
	require.Error(t, err)
	require.Zero(t, unixCallbackCalls.Load())
	require.NoError(t, tcpListener.Close())

	var unixListener net.Listener
	require.Eventually(t, func() bool {
		unixListener, err = client.ListenUnix("/virtual/limited.sock")
		return err == nil
	}, time.Second, time.Millisecond)
	require.Equal(t, int64(1), unixCallbackCalls.Load())
	closeQuietly(unixListener)
}

func TestReverseStreamLocalRespectsChannelLimit(t *testing.T) {
	maxChannels := 1
	serverListener := newStreamLocalTestListener()
	handler := &ForwardedUnixHandler{}
	_, client, cleanup := newTestSession(t, &Server{
		Handler:                  func(Session) {},
		MaxChannelsPerConnection: &maxChannels,
		ReverseUnixForwardingCallback: func(Context, string) (net.Listener, error) {
			return serverListener, nil
		},
		RequestHandlers: streamLocalRequestHandlers(handler),
	}, nil)
	defer cleanup()

	listener, err := client.ListenUnix("/virtual/channel-limited.sock")
	require.NoError(t, err)
	defer closeQuietly(listener)
	peer := serverListener.connect(t)
	defer closeQuietly(peer)
	readResult := make(chan error, 1)
	go func() {
		_, err := peer.Read(make([]byte, 1))
		readResult <- err
	}()
	select {
	case err = <-readResult:
		require.Error(t, err)
	case <-time.After(time.Second):
		t.Fatal("channel-limited connection was not closed")
	}
}

func TestReverseStreamLocalListenerClosesBeforeDisconnectCallback(t *testing.T) {
	serverListener := newStreamLocalTestListener()
	disconnected := make(chan bool, 1)
	handler := &ForwardedUnixHandler{}
	session, client, cleanup := newTestSession(t, &Server{
		Handler: func(Session) {},
		ReverseUnixForwardingCallback: func(Context, string) (net.Listener, error) {
			return serverListener, nil
		},
		DisconnectCallback: func(Context, net.Conn) {
			select {
			case <-serverListener.closed:
				disconnected <- true
			default:
				disconnected <- false
			}
		},
		RequestHandlers: streamLocalRequestHandlers(handler),
	}, nil)
	defer cleanup()

	listener, err := client.ListenUnix("/virtual/disconnect.sock")
	require.NoError(t, err)
	defer closeQuietly(listener)
	closeQuietly(session)
	closeQuietly(client)
	select {
	case closed := <-disconnected:
		require.True(t, closed)
	case <-time.After(time.Second):
		t.Fatal("disconnect callback was not called")
	}
}

func TestUnixForwardingCallbacksAreSnapshotted(t *testing.T) {
	localCalls := make(chan string, 1)
	reverseCalls := make(chan string, 1)
	srv := &Server{
		LocalUnixForwardingCallback: func(_ Context, path string) (net.Conn, error) {
			localCalls <- path
			left, right := net.Pipe()
			closeQuietly(right)
			return left, nil
		},
		ReverseUnixForwardingCallback: func(_ Context, path string) (net.Listener, error) {
			reverseCalls <- path
			return newStreamLocalTestListener(), nil
		},
	}
	settings := srv.connectionSettings()
	srv.LocalUnixForwardingCallback = nil
	srv.ReverseUnixForwardingCallback = nil

	conn, err := settings.localUnixForwardingCallback(nil, "local")
	require.NoError(t, err)
	closeQuietly(conn)
	listener, err := settings.reverseUnixForwardingCallback(nil, "reverse")
	require.NoError(t, err)
	closeQuietly(listener)
	require.Equal(t, "local", <-localCalls)
	require.Equal(t, "reverse", <-reverseCalls)
}

func TestUnixForwardingCallbackRetainsResultsOnError(t *testing.T) {
	forward, peer := net.Pipe()
	defer closeQuietly(forward)
	defer closeQuietly(peer)
	_, client, cleanup := newTestSession(t, &Server{
		Handler: func(Session) {},
		LocalUnixForwardingCallback: func(Context, string) (net.Conn, error) {
			return forward, ErrServerPermissionDenied
		},
	}, nil)
	defer cleanup()
	_, err := client.Dial("unix", "/virtual/owned-by-callback.sock")
	require.Error(t, err)
	require.NoError(t, peer.SetReadDeadline(time.Now().Add(20*time.Millisecond)))
	_, err = peer.Read(make([]byte, 1))
	var netErr net.Error
	require.ErrorAs(t, err, &netErr)
	require.True(t, netErr.Timeout())

	listener := newStreamLocalTestListener()
	defer closeQuietly(listener)
	handler := &ForwardedUnixHandler{}
	_, reverseClient, reverseCleanup := newTestSession(t, &Server{
		Handler: func(Session) {},
		ReverseUnixForwardingCallback: func(Context, string) (net.Listener, error) {
			return listener, ErrServerPermissionDenied
		},
		RequestHandlers: streamLocalRequestHandlers(handler),
	}, nil)
	defer reverseCleanup()
	_, err = reverseClient.ListenUnix("/virtual/owned-by-callback.sock")
	require.Error(t, err)
	select {
	case <-listener.closed:
		t.Fatal("server closed listener returned with an error")
	default:
	}
}

func acceptStreamLocal(t *testing.T, listener net.Listener) net.Conn {
	t.Helper()
	type result struct {
		conn net.Conn
		err  error
	}
	accepted := make(chan result, 1)
	go func() {
		conn, err := listener.Accept()
		accepted <- result{conn: conn, err: err}
	}()
	select {
	case got := <-accepted:
		require.NoError(t, got.err)
		require.NotNil(t, got.conn)
		return got.conn
	case <-time.After(time.Second):
		t.Fatal("timed out accepting forwarded connection")
		return nil
	}
}

func assertStreamLocalExchange(t *testing.T, left, right net.Conn) {
	t.Helper()
	for _, exchange := range []struct {
		from net.Conn
		to   net.Conn
		data []byte
	}{
		{from: left, to: right, data: []byte("left to right")},
		{from: right, to: left, data: []byte("right to left")},
	} {
		writeResult := make(chan error, 1)
		readResult := make(chan error, 1)
		got := make([]byte, len(exchange.data))
		go func() {
			_, err := exchange.from.Write(exchange.data)
			writeResult <- err
		}()
		go func() {
			_, err := io.ReadFull(exchange.to, got)
			readResult <- err
		}()
		select {
		case err := <-readResult:
			require.NoError(t, err)
		case <-time.After(time.Second):
			t.Fatal("timed out reading forwarded data")
		}
		require.True(t, bytes.Equal(exchange.data, got))
		select {
		case err := <-writeResult:
			require.NoError(t, err)
		case <-time.After(time.Second):
			t.Fatal("timed out writing forwarded data")
		}
	}
}

func TestStreamLocalWirePayloads(t *testing.T) {
	require.Equal(t,
		[]byte{0, 0, 0, 1, 'p', 0, 0, 0, 1, 'r', 0, 0, 0, 7},
		gossh.Marshal(&directStreamLocalChannelData{SocketPath: "p", Reserved1: "r", Reserved2: 7}),
	)
	require.Equal(t,
		[]byte{0, 0, 0, 1, 'p'},
		gossh.Marshal(&remoteUnixForwardRequest{SocketPath: "p"}),
	)
	require.Equal(t,
		[]byte{0, 0, 0, 1, 'p', 0, 0, 0, 1, 'r'},
		gossh.Marshal(&remoteUnixForwardChannelData{SocketPath: "p", Reserved: "r"}),
	)
}

func TestStreamLocalForwardRegistrationRaceError(t *testing.T) {
	require.True(t, isStreamLocalForwardRegistrationRace(&gossh.OpenChannelError{
		Reason:  gossh.Prohibited,
		Message: "no forward for address",
	}))
	for _, err := range []error{
		nil,
		errors.New("no forward for address"),
		&gossh.OpenChannelError{Reason: gossh.UnknownChannelType, Message: "no forward for address"},
		&gossh.OpenChannelError{Reason: gossh.Prohibited, Message: "different rejection"},
	} {
		require.False(t, isStreamLocalForwardRegistrationRace(err))
	}
}

func TestReverseStreamLocalRejectsMalformedPayloadBeforeCallback(t *testing.T) {
	handler := &ForwardedUnixHandler{}
	var callbackCalls atomic.Int64
	_, client, cleanup := newTestSession(t, &Server{
		Handler: func(Session) {},
		ReverseUnixForwardingCallback: func(Context, string) (net.Listener, error) {
			callbackCalls.Add(1)
			return nil, nil
		},
		RequestHandlers: streamLocalRequestHandlers(handler),
	}, nil)
	defer cleanup()

	payload := append(gossh.Marshal(&remoteUnixForwardRequest{SocketPath: "/virtual/socket.sock"}), 1)
	ok, _, err := client.SendRequest("streamlocal-forward@openssh.com", true, payload)
	require.NoError(t, err)
	require.False(t, ok)
	require.Zero(t, callbackCalls.Load())
}
