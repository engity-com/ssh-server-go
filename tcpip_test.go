package ssh

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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
		Handler: func(s Session) error { return nil },
		LocalPortForwardingCallback: func(ctx Context, _ gossh.ConnMetadata, destinationHost string, destinationPort uint32) (bool, error) {
			addr := net.JoinHostPort(destinationHost, strconv.FormatInt(int64(destinationPort), 10))
			if addr != l.Addr().String() {
				panic("unexpected destinationHost: " + addr)
			}
			return forwardingEnabled, nil
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
		Handler:                     func(Session) error { return nil },
		LocalPortForwardingCallback: func(Context, gossh.ConnMetadata, string, uint32) (bool, error) { return true, nil },
	}, nil)
	defer cleanup()

	_, err := client.Dial("tcp", addr)
	require.Error(t, err)
	require.Contains(t, err.Error(), "connection failed")
	require.NotContains(t, strings.ToLower(err.Error()), "refused")
}

func TestLocalPortForwardingReleasesChannelSlotAfterChannelClose(t *testing.T) {
	target := newLocalListener()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := target.Accept()
		if err == nil {
			accepted <- conn
		}
	}()
	maxChannels := 1
	initial, client, cleanup := newTestSession(t, &Server{
		Handler:                  func(Session) error { return nil },
		MaxChannelsPerConnection: &maxChannels,
		LocalPortForwardingCallback: func(Context, gossh.ConnMetadata, string, uint32) (bool, error) {
			return true, nil
		},
	}, nil)
	defer cleanup()
	defer closeQuietly(target)
	require.NoError(t, initial.Close())

	var forwarded net.Conn
	require.Eventually(t, func() bool {
		var err error
		forwarded, err = client.Dial("tcp", target.Addr().String())
		return err == nil
	}, time.Second, time.Millisecond)
	targetPeer := <-accepted
	defer closeQuietly(targetPeer)
	require.NoError(t, forwarded.Close())

	var next *gossh.Session
	require.Eventually(t, func() bool {
		var err error
		next, err = client.NewSession()
		return err == nil
	}, time.Second, time.Millisecond)
	closeQuietly(next)
}

func TestRemotePortZeroForwardIsRemovedOnCancel(t *testing.T) {
	handler := &ForwardedTCPHandler{}
	session, client, cleanup := newTestSession(t, &Server{
		Handler:                       func(Session) error { return nil },
		ReversePortForwardingCallback: func(Context, gossh.ConnMetadata, string, uint32) (bool, error) { return true, nil },
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

type trackedTCPListener struct {
	net.Listener
	closed chan struct{}
	once   sync.Once
}

func (l *trackedTCPListener) Close() error {
	err := l.Listener.Close()
	l.once.Do(func() { close(l.closed) })
	return err
}

func TestRemoteForwardDefaultListener(t *testing.T) {
	handler := &ForwardedTCPHandler{}
	_, client, cleanup := newTestSession(t, &Server{
		ReversePortForwardingCallback: func(Context, gossh.ConnMetadata, string, uint32) (bool, error) { return true, nil },
		RequestHandlers: map[string]RequestHandler{
			"tcpip-forward":        handler.HandleSSHRequest,
			"cancel-tcpip-forward": handler.HandleSSHRequest,
		},
	}, nil)
	defer cleanup()

	listener, err := client.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer closeQuietly(listener)
	addr, ok := listener.Addr().(*net.TCPAddr)
	require.True(t, ok)
	require.NotZero(t, addr.Port)
	peer, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	defer closeQuietly(peer)
	forwarded := acceptStreamLocal(t, listener)
	defer closeQuietly(forwarded)
	assertStreamLocalExchange(t, forwarded, peer)
	require.NoError(t, listener.Close())
	require.Eventually(t, func() bool {
		handler.Lock()
		defer handler.Unlock()
		return len(handler.forwards) == 0
	}, time.Second, time.Millisecond)
}

func TestRemoteForwardListenCallbackPortAndMetadata(t *testing.T) {
	type call struct {
		host    string
		port    uint32
		user    string
		sameCtx bool
	}
	calls := make(chan call, 1)
	var authorized atomic.Bool
	var serverListener *trackedTCPListener
	handler := &ForwardedTCPHandler{
		ListenCallback: func(ctx Context, conn gossh.ConnMetadata, host string, port uint32) (net.Listener, error) {
			if !authorized.Load() {
				return nil, errors.New("listener called before authorization")
			}
			ln, err := new(net.ListenConfig).Listen(ctx, "tcp", "127.0.0.1:0")
			if err != nil {
				return nil, err
			}
			serverListener = &trackedTCPListener{Listener: ln, closed: make(chan struct{})}
			calls <- call{host, port, conn.User(), ctx.Value(ContextKeyConn) == conn}
			return serverListener, nil
		},
	}
	_, client, cleanup := newTestSession(t, &Server{
		ReversePortForwardingCallback: func(Context, gossh.ConnMetadata, string, uint32) (bool, error) {
			authorized.Store(true)
			return true, nil
		},
		RequestHandlers: map[string]RequestHandler{
			"tcpip-forward":        handler.HandleSSHRequest,
			"cancel-tcpip-forward": handler.HandleSSHRequest,
		},
	}, nil)
	defer cleanup()

	incoming := client.HandleChannelOpen(forwardedTCPChannelType)
	require.NotNil(t, incoming)
	const bindHost = "localhost"
	ok, reply, err := client.SendRequest("tcpip-forward", true, gossh.Marshal(&remoteForwardRequest{BindAddr: bindHost, BindPort: 0}))
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, call{bindHost, 0, "testuser", true}, <-calls)
	var success remoteForwardSuccess
	require.NoError(t, gossh.Unmarshal(reply, &success))
	require.Equal(t, uint32(serverListener.Addr().(*net.TCPAddr).Port), success.BindPort)
	require.NotZero(t, success.BindPort)
	peer, err := net.Dial("tcp", serverListener.Addr().String())
	require.NoError(t, err)
	defer closeQuietly(peer)
	var opened gossh.NewChannel
	select {
	case opened = <-incoming:
		require.NotNil(t, opened)
	case <-time.After(time.Second):
		t.Fatal("forwarded-tcpip channel was not opened")
	}
	var data remoteForwardChannelData
	require.NoError(t, gossh.Unmarshal(opened.ExtraData(), &data))
	peerHost, peerPort, err := net.SplitHostPort(peer.LocalAddr().String())
	require.NoError(t, err)
	parsedPeerPort, err := strconv.Atoi(peerPort)
	require.NoError(t, err)
	require.Equal(t, remoteForwardChannelData{DestAddr: bindHost, DestPort: success.BindPort, OriginAddr: peerHost, OriginPort: uint32(parsedPeerPort)}, data)
	channel, requests, err := opened.Accept()
	require.NoError(t, err)
	defer closeQuietly(channel)
	go gossh.DiscardRequests(requests)

	ok, _, err = client.SendRequest("cancel-tcpip-forward", true, gossh.Marshal(&remoteForwardCancelRequest{BindAddr: bindHost, BindPort: success.BindPort}))
	require.NoError(t, err)
	require.True(t, ok)
	select {
	case <-serverListener.closed:
	case <-time.After(time.Second):
		t.Fatal("cancel did not close callback listener")
	}
	require.Eventually(t, func() bool {
		handler.Lock()
		defer handler.Unlock()
		return len(handler.forwards) == 0
	}, time.Second, time.Millisecond)
}

func TestRemoteForwardListenCallbackRejectsUnexpectedPort(t *testing.T) {
	listeners := make(chan *trackedTCPListener, 2)
	handler := &ForwardedTCPHandler{
		ListenCallback: func(ctx Context, _ gossh.ConnMetadata, _ string, _ uint32) (net.Listener, error) {
			ln, err := new(net.ListenConfig).Listen(ctx, "tcp", "127.0.0.1:0")
			if err != nil {
				return nil, err
			}
			tracked := &trackedTCPListener{Listener: ln, closed: make(chan struct{})}
			listeners <- tracked
			return tracked, nil
		},
	}
	maxForwards := 1
	_, client, cleanup := newTestSession(t, &Server{
		MaxReverseForwardsPerConnection: &maxForwards,
		ReversePortForwardingCallback:   func(Context, gossh.ConnMetadata, string, uint32) (bool, error) { return true, nil },
		RequestHandlers: map[string]RequestHandler{
			"tcpip-forward":        handler.HandleSSHRequest,
			"cancel-tcpip-forward": handler.HandleSSHRequest,
		},
	}, nil)
	defer cleanup()

	const requestedPort = 1
	_, err := client.Listen("tcp", "127.0.0.1:1")
	require.Error(t, err)
	listener := <-listeners
	require.NotEqual(t, requestedPort, listener.Addr().(*net.TCPAddr).Port)
	select {
	case <-listener.closed:
	case <-time.After(time.Second):
		t.Fatal("rejected listener was not closed")
	}
	handler.Lock()
	count := len(handler.forwards)
	handler.Unlock()
	require.Zero(t, count)
	next, err := client.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "rejected listener must release the forward slot")
	require.NoError(t, next.Close())
}

type formattedTCPAddr string

func (formattedTCPAddr) Network() string  { return "tcp" }
func (a formattedTCPAddr) String() string { return string(a) }

type formattedTCPListener struct {
	*trackedTCPListener
	addr net.Addr
}

func (l *formattedTCPListener) Addr() net.Addr { return l.addr }

func TestRemoteForwardListenCallbackCanonicalizesPort(t *testing.T) {
	listeners := make(chan *trackedTCPListener, 1)
	handler := &ForwardedTCPHandler{
		ListenCallback: func(ctx Context, _ gossh.ConnMetadata, _ string, _ uint32) (net.Listener, error) {
			ln, err := new(net.ListenConfig).Listen(ctx, "tcp", "127.0.0.1:0")
			if err != nil {
				return nil, err
			}
			tracked := &trackedTCPListener{Listener: ln, closed: make(chan struct{})}
			listeners <- tracked
			port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
			return &formattedTCPListener{tracked, formattedTCPAddr(net.JoinHostPort("127.0.0.1", "000"+port))}, nil
		},
	}
	_, client, cleanup := newTestSession(t, &Server{
		ReversePortForwardingCallback: func(Context, gossh.ConnMetadata, string, uint32) (bool, error) { return true, nil },
		RequestHandlers: map[string]RequestHandler{
			"tcpip-forward":        handler.HandleSSHRequest,
			"cancel-tcpip-forward": handler.HandleSSHRequest,
		},
	}, nil)
	defer cleanup()

	listener, err := client.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	tracked := <-listeners
	require.Equal(t, tracked.Addr().(*net.TCPAddr).Port, listener.Addr().(*net.TCPAddr).Port)
	require.NoError(t, listener.Close())
	select {
	case <-tracked.closed:
	case <-time.After(time.Second):
		t.Fatal("cancel did not close listener with formatted port")
	}
	require.Eventually(t, func() bool {
		handler.Lock()
		defer handler.Unlock()
		return len(handler.forwards) == 0
	}, time.Second, time.Millisecond)
}

func TestRemoteForwardListenCallbackRejectsDuplicateBoundPort(t *testing.T) {
	maxForwards := 2
	listeners := make(chan *trackedTCPListener, 3)
	var firstPort atomic.Int32
	var calls atomic.Int32
	handler := &ForwardedTCPHandler{
		ListenCallback: func(ctx Context, _ gossh.ConnMetadata, _ string, _ uint32) (net.Listener, error) {
			ln, err := new(net.ListenConfig).Listen(ctx, "tcp", "127.0.0.1:0")
			if err != nil {
				return nil, err
			}
			tracked := &trackedTCPListener{Listener: ln, closed: make(chan struct{})}
			listeners <- tracked
			switch calls.Add(1) {
			case 1:
				firstPort.Store(int32(ln.Addr().(*net.TCPAddr).Port))
			case 2:
				return &formattedTCPListener{tracked, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 2), Port: int(firstPort.Load())}}, nil
			}
			return tracked, nil
		},
	}
	_, client, cleanup := newTestSession(t, &Server{
		MaxReverseForwardsPerConnection: &maxForwards,
		ReversePortForwardingCallback:   func(Context, gossh.ConnMetadata, string, uint32) (bool, error) { return true, nil },
		RequestHandlers: map[string]RequestHandler{
			"tcpip-forward":        handler.HandleSSHRequest,
			"cancel-tcpip-forward": handler.HandleSSHRequest,
		},
	}, nil)
	defer cleanup()

	first, err := client.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer closeQuietly(first)
	firstServer := <-listeners
	_, err = client.Listen("tcp", "127.0.0.1:0")
	require.Error(t, err)
	duplicate := <-listeners
	select {
	case <-duplicate.closed:
	case <-time.After(time.Second):
		t.Fatal("duplicate listener was not closed")
	}
	select {
	case <-firstServer.closed:
		t.Fatal("duplicate closed the existing listener")
	default:
	}

	third, err := client.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "duplicate must release its forward slot")
	defer closeQuietly(third)
	<-listeners
	peer, err := net.Dial("tcp", firstServer.Addr().String())
	require.NoError(t, err)
	defer closeQuietly(peer)
	forwarded := acceptStreamLocal(t, first)
	defer closeQuietly(forwarded)
	assertStreamLocalExchange(t, forwarded, peer)
	require.NoError(t, first.Close())
	require.NoError(t, third.Close())
	require.Eventually(t, func() bool {
		handler.Lock()
		defer handler.Unlock()
		return len(handler.forwards) == 0
	}, time.Second, time.Millisecond)
}

func TestRemoteForwardListenCallbackCanRebindAfterCancel(t *testing.T) {
	handler := &ForwardedTCPHandler{
		ListenCallback: func(ctx Context, _ gossh.ConnMetadata, host string, port uint32) (net.Listener, error) {
			return new(net.ListenConfig).Listen(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(int(port))))
		},
	}
	_, client, cleanup := newTestSession(t, &Server{
		ReversePortForwardingCallback: func(Context, gossh.ConnMetadata, string, uint32) (bool, error) { return true, nil },
		RequestHandlers: map[string]RequestHandler{
			"tcpip-forward":        handler.HandleSSHRequest,
			"cancel-tcpip-forward": handler.HandleSSHRequest,
		},
	}, nil)
	defer cleanup()

	first, err := client.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := first.Addr().String()
	require.NoError(t, first.Close())
	second, err := client.Listen("tcp", addr)
	require.NoError(t, err, "a confirmed cancel must allow immediate reuse of the same port")
	require.NoError(t, second.Close())
}

func TestRemoteForwardListenCallbackFailureReleasesLimit(t *testing.T) {
	for _, failure := range []string{"error", "listener and error", "nil listener", "invalid address"} {
		t.Run(failure, func(t *testing.T) {
			maxForwards := 1
			var attempts atomic.Int32
			var failedListener *trackedTCPListener
			handler := &ForwardedTCPHandler{
				ListenCallback: func(ctx Context, _ gossh.ConnMetadata, _ string, _ uint32) (net.Listener, error) {
					if attempts.Add(1) != 1 {
						return new(net.ListenConfig).Listen(ctx, "tcp", "127.0.0.1:0")
					}
					if failure == "error" {
						return nil, errors.New("bind failed")
					}
					if failure == "nil listener" {
						return nil, nil
					}
					ln, err := new(net.ListenConfig).Listen(ctx, "tcp", "127.0.0.1:0")
					if err != nil {
						return nil, err
					}
					failedListener = &trackedTCPListener{Listener: ln, closed: make(chan struct{})}
					if failure == "listener and error" {
						return failedListener, errors.New("bind failed")
					}
					return invalidTCPListener{failedListener}, nil
				},
			}
			_, client, cleanup := newTestSession(t, &Server{
				MaxReverseForwardsPerConnection: &maxForwards,
				ReversePortForwardingCallback:   func(Context, gossh.ConnMetadata, string, uint32) (bool, error) { return true, nil },
				RequestHandlers: map[string]RequestHandler{
					"tcpip-forward":        handler.HandleSSHRequest,
					"cancel-tcpip-forward": handler.HandleSSHRequest,
				},
			}, nil)
			defer cleanup()

			_, err := client.Listen("tcp", "127.0.0.1:0")
			require.Error(t, err)
			handler.Lock()
			count := len(handler.forwards)
			handler.Unlock()
			require.Zero(t, count)
			if failedListener != nil {
				select {
				case <-failedListener.closed:
				case <-time.After(time.Second):
					t.Fatal("failed callback listener was not closed")
				}
			}
			listener, err := client.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err, "failed bind must release the forward slot")
			require.NoError(t, listener.Close())
			require.Equal(t, int32(2), attempts.Load())
		})
	}
}

type invalidTCPListener struct{ *trackedTCPListener }

func (invalidTCPListener) Addr() net.Addr { return &net.UnixAddr{Name: "invalid", Net: "unix"} }

func TestRemoteForwardListenCallbackRequiresAuthorizationAndCapacity(t *testing.T) {
	maxForwards := 1
	var calls atomic.Int32
	handler := &ForwardedTCPHandler{
		ListenCallback: func(ctx Context, _ gossh.ConnMetadata, _ string, _ uint32) (net.Listener, error) {
			calls.Add(1)
			return new(net.ListenConfig).Listen(ctx, "tcp", "127.0.0.1:0")
		},
	}
	_, client, cleanup := newTestSession(t, &Server{
		MaxReverseForwardsPerConnection: &maxForwards,
		ReversePortForwardingCallback: func(_ Context, _ gossh.ConnMetadata, _ string, port uint32) (bool, error) {
			return port != 12345, nil
		},
		RequestHandlers: map[string]RequestHandler{
			"tcpip-forward":        handler.HandleSSHRequest,
			"cancel-tcpip-forward": handler.HandleSSHRequest,
		},
	}, nil)
	defer cleanup()

	_, err := client.Listen("tcp", "127.0.0.1:12345")
	require.Error(t, err)
	require.Zero(t, calls.Load())
	first, err := client.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer closeQuietly(first)
	_, err = client.Listen("tcp", "127.0.0.1:0")
	require.Error(t, err)
	require.Equal(t, int32(1), calls.Load())
}

func TestRemoteForwardListenCallbackClosesOnDisconnect(t *testing.T) {
	listeners := make(chan *trackedTCPListener, 1)
	disconnected := make(chan bool, 1)
	handler := &ForwardedTCPHandler{
		ListenCallback: func(ctx Context, _ gossh.ConnMetadata, _ string, _ uint32) (net.Listener, error) {
			ln, err := new(net.ListenConfig).Listen(ctx, "tcp", "127.0.0.1:0")
			if err != nil {
				return nil, err
			}
			tracked := &trackedTCPListener{Listener: ln, closed: make(chan struct{})}
			listeners <- tracked
			return tracked, nil
		},
	}
	_, client, cleanup := newTestSession(t, &Server{
		ReversePortForwardingCallback: func(Context, gossh.ConnMetadata, string, uint32) (bool, error) { return true, nil },
		DisconnectCallback: func(Context, net.Conn) error {
			select {
			case listener := <-listeners:
				select {
				case <-listener.closed:
					disconnected <- true
				default:
					disconnected <- false
				}
			default:
				disconnected <- false
			}
			return nil
		},
		RequestHandlers: map[string]RequestHandler{
			"tcpip-forward":        handler.HandleSSHRequest,
			"cancel-tcpip-forward": handler.HandleSSHRequest,
		},
	}, nil)
	defer cleanup()

	listener, err := client.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer closeQuietly(listener)
	require.NoError(t, client.Close())
	select {
	case closed := <-disconnected:
		require.True(t, closed)
	case <-time.After(time.Second):
		t.Fatal("disconnect callback was not called")
	}
	handler.Lock()
	count := len(handler.forwards)
	handler.Unlock()
	require.Zero(t, count)
}

func TestRemoteForwardIsRemovedWhenRequestReplyFails(t *testing.T) {
	listeners := make(chan *trackedTCPListener, 1)
	handler := &ForwardedTCPHandler{
		ListenCallback: func(ctx Context, _ gossh.ConnMetadata, _ string, _ uint32) (net.Listener, error) {
			ln, err := new(net.ListenConfig).Listen(ctx, "tcp", "127.0.0.1:0")
			if err != nil {
				return nil, err
			}
			tracked := &trackedTCPListener{Listener: ln, closed: make(chan struct{})}
			listeners <- tracked
			return tracked, nil
		},
	}
	session, client, cleanup := newTestSession(t, &Server{
		Handler:                       func(Session) error { return nil },
		ReversePortForwardingCallback: func(Context, gossh.ConnMetadata, string, uint32) (bool, error) { return true, nil },
		RequestHandlers: map[string]RequestHandler{
			"tcpip-forward": func(response RequestResponseWriter, request *Request) error {
				return handler.HandleSSHRequest(requestResponseWriterFuncs{
					accept: func(payload []byte) error {
						closeSSHConnection(request.Context())
						return response.Accept(payload)
					},
					reject: response.Reject,
				}, request)
			},
		},
	}, nil)
	defer cleanup()
	defer closeQuietly(session)

	_, _, err := client.SendRequest("tcpip-forward", true, gossh.Marshal(&remoteForwardRequest{BindAddr: "127.0.0.1", BindPort: 0}))
	require.Error(t, err)
	listener := <-listeners
	select {
	case <-listener.closed:
	case <-time.After(time.Second):
		t.Fatal("failed reply did not close callback listener")
	}

	require.Eventually(t, func() bool {
		handler.Lock()
		defer handler.Unlock()
		return len(handler.forwards) == 0
	}, time.Second, time.Millisecond)
}

type requestResponseWriterFuncs struct {
	accept func([]byte) error
	reject func([]byte) error
}

func (r requestResponseWriterFuncs) Accept(payload []byte) error {
	if r.accept == nil {
		return nil
	}
	return r.accept(payload)
}

func (r requestResponseWriterFuncs) Reject(message []byte) error {
	if r.reject == nil {
		return nil
	}
	return r.reject(message)
}

func TestRemoteForwardListenerLimit(t *testing.T) {
	maxForwards := 1
	handler := &ForwardedTCPHandler{}
	session, client, cleanup := newTestSession(t, &Server{
		Handler:                         func(Session) error { return nil },
		MaxReverseForwardsPerConnection: &maxForwards,
		ReversePortForwardingCallback:   func(Context, gossh.ConnMetadata, string, uint32) (bool, error) { return true, nil },
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

func TestRemotePortForwardingReleasesChannelSlotAfterChannelClose(t *testing.T) {
	maxChannels := 1
	handler := &ForwardedTCPHandler{}
	initial, client, cleanup := newTestSession(t, &Server{
		Handler:                  func(Session) error { return nil },
		MaxChannelsPerConnection: &maxChannels,
		ReversePortForwardingCallback: func(Context, gossh.ConnMetadata, string, uint32) (bool, error) {
			return true, nil
		},
		RequestHandlers: map[string]RequestHandler{
			"tcpip-forward":        handler.HandleSSHRequest,
			"cancel-tcpip-forward": handler.HandleSSHRequest,
		},
	}, nil)
	defer cleanup()
	require.NoError(t, initial.Close())

	listener, err := client.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer closeQuietly(listener)
	tcpPeer, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	defer closeQuietly(tcpPeer)
	forwarded, err := listener.Accept()
	require.NoError(t, err)
	require.NoError(t, forwarded.Close())

	var next *gossh.Session
	require.Eventually(t, func() bool {
		var err error
		next, err = client.NewSession()
		return err == nil
	}, time.Second, time.Millisecond)
	closeQuietly(next)
}

func TestRemoteForwardListenerLimitIsSharedAcrossProtocolsWithinServe(t *testing.T) {
	maxForwards := 1
	tcpHandler := &ForwardedTCPHandler{}
	unixHandler := &ForwardedUnixHandler{}
	requestHandlers := streamLocalRequestHandlers(unixHandler)
	requestHandlers["tcpip-forward"] = tcpHandler.HandleSSHRequest
	requestHandlers["cancel-tcpip-forward"] = tcpHandler.HandleSSHRequest
	srv := &Server{
		MaxReverseForwards:            &maxForwards,
		ReversePortForwardingCallback: func(Context, gossh.ConnMetadata, string, uint32) (bool, error) { return true, nil },
		ReverseUnixForwardingCallback: func(Context, gossh.ConnMetadata, string) (net.Listener, error) {
			return newStreamLocalTestListener(), nil
		},
		RequestHandlers: requestHandlers,
	}
	listener := newLocalListener()
	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- srv.Serve(ctx, listener) }()
	config := &gossh.ClientConfig{User: "test", HostKeyCallback: gossh.InsecureIgnoreHostKey()}
	firstClient, err := gossh.Dial("tcp", listener.Addr().String(), config)
	require.NoError(t, err)
	secondClient, err := gossh.Dial("tcp", listener.Addr().String(), config)
	require.NoError(t, err)
	defer func() {
		closeQuietly(firstClient)
		closeQuietly(secondClient)
		cancel()
		closeQuietly(listener)
		<-serveDone
	}()

	first, err := firstClient.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	_, err = secondClient.ListenUnix("/virtual/globally-limited.sock")
	require.Error(t, err)
	require.NoError(t, first.Close())

	var second net.Listener
	require.Eventually(t, func() bool {
		second, err = secondClient.ListenUnix("/virtual/globally-limited.sock")
		return err == nil
	}, time.Second, time.Millisecond)
	closeQuietly(second)
}

type blockingSSHConn struct {
	started     chan struct{}
	openRelease chan struct{}
	closed      chan struct{}
	closeOnce   sync.Once
	releaseOnce sync.Once
}

func (c *blockingSSHConn) User() string          { return "test" }
func (c *blockingSSHConn) SessionID() []byte     { return nil }
func (c *blockingSSHConn) ClientVersion() []byte { return nil }
func (c *blockingSSHConn) ServerVersion() []byte { return nil }
func (c *blockingSSHConn) RemoteAddr() net.Addr  { return nil }
func (c *blockingSSHConn) LocalAddr() net.Addr   { return nil }
func (c *blockingSSHConn) SendRequest(string, bool, []byte) (bool, []byte, error) {
	return false, nil, nil
}
func (c *blockingSSHConn) OpenChannel(string, []byte) (gossh.Channel, <-chan *gossh.Request, error) {
	close(c.started)
	<-c.openRelease
	return nil, nil, net.ErrClosed
}
func (c *blockingSSHConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	c.releaseOpen()
	return nil
}
func (c *blockingSSHConn) Wait() error {
	<-c.closed
	return net.ErrClosed
}

func (c *blockingSSHConn) releaseOpen() {
	c.releaseOnce.Do(func() { close(c.openRelease) })
}

func TestOpenForwardedChannelTimeoutDoesNotCloseSSHConnection(t *testing.T) {
	conn := &blockingSSHConn{started: make(chan struct{}), openRelease: make(chan struct{}), closed: make(chan struct{})}
	defer conn.releaseOpen()
	result := make(chan error, 1)
	go func() {
		_, _, err := openForwardedChannel(context.Background(), nil, conn, agentChannelType, nil)
		result <- err
	}()
	<-conn.started
	select {
	case err := <-result:
		require.ErrorIs(t, err, context.DeadlineExceeded)
	case <-time.After(2 * forwardedChannelRegistrationTimeout):
		t.Fatal("blocked channel open was not terminated")
	}
	select {
	case <-conn.closed:
		t.Fatal("SSH connection was closed")
	default:
	}
}

func TestForwardedChannelTimeoutKeepsSSHTransportUsable(t *testing.T) {
	handler := &ForwardedTCPHandler{}
	handlerStarted := make(chan struct{}, 2)
	active, client, cleanup := newTestSession(t, &Server{
		Handler: func(session Session) error {
			handlerStarted <- struct{}{}
			_, err := io.Copy(session, session)
			return err
		},
		ReversePortForwardingCallback: func(Context, gossh.ConnMetadata, string, uint32) (bool, error) { return true, nil },
		RequestHandlers: map[string]RequestHandler{
			"tcpip-forward":        handler.HandleSSHRequest,
			"cancel-tcpip-forward": handler.HandleSSHRequest,
		},
	}, nil)
	defer cleanup()
	defer closeQuietly(active)
	activeStdin, activeStdout := startEchoClientSession(t, active)
	<-handlerStarted

	incoming := client.HandleChannelOpen(forwardedTCPChannelType)
	require.NotNil(t, incoming)
	ok, response, err := client.SendRequest("tcpip-forward", true, gossh.Marshal(&remoteForwardRequest{
		BindAddr: "127.0.0.1",
		BindPort: 0,
	}))
	require.NoError(t, err)
	require.True(t, ok)
	var forward remoteForwardSuccess
	require.NoError(t, gossh.Unmarshal(response, &forward))

	forwardConn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(forward.BindPort))))
	require.NoError(t, err)
	defer closeQuietly(forwardConn)
	var delayed gossh.NewChannel
	select {
	case delayed = <-incoming:
		require.NotNil(t, delayed)
		require.Equal(t, forwardedTCPChannelType, delayed.ChannelType())
	case <-time.After(forwardedChannelRegistrationTimeout):
		t.Fatal("did not receive forwarded-tcpip channel")
	}

	require.NoError(t, forwardConn.SetReadDeadline(time.Now().Add(2*forwardedChannelRegistrationTimeout)))
	var b [1]byte
	_, err = forwardConn.Read(b[:])
	require.ErrorIs(t, err, io.EOF, "forwarded TCP connection must fail after the channel-open timeout")

	requireEcho(t, activeStdin, activeStdout, "active session remains usable")
	next, err := client.NewSession()
	require.NoError(t, err)
	defer closeQuietly(next)
	nextStdin, nextStdout := startEchoClientSession(t, next)
	<-handlerStarted
	requireEcho(t, nextStdin, nextStdout, "new session works")

	lateChannel, lateRequests, err := delayed.Accept()
	require.NoError(t, err)
	defer closeQuietly(lateChannel)
	go gossh.DiscardRequests(lateRequests)
	lateClosed := make(chan error, 1)
	go func() {
		_, err := lateChannel.Read(b[:])
		lateClosed <- err
	}()
	select {
	case err := <-lateClosed:
		require.ErrorIs(t, err, io.EOF)
	case <-time.After(time.Second):
		t.Fatal("late forwarded-tcpip channel was not closed")
	}
}
