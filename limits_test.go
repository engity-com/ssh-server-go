package ssh

import (
	"context"
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

type limitRejectionRecorder struct {
	mu          sync.Mutex
	reasons     []LimitRejectionReason
	callbackErr error
}

func (r *limitRejectionRecorder) record(reason LimitRejectionReason) {
	r.mu.Lock()
	r.reasons = append(r.reasons, reason)
	r.mu.Unlock()
}

func (r *limitRejectionRecorder) callback(reason LimitRejectionReason) error {
	r.record(reason)
	return r.callbackErr
}

func (r *limitRejectionRecorder) require(t *testing.T, reason LimitRejectionReason, count int) {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	require.Len(t, r.reasons, count)
	for _, got := range r.reasons {
		require.Equal(t, reason, got)
	}
}

func TestLimitRejectionReasonString(t *testing.T) {
	for reason, name := range map[LimitRejectionReason]string{
		LimitRejectionMaxStartups:                     "max_startups",
		LimitRejectionMaxConnections:                  "max_connections",
		LimitRejectionMaxChannels:                     "max_channels",
		LimitRejectionMaxChannelsPerConnection:        "max_channels_per_connection",
		LimitRejectionMaxSessionsPerConnection:        "max_sessions_per_connection",
		LimitRejectionMaxReverseForwards:              "max_reverse_forwards",
		LimitRejectionMaxReverseForwardsPerConnection: "max_reverse_forwards_per_connection",
		0:   "unknown",
		255: "unknown",
	} {
		require.Equal(t, name, reason.String())
	}
}

func TestLimitRejectedCallbackMaxStartups(t *testing.T) {
	for name, config := range map[string]MaxStartupsConfig{
		"full":       {Start: 1, Full: 1},
		"early drop": {Start: 1, Rate: 100, Full: 10},
	} {
		t.Run(name, func(t *testing.T) {
			for _, mode := range limitCallbackTestModes() {
				t.Run(mode.name, func(t *testing.T) {
					recorder := limitRejectionRecorder{callbackErr: mode.err}
					srv := &Server{MaxStartups: &config}
					scope := newServeContext(srv, context.Background(), nil)
					if mode.enabled {
						srv.LimitRejectedCallback = func(reason LimitRejectionReason) error {
							if scope.mu.TryLock() {
								scope.mu.Unlock()
							} else {
								t.Error("callback ran under the serve scope lock")
							}
							return recorder.callback(reason)
						}
					}
					first, firstPeer := net.Pipe()
					defer closeQuietly(first)
					defer closeQuietly(firstPeer)
					active := scope.trackConnection(first)
					require.NotNil(t, active)
					recorder.require(t, 0, 0)
					for range 3 {
						conn, peer := net.Pipe()
						require.NoError(t, peer.SetReadDeadline(time.Now().Add(time.Second)))
						require.Nil(t, scope.trackConnection(conn))
						_, err := peer.Read(make([]byte, 1))
						require.ErrorIs(t, err, io.EOF)
						closeQuietly(peer)
					}
					count := 0
					if mode.enabled {
						count = 3
					}
					recorder.require(t, LimitRejectionMaxStartups, count)
					scope.untrackConnection(active)
					// Shutdown rejection is not a protection-limit rejection.
					require.NoError(t, scope.stopAccepting())
					conn, peer := net.Pipe()
					defer closeQuietly(peer)
					require.Nil(t, scope.trackConnection(conn))
					recorder.require(t, LimitRejectionMaxStartups, count)
				})
			}
		})
	}
}

func TestLimitRejectedCallbackMaxStartupsRandomEarlyDrops(t *testing.T) {
	var recorder limitRejectionRecorder
	srv := &Server{
		MaxStartups:           &MaxStartupsConfig{Start: 0, Rate: 50, Full: 1000},
		LimitRejectedCallback: recorder.callback,
	}
	scope := newServeContext(srv, context.Background(), nil)
	rejected := 0
	for range 128 {
		conn, peer := net.Pipe()
		if active := scope.trackConnection(conn); active != nil {
			scope.untrackConnection(active)
		} else {
			rejected++
		}
		closeQuietly(conn)
		closeQuietly(peer)
	}
	// Count actual decisions rather than relying on a particular random sample.
	recorder.require(t, LimitRejectionMaxStartups, rejected)
}

type limitCallbackTestMode struct {
	name    string
	enabled bool
	err     error
}

func limitCallbackTestModes() []limitCallbackTestMode {
	return []limitCallbackTestMode{
		{name: "nil callback"},
		{name: "callback", enabled: true},
		{name: "failing callback", enabled: true, err: errors.New("observation failed")},
	}
}

func startLimitTestServer(t *testing.T, srv *Server) string {
	t.Helper()
	listener := newLocalListener()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, listener) }()
	t.Cleanup(func() {
		cancel()
		closeQuietly(listener)
		select {
		case err := <-done:
			require.ErrorIs(t, err, context.Canceled)
		case <-time.After(time.Second):
			t.Error("server did not stop")
		}
	})
	return listener.Addr().String()
}

func dialLimitTestClient(t *testing.T, addr string) *gossh.Client {
	t.Helper()
	client, err := gossh.Dial("tcp", addr, &gossh.ClientConfig{
		User: "test", HostKeyCallback: gossh.InsecureIgnoreHostKey(), Timeout: time.Second,
	})
	require.NoError(t, err)
	t.Cleanup(func() { closeQuietly(client) })
	return client
}

func TestLimitRejectedCallbackMaxConnections(t *testing.T) {
	for _, mode := range limitCallbackTestModes() {
		t.Run(mode.name, func(t *testing.T) {
			recorder := limitRejectionRecorder{callbackErr: mode.err}
			limit := 1
			disconnected := make(chan struct{}, 4)
			srv := &Server{
				MaxConnections: &limit,
				DisconnectCallback: func(Context, net.Conn) error {
					disconnected <- struct{}{}
					return nil
				},
			}
			if mode.enabled {
				srv.LimitRejectedCallback = recorder.callback
			}
			addr := startLimitTestServer(t, srv)
			first := dialLimitTestClient(t, addr)
			session, err := first.NewSession()
			require.NoError(t, err) // Synchronize with the first reservation.
			defer closeQuietly(session)
			recorder.require(t, 0, 0)
			for range 3 {
				client, _ := gossh.Dial("tcp", addr, &gossh.ClientConfig{
					User: "test", HostKeyCallback: gossh.InsecureIgnoreHostKey(), Timeout: time.Second,
				})
				if client != nil {
					defer closeQuietly(client)
					_, err = client.NewSession()
					require.Error(t, err)
				}
				select {
				case <-disconnected:
				case <-time.After(time.Second):
					t.Fatal("rejected connection was not disconnected")
				}
			}
			count := 0
			if mode.enabled {
				count = 3
			}
			recorder.require(t, LimitRejectionMaxConnections, count)
			next, err := first.NewSession()
			require.NoError(t, err, "accepted connection must remain usable")
			closeQuietly(next)
		})
	}
}

func TestLimitRejectedCallbackIncomingChannels(t *testing.T) {
	for _, tc := range []struct {
		name                       string
		channels, global, sessions int
		reason                     LimitRejectionReason
		message                    string
	}{
		{"connection before global and sessions", 1, 1, 1, LimitRejectionMaxChannelsPerConnection, "too many open channels"},
		{"global before sessions", 2, 1, 1, LimitRejectionMaxChannels, "too many open channels"},
		{"sessions", 2, 2, 1, LimitRejectionMaxSessionsPerConnection, "too many open sessions"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, mode := range limitCallbackTestModes() {
				t.Run(mode.name, func(t *testing.T) {
					recorder := limitRejectionRecorder{callbackErr: mode.err}
					srv := &Server{
						MaxChannelsPerConnection: &tc.channels, MaxChannels: &tc.global,
						MaxSessionsPerConnection: &tc.sessions,
					}
					if mode.enabled {
						srv.LimitRejectedCallback = recorder.callback
					}
					first, client, cleanup := newTestSession(t, srv, nil)
					defer cleanup()
					defer closeQuietly(first)
					recorder.require(t, 0, 0)
					// Unsupported channels are rejected before consulting limits.
					_, _, err := client.OpenChannel("unsupported", nil)
					require.Error(t, err)
					recorder.require(t, 0, 0)
					for range 3 {
						_, err = client.NewSession()
						var openErr *gossh.OpenChannelError
						require.ErrorAs(t, err, &openErr)
						require.Equal(t, gossh.ResourceShortage, openErr.Reason)
						require.Equal(t, tc.message, openErr.Message)
					}
					count := 0
					if mode.enabled {
						count = 3
					}
					recorder.require(t, tc.reason, count)
				})
			}
		})
	}
}

func TestLimitRejectedCallbackReverseForwards(t *testing.T) {
	for _, protocol := range []string{"tcp", "unix"} {
		for _, global := range []bool{false, true} {
			for _, mode := range limitCallbackTestModes() {
				reason := LimitRejectionMaxReverseForwardsPerConnection
				if global {
					reason = LimitRejectionMaxReverseForwards
				}
				t.Run(protocol+"/"+reason.String()+"/"+mode.name, func(t *testing.T) {
					recorder := limitRejectionRecorder{callbackErr: mode.err}
					tcpHandler, unixHandler := &ForwardedTCPHandler{}, &ForwardedUnixHandler{}
					handlers := streamLocalRequestHandlers(unixHandler)
					handlers["tcpip-forward"] = tcpHandler.HandleSSHRequest
					localLimit, globalLimit := 1, 1
					if global {
						localLimit = 2
					}
					srv := &Server{
						MaxReverseForwardsPerConnection: &localLimit, MaxReverseForwards: &globalLimit,
						RequestHandlers: handlers,
						ReversePortForwardingCallback: func(Context, gossh.ConnMetadata, string, uint32) (bool, error) {
							return true, nil
						},
						ReverseUnixForwardingCallback: func(Context, gossh.ConnMetadata, string) (net.Listener, error) {
							return newStreamLocalTestListener(), nil
						},
					}
					if mode.enabled {
						srv.LimitRejectedCallback = func(reason LimitRejectionReason) error {
							for _, mu := range []*sync.Mutex{&tcpHandler.Mutex, &unixHandler.Mutex} {
								if mu.TryLock() {
									mu.Unlock()
								} else {
									t.Error("callback ran under a forwarding handler lock")
								}
							}
							return recorder.callback(reason)
						}
					}
					_, client, cleanup := newTestSession(t, srv, nil)
					defer cleanup()
					requestType := "tcpip-forward"
					payload := gossh.Marshal(remoteForwardRequest{BindAddr: "127.0.0.1"})
					if protocol == "unix" {
						requestType = "streamlocal-forward@openssh.com"
						payload = gossh.Marshal(remoteUnixForwardRequest{SocketPath: "/virtual/first.sock"})
					}
					ok, _, err := client.SendRequest(requestType, true, payload)
					require.NoError(t, err)
					require.True(t, ok)
					recorder.require(t, 0, 0)
					if protocol == "unix" {
						// A duplicate is not a limit rejection, even at capacity.
						ok, _, err = client.SendRequest(requestType, true, payload)
						require.NoError(t, err)
						require.False(t, ok)
						recorder.require(t, 0, 0)
						payload = gossh.Marshal(remoteUnixForwardRequest{SocketPath: "/virtual/next.sock"})
					}
					for range 3 {
						ok, reply, err := client.SendRequest(requestType, true, payload)
						require.NoError(t, err)
						require.False(t, ok)
						if protocol == "tcp" {
							require.Equal(t, []byte("too many reverse port forwards"), reply)
						} else {
							require.Empty(t, reply)
						}
					}
					count := 0
					if mode.enabled {
						count = 3
					}
					recorder.require(t, reason, count)
				})
			}
		}
	}
}

func TestLimitRejectedCallbackForwardedChannels(t *testing.T) {
	for _, protocol := range []string{"tcp", "unix", "agent"} {
		for _, global := range []bool{false, true} {
			for _, mode := range limitCallbackTestModes() {
				reason := LimitRejectionMaxChannelsPerConnection
				if global {
					reason = LimitRejectionMaxChannels
				}
				t.Run(protocol+"/"+reason.String()+"/"+mode.name, func(t *testing.T) {
					recorder := limitRejectionRecorder{callbackErr: mode.err}
					serverListener := newStreamLocalTestListener()
					tcpHandler, unixHandler := &ForwardedTCPHandler{}, &ForwardedUnixHandler{}
					handlers := streamLocalRequestHandlers(unixHandler)
					handlers["tcpip-forward"] = tcpHandler.HandleSSHRequest
					handlers["cancel-tcpip-forward"] = tcpHandler.HandleSSHRequest
					localLimit, globalLimit := 1, 1
					if global {
						localLimit = 0
					}
					srv := &Server{
						MaxChannelsPerConnection: &localLimit, MaxChannels: &globalLimit,
						RequestHandlers: handlers,
						ReversePortForwardingCallback: func(Context, gossh.ConnMetadata, string, uint32) (bool, error) {
							return true, nil
						},
						ReverseUnixForwardingCallback: func(Context, gossh.ConnMetadata, string) (net.Listener, error) {
							return serverListener, nil
						},
					}
					if mode.enabled {
						srv.LimitRejectedCallback = recorder.callback
					}
					if protocol == "agent" {
						srv.Handler = func(sess Session) error {
							ForwardAgentConnections(serverListener, nil, sess)
							return nil
						}
					}
					first, client, cleanup := newTestSession(t, srv, nil)
					defer cleanup()
					defer closeQuietly(serverListener)
					var listener net.Listener
					var err error
					switch protocol {
					case "tcp":
						listener, err = client.Listen("tcp", "127.0.0.1:0")
					case "unix":
						listener, err = client.ListenUnix("/virtual/channel-limited.sock")
					case "agent":
						err = first.Shell()
					}
					require.NoError(t, err)
					defer closeQuietly(listener)
					recorder.require(t, 0, 0)
					for range 3 {
						var peer net.Conn
						if protocol == "tcp" {
							peer, err = net.Dial("tcp", listener.Addr().String())
							require.NoError(t, err)
						} else {
							peer = serverListener.connect(t)
						}
						if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
							// A net.Pipe peer may already have been rejected and closed.
							require.ErrorIs(t, err, io.ErrClosedPipe)
						}
						_, err = peer.Read(make([]byte, 1))
						require.ErrorIs(t, err, io.EOF, "limit must still close the forwarded connection")
						closeQuietly(peer)
					}
					count := 0
					if mode.enabled {
						count = 3
					}
					recorder.require(t, reason, count)
				})
			}
		}
	}
}

func TestLimitRejectedCallbackDoesNotReportAuthorizationDenials(t *testing.T) {
	var recorder limitRejectionRecorder
	tcpHandler, unixHandler := &ForwardedTCPHandler{}, &ForwardedUnixHandler{}
	handlers := streamLocalRequestHandlers(unixHandler)
	handlers["tcpip-forward"] = tcpHandler.HandleSSHRequest
	srv := &Server{
		LimitRejectedCallback:  recorder.callback,
		RequestHandlers:        handlers,
		SessionRequestCallback: func(Session, string) (bool, error) { return false, nil },
		ReversePortForwardingCallback: func(Context, gossh.ConnMetadata, string, uint32) (bool, error) {
			return false, nil
		},
		ReverseUnixForwardingCallback: func(Context, gossh.ConnMetadata, string) (net.Listener, error) {
			return nil, ErrServerPermissionDenied
		},
	}
	first, client, cleanup := newTestSession(t, srv, nil)
	defer cleanup()
	require.Error(t, first.Shell())
	_, err := client.Listen("tcp", "127.0.0.1:0")
	require.Error(t, err)
	_, err = client.ListenUnix("/virtual/denied.sock")
	require.Error(t, err)
	recorder.require(t, 0, 0)
}

func TestLimitRejectedCallbackDisabledLimits(t *testing.T) {
	var recorder limitRejectionRecorder
	disabled := 0
	srv := &Server{
		LimitRejectedCallback: recorder.callback, MaxStartups: &MaxStartupsConfig{},
		MaxConnections: &disabled, MaxChannels: &disabled,
		MaxChannelsPerConnection: &disabled, MaxSessionsPerConnection: &disabled,
		MaxReverseForwards: &disabled, MaxReverseForwardsPerConnection: &disabled,
	}
	addr := startLimitTestServer(t, srv)
	for range 3 {
		client := dialLimitTestClient(t, addr)
		for range 3 {
			sess, err := client.NewSession()
			require.NoError(t, err)
			t.Cleanup(func() { closeQuietly(sess) })
		}
	}
	recorder.require(t, 0, 0)
}

func TestLimitRejectedCallbackAfterReservationRollback(t *testing.T) {
	for _, channels := range []bool{false, true} {
		t.Run(map[bool]string{false: "resources", true: "channels"}[channels], func(t *testing.T) {
			var globalActive, localActive atomic.Int64
			globalActive.Store(1)
			var recorder limitRejectionRecorder
			global := &resourceLimiter{
				limit: 1, active: &globalActive, reason: LimitRejectionMaxReverseForwards,
				onRejected: func(LimitRejectionReason) { t.Error("parent notified observer twice") },
			}
			local := &resourceLimiter{limit: 2, active: &localActive, parent: global}
			channel := &connectionChannelLimiter{limit: 2, global: global}
			onRejected := func(reason LimitRejectionReason) {
				require.Zero(t, localActive.Load())
				require.Zero(t, channel.active.Load())
				require.Equal(t, int64(1), globalActive.Load())
				recorder.record(reason)
			}
			local.onRejected, channel.onRejected = onRejected, onRejected
			if channels {
				global.reason = LimitRejectionMaxChannels
				require.False(t, channel.reserve())
			} else {
				require.False(t, local.reserve())
			}
			recorder.require(t, global.reason, 1)
		})
	}
}

func TestLimitRejectedCallbackConcurrentConnections(t *testing.T) {
	var recorder limitRejectionRecorder
	limit, unlimited := 1, 0
	srv := &Server{
		LimitRejectedCallback: recorder.callback, MaxStartups: &MaxStartupsConfig{},
		MaxSessionsPerConnection: &limit, MaxChannelsPerConnection: &unlimited, MaxChannels: &unlimited,
	}
	addr := startLimitTestServer(t, srv)
	var clients []*gossh.Client
	for range 8 {
		client := dialLimitTestClient(t, addr)
		sess, err := client.NewSession()
		require.NoError(t, err)
		t.Cleanup(func() { closeQuietly(sess) })
		clients = append(clients, client)
	}
	var workers sync.WaitGroup
	for _, client := range clients {
		workers.Go(func() {
			for range 20 {
				sess, err := client.NewSession()
				if err == nil {
					closeQuietly(sess)
					t.Error("session unexpectedly accepted")
				}
			}
		})
	}
	workers.Wait()
	recorder.require(t, LimitRejectionMaxSessionsPerConnection, 8*20)
}

func TestLimitRejectedCallbackConcurrentLimiters(t *testing.T) {
	for _, reason := range []LimitRejectionReason{
		LimitRejectionMaxConnections,
		LimitRejectionMaxChannels,
		LimitRejectionMaxChannelsPerConnection,
		LimitRejectionMaxReverseForwards,
		LimitRejectionMaxReverseForwardsPerConnection,
	} {
		t.Run(reason.String(), func(t *testing.T) {
			var recorder limitRejectionRecorder
			var active, globalActive atomic.Int64
			active.Store(1)
			globalActive.Store(1)
			global := &resourceLimiter{limit: 1, active: &globalActive, reason: reason}
			local := &resourceLimiter{limit: 1, active: &active, reason: reason, onRejected: recorder.record}
			channel := &connectionChannelLimiter{limit: 1, global: global, onRejected: recorder.record}
			channel.active.Store(1)
			reserve := local.reserve
			switch reason {
			case LimitRejectionMaxChannels:
				channel.limit = 128
				channel.active.Store(0)
				reserve = channel.reserve
			case LimitRejectionMaxChannelsPerConnection:
				reserve = channel.reserve
			case LimitRejectionMaxReverseForwards:
				local.limit = 128
				local.parent = global
				active.Store(0)
			}
			var workers sync.WaitGroup
			for range 16 {
				workers.Go(func() {
					for range 64 {
						if reserve() {
							t.Error("exhausted limiter unexpectedly reserved a slot")
						}
					}
				})
			}
			workers.Wait()
			recorder.require(t, reason, 16*64)
			require.Equal(t, int64(1), globalActive.Load())
			if reason == LimitRejectionMaxReverseForwards {
				require.Zero(t, active.Load())
			} else {
				require.Equal(t, int64(1), active.Load())
			}
			if reason == LimitRejectionMaxChannels {
				require.Zero(t, channel.active.Load())
			} else {
				require.Equal(t, int64(1), channel.active.Load())
			}
		})
	}
}

func TestLimitRejectedCallbackSharedLimits(t *testing.T) {
	for _, reason := range []LimitRejectionReason{LimitRejectionMaxChannels, LimitRejectionMaxReverseForwards} {
		t.Run(reason.String(), func(t *testing.T) {
			var recorder limitRejectionRecorder
			limit := 1
			handler := &ForwardedTCPHandler{}
			srv := &Server{
				LimitRejectedCallback: recorder.callback, MaxChannels: &limit, MaxReverseForwards: &limit,
				MaxChannelsPerConnection: &limit, MaxReverseForwardsPerConnection: &limit,
				ReversePortForwardingCallback: func(Context, gossh.ConnMetadata, string, uint32) (bool, error) {
					return true, nil
				},
				RequestHandlers: map[string]RequestHandler{"tcpip-forward": handler.HandleSSHRequest},
			}
			addr := startLimitTestServer(t, srv)
			first := dialLimitTestClient(t, addr)
			second := dialLimitTestClient(t, addr)
			open := func(client *gossh.Client) (io.Closer, error) {
				if reason == LimitRejectionMaxChannels {
					return client.NewSession()
				}
				return client.Listen("tcp", "127.0.0.1:0")
			}
			resource, err := open(first)
			require.NoError(t, err)
			t.Cleanup(func() { closeQuietly(resource) })
			_, err = open(second)
			require.Error(t, err)
			recorder.require(t, reason, 1)
			// The same Server's other Serve scope retains its own global capacity.
			independent := dialLimitTestClient(t, startLimitTestServer(t, srv))
			other, err := open(independent)
			require.NoError(t, err)
			t.Cleanup(func() { closeQuietly(other) })
			recorder.require(t, reason, 1)
		})
	}
}

func TestLimitRejectedCallbackErrorDispatch(t *testing.T) {
	callbackErr := errors.New("observer unavailable")
	for _, tc := range []struct {
		reason LimitRejectionReason
		scope  ErrorScope
	}{
		{LimitRejectionMaxStartups, ErrorScopeConnection},
		{LimitRejectionMaxConnections, ErrorScopeConnection},
		{LimitRejectionMaxChannels, ErrorScopeChannel},
		{LimitRejectionMaxChannelsPerConnection, ErrorScopeChannel},
		{LimitRejectionMaxSessionsPerConnection, ErrorScopeSession},
		{LimitRejectionMaxReverseForwards, ErrorScopeForwarding},
		{LimitRejectionMaxReverseForwardsPerConnection, ErrorScopeForwarding},
	} {
		t.Run(tc.reason.String(), func(t *testing.T) {
			var callbackCalls, errorCalls int
			var scope *serveContext
			var closeCalls atomic.Int64
			var savedRespond ErrorResponder
			srv := &Server{
				LimitRejectedCallback: func(reason LimitRejectionReason) error {
					callbackCalls++
					require.Equal(t, tc.reason, reason)
					// A nested location must not move this failure to an async
					// server-scope dispatch or change the reported operation.
					return locateError(ErrorScopeServer, ErrorOperationAccept, callbackErr)
				},
				ErrorHandler: func(ctx context.Context, es ErrorScope, operation ErrorOperation, err error, respond ErrorResponder, next ErrorHandler) (bool, error) {
					errorCalls++
					require.Equal(t, tc.scope, es)
					require.Equal(t, ErrorOperationHandle, operation)
					require.ErrorIs(t, err, callbackErr)
					if scope.mu.TryLock() {
						scope.mu.Unlock()
					} else {
						t.Error("callback error was dispatched under an internal lock")
					}
					savedRespond = respond
					require.ErrorIs(t, respond([]byte("must not be sent"), true), ErrErrorResponseUnsupported)
					require.ErrorIs(t, respond(nil, false), ErrErrorResponseAlreadySent)
					canContinue, nextErr := next(ctx, es, operation, err, respond, next)
					require.False(t, canContinue)
					require.NoError(t, nextErr)
					return false, errors.New("error handler also failed")
				},
			}
			ctx, cancel := newContext(srv)
			defer cancel()
			ctx.SetValue(contextKeyCloseConnection, func() { closeCalls.Add(1) })
			scope = newServeContext(srv, ctx, nil)
			scope.onLimitRejected(ctx, tc.reason)
			require.Equal(t, 1, callbackCalls, "callback must finish synchronously, once")
			require.Equal(t, 1, errorCalls, "error dispatch must finish synchronously, once")
			require.Zero(t, closeCalls.Load())
			require.NoError(t, ctx.Err())
			require.ErrorIs(t, savedRespond(nil, true), ErrErrorResponseExpired)
		})
	}
}

func TestLimitRejectedCallbackErrorHandlerPreservesSSHResponse(t *testing.T) {
	callbackErr, errorHandlerErr := errors.New("observation failed"), errors.New("handling failed")
	for _, tc := range []struct {
		channels, global, sessions int
		reason                     LimitRejectionReason
		scope                      ErrorScope
		message                    string
	}{
		{1, 1, 1, LimitRejectionMaxChannelsPerConnection, ErrorScopeChannel, "too many open channels"},
		{2, 1, 1, LimitRejectionMaxChannels, ErrorScopeChannel, "too many open channels"},
		{2, 2, 1, LimitRejectionMaxSessionsPerConnection, ErrorScopeSession, "too many open sessions"},
	} {
		t.Run(tc.reason.String(), func(t *testing.T) {
			recorder := limitRejectionRecorder{callbackErr: callbackErr}
			var errorCalls atomic.Int64
			srv := &Server{
				LimitRejectedCallback:    recorder.callback,
				MaxChannelsPerConnection: &tc.channels, MaxChannels: &tc.global, MaxSessionsPerConnection: &tc.sessions,
				Handler: func(sess Session) error {
					_, err := io.Copy(sess, sess)
					return err
				},
				ErrorHandler: func(ctx context.Context, scope ErrorScope, operation ErrorOperation, err error, respond ErrorResponder, next ErrorHandler) (bool, error) {
					if !errors.Is(err, callbackErr) {
						// Closing the echo session can independently fail its exit reply.
						return next(ctx, scope, operation, err, respond, next)
					}
					errorCalls.Add(1)
					if scope != tc.scope || operation != ErrorOperationHandle {
						t.Errorf("unexpected callback error: %v (%v/%v)", err, scope, operation)
					}
					if responseErr := respond([]byte("must not replace the limit reply"), true); !errors.Is(responseErr, ErrErrorResponseUnsupported) {
						t.Errorf("unexpected response error: %v", responseErr)
					}
					return false, errorHandlerErr
				},
			}
			first, client, cleanup := newTestSession(t, srv, nil)
			defer cleanup()
			for range 3 {
				_, err := client.NewSession()
				var openErr *gossh.OpenChannelError
				require.ErrorAs(t, err, &openErr)
				require.Equal(t, gossh.ResourceShortage, openErr.Reason)
				require.Equal(t, tc.message, openErr.Message)
			}
			recorder.require(t, tc.reason, 3)
			require.Equal(t, int64(3), errorCalls.Load())
			stdin, stdout := startEchoClientSession(t, first)
			requireEcho(t, stdin, stdout, "connection survives callback and error-handler failures")
		})
	}
}

func TestLimitRejectedCallbackSuccessDoesNotDispatchError(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		var recorder limitRejectionRecorder
		srv := &Server{
			ErrorHandler: func(context.Context, ErrorScope, ErrorOperation, error, ErrorResponder, ErrorHandler) (bool, error) {
				t.Error("successful or nil callback must not invoke ErrorHandler")
				return false, nil
			},
		}
		if enabled {
			srv.LimitRejectedCallback = recorder.callback
		}
		scope := newServeContext(srv, context.Background(), nil)
		scope.onLimitRejected(scope.parent, LimitRejectionMaxStartups)
		count := 0
		if enabled {
			count = 1
		}
		recorder.require(t, LimitRejectionMaxStartups, count)
	}
}

func TestLimitRejectedCallbackConcurrentErrorDispatch(t *testing.T) {
	callbackErr := errors.New("observation failed")
	recorder := limitRejectionRecorder{callbackErr: callbackErr}
	var errorCalls atomic.Int64
	srv := &Server{
		LimitRejectedCallback: recorder.callback,
		ErrorHandler: func(_ context.Context, scope ErrorScope, operation ErrorOperation, err error, _ ErrorResponder, _ ErrorHandler) (bool, error) {
			errorCalls.Add(1)
			if !errors.Is(err, callbackErr) || scope != ErrorScopeForwarding || operation != ErrorOperationHandle {
				t.Errorf("unexpected callback error: %v (%v/%v)", err, scope, operation)
			}
			return false, nil
		},
	}
	scope := newServeContext(srv, context.Background(), nil)
	var workers sync.WaitGroup
	for range 16 {
		workers.Go(func() {
			for range 64 {
				scope.onLimitRejected(scope.parent, LimitRejectionMaxReverseForwards)
			}
		})
	}
	workers.Wait()
	recorder.require(t, LimitRejectionMaxReverseForwards, 16*64)
	require.Equal(t, int64(16*64), errorCalls.Load())
}
