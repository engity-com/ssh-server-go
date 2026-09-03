package ssh

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/echocat/slf4g"
	"github.com/echocat/slf4g/names"
	gossh "golang.org/x/crypto/ssh"
)

const (
	forwardedTCPChannelType             = "forwarded-tcpip"
	forwardedChannelRegistrationTimeout = time.Second
)

// direct-tcpip data struct as specified in RFC4254, Section 7.2
type localForwardChannelData struct {
	DestAddr string
	DestPort uint32

	OriginAddr string
	OriginPort uint32
}

// DirectTCPIPHandler can be enabled by adding it to the server's
// ChannelHandlers under direct-tcpip.
func DirectTCPIPHandler(srv *Server, sshConn *gossh.ServerConn, newChan gossh.NewChannel, ctx Context) error {
	if newChan == nil {
		return nil
	}
	if srv == nil || sshConn == nil || ctx == nil {
		_ = newChan.Reject(gossh.ConnectionFailed, "missing server connection context")
		return nil
	}
	d := localForwardChannelData{}
	if err := gossh.Unmarshal(newChan.ExtraData(), &d); err != nil {
		return locateError(ErrorScopeChannel, ErrorOperationParse, fmt.Errorf("parse direct-tcpip channel data: %w", err))
	}

	if srv.LocalPortForwardingCallback == nil {
		_ = newChan.Reject(gossh.Prohibited, "port forwarding is disabled")
		return nil
	}
	allowed, err := srv.LocalPortForwardingCallback(ctx, sshConn, d.DestAddr, d.DestPort)
	if err != nil {
		return locateError(ErrorScopeForwarding, ErrorOperationHandle, fmt.Errorf("authorize direct-tcpip destination %s:%d: %w", d.DestAddr, d.DestPort, err))
	}
	if !allowed {
		_ = newChan.Reject(gossh.Prohibited, "port forwarding is disabled")
		return nil
	}

	dest := net.JoinHostPort(d.DestAddr, strconv.FormatInt(int64(d.DestPort), 10))

	finishAcquisition, ok := beginConnectionResourceAcquisition(ctx)
	if !ok {
		_ = newChan.Reject(gossh.ConnectionFailed, "connection is closing")
		return nil
	}
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", dest)
	if err != nil {
		finishAcquisition(nil)
		return locateError(ErrorScopeForwarding, ErrorOperationDial, fmt.Errorf("dial direct-tcpip destination %s: %w", dest, err))
	}
	unregisterConn := finishAcquisition(func() { closeQuietly(conn) })
	defer unregisterConn()

	ch, reqs, err := newChan.Accept()
	if err != nil {
		closeQuietly(conn)
		return locateError(ErrorScopeChannel, ErrorOperationAccept, fmt.Errorf("accept direct-tcpip channel: %w", err))
	}
	go gossh.DiscardRequests(reqs)
	defer closeQuietly(ch)
	defer closeQuietly(conn)
	if err := FullDuplexCopy(ctx, conn, ch, nil); err != nil {
		return locateError(ErrorScopeForwarding, ErrorOperationForward, fmt.Errorf("forward direct-tcpip connection: %w", err))
	}
	return nil
}

type remoteForwardRequest struct {
	BindAddr string
	BindPort uint32
}

type remoteForwardSuccess struct {
	BindPort uint32
}

type remoteForwardCancelRequest struct {
	BindAddr string
	BindPort uint32
}

type remoteForwardChannelData struct {
	DestAddr   string
	DestPort   uint32
	OriginAddr string
	OriginPort uint32
}

// ForwardedTCPHandler can be enabled by creating a ForwardedTCPHandler and
// adding the HandleSSHRequest callback to the server's RequestHandlers under
// tcpip-forward and cancel-tcpip-forward.
type ForwardedTCPHandler struct {
	Logger log.Logger

	forwards map[forwardKey]*forward
	sync.Mutex
}

type forwardKey struct {
	conn *gossh.ServerConn
	addr string
}

type forward struct {
	listener net.Listener
	done     chan struct{}
	close    func()
	pending  sync.WaitGroup
	mu       sync.Mutex
	closing  bool
}

func newForward(listener net.Listener, onClose func()) *forward {
	f := &forward{listener: listener, done: make(chan struct{})}
	f.close = sync.OnceFunc(func() {
		f.mu.Lock()
		f.closing = true
		f.mu.Unlock()
		close(f.done)
		closeQuietly(f.listener)
		if onClose != nil {
			onClose()
		}
	})
	return f
}

func (f *forward) beginOpen() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closing {
		return false
	}
	f.pending.Add(1)
	return true
}

func (f *forward) endOpen() {
	f.pending.Done()
}

func (f *forward) waitForPendingOpens() {
	f.pending.Wait()
}

func (h *ForwardedTCPHandler) HandleSSHRequest(response RequestResponseWriter, request *Request) error {
	if h == nil || response == nil || request == nil {
		return errors.New("ssh: missing TCP forwarding request handler state")
	}
	ctx := request.Context()
	srv := request.Server()
	if ctx == nil || srv == nil {
		return response.Reject([]byte("missing server connection context"))
	}
	conn, ok := ctx.Value(ContextKeyConn).(*gossh.ServerConn)
	if !ok || conn == nil {
		return response.Reject([]byte("missing server connection context"))
	}
	h.Lock()
	if h.forwards == nil {
		h.forwards = make(map[forwardKey]*forward)
	}
	h.Unlock()
	errorHandler := errorHandlerFromContext(ctx, srv)
	switch request.Type {
	case "tcpip-forward":
		var reqPayload remoteForwardRequest
		if err := gossh.Unmarshal(request.Payload, &reqPayload); err != nil {
			return locateError(ErrorScopeRequest, ErrorOperationParse, fmt.Errorf("parse tcpip-forward request: %w", err))
		}
		if srv.ReversePortForwardingCallback == nil {
			return response.Reject([]byte("port forwarding is disabled"))
		}
		allowed, err := srv.ReversePortForwardingCallback(ctx, conn, reqPayload.BindAddr, reqPayload.BindPort)
		if err != nil {
			return locateError(ErrorScopeForwarding, ErrorOperationHandle, fmt.Errorf("authorize tcpip-forward on %s:%d: %w", reqPayload.BindAddr, reqPayload.BindPort, err))
		}
		if !allowed {
			return response.Reject([]byte("port forwarding is disabled"))
		}
		forwardLimiter, _ := ctx.Value(contextKeyForwardLimiter).(*resourceLimiter)
		if !forwardLimiter.reserve() {
			return response.Reject([]byte("too many reverse port forwards"))
		}
		addr := net.JoinHostPort(reqPayload.BindAddr, strconv.Itoa(int(reqPayload.BindPort)))
		finishAcquisition, ok := beginConnectionResourceAcquisition(ctx)
		if !ok {
			forwardLimiter.release()
			return response.Reject(nil)
		}
		ln, err := new(net.ListenConfig).Listen(ctx, "tcp", addr)
		if err != nil {
			finishAcquisition(nil)
			forwardLimiter.release()
			return locateError(ErrorScopeForwarding, ErrorOperationListen, fmt.Errorf("listen for tcpip-forward on %s: %w", addr, err))
		}
		_, destPortStr, _ := net.SplitHostPort(ln.Addr().String())
		destPort, _ := strconv.ParseUint(destPortStr, 10, 16)
		key := forwardKey{conn: conn, addr: net.JoinHostPort(reqPayload.BindAddr, destPortStr)}
		f := newForward(ln, forwardLimiter.release)
		unregisterForward := finishAcquisition(f.close)
		h.Lock()
		h.forwards[key] = f
		h.Unlock()
		responseState := request.response
		started := startConnectionWorker(ctx, func() {
			defer unregisterForward()
			defer func() {
				f.close()
				f.waitForPendingOpens()
				h.Lock()
				if h.forwards[key] == f {
					delete(h.forwards, key)
				}
				h.Unlock()
			}()
			go func() {
				select {
				case <-ctx.Done():
					f.close()
				case <-f.done:
				}
			}()
			accepted, responseErr := responseState.wait(ctx)
			if responseErr != nil || !accepted {
				return
			}
			limiter, _ := ctx.Value(contextKeyChannelLimiter).(*connectionChannelLimiter)
			var acceptDelay time.Duration
			for {
				finishAcquisition, ok := beginConnectionResourceAcquisition(ctx)
				if !ok {
					break
				}
				c, err := ln.Accept()
				if err != nil {
					finishAcquisition(nil)
					if ctx.Err() == nil && !isClosedError(err) {
						if dispatchErrorOrEscalate(ctx, h.loggerOfConnection(conn), errorHandler, ErrorScopeForwarding, ErrorOperationAccept, err, nil, defaultLogAndFailErrorAction) {
							if !waitForRetry(ctx, &acceptDelay) {
								break
							}
							continue
						}
					}
					break
				}
				acceptDelay = 0
				unregisterConn := finishAcquisition(func() { closeQuietly(c) })
				originAddr, orignPortStr, _ := net.SplitHostPort(c.RemoteAddr().String())
				originPort, _ := strconv.ParseUint(orignPortStr, 10, 16)
				payload := gossh.Marshal(&remoteForwardChannelData{
					DestAddr:   reqPayload.BindAddr,
					DestPort:   uint32(destPort), // #nosec G115 -- parsed above with a 16-bit bound
					OriginAddr: originAddr,
					OriginPort: uint32(originPort),
				})
				if !limiter.reserve() {
					unregisterConn()
					closeQuietly(c)
					h.loggerOfConnection(conn).
						Warn("'tcpip-forward': too many open SSH channels; rejecting connection")
					continue
				}
				if !f.beginOpen() {
					unregisterConn()
					limiter.release()
					closeQuietly(c)
					return
				}
				if !startConnectionWorker(ctx, func() {
					defer unregisterConn()
					defer closeQuietly(c)
					defer limiter.release()
					var ch gossh.Channel
					var reqs <-chan *gossh.Request
					var err error
					func() {
						defer f.endOpen()
						ch, reqs, err = openForwardedChannel(ctx, f.done, conn, forwardedTCPChannelType, payload)
					}()
					if err != nil {
						select {
						case <-f.done:
							return
						default:
						}
						if !dispatchErrorOrEscalate(ctx, h.loggerOfConnection(conn), errorHandler, ErrorScopeForwarding, ErrorOperationOpenChannel, err, nil, defaultLogAndFailErrorAction) {
							f.close()
						}
						return
					}
					defer closeQuietly(ch)
					go gossh.DiscardRequests(reqs)
					if err := FullDuplexCopy(ctx, c, ch, nil); err != nil {
						if !dispatchErrorOrEscalate(ctx, h.loggerOfConnection(conn), errorHandler, ErrorScopeForwarding, ErrorOperationForward, err, nil, defaultLogAndFailErrorAction) {
							f.close()
						}
					}
				}) {
					unregisterConn()
					f.endOpen()
					limiter.release()
					closeQuietly(c)
				}
			}
		})
		if !started {
			unregisterForward()
			h.Lock()
			if h.forwards[key] == f {
				delete(h.forwards, key)
			}
			h.Unlock()
			f.close()
			return response.Reject(nil)
		}
		return response.Accept(gossh.Marshal(&remoteForwardSuccess{uint32(destPort)}))

	case "cancel-tcpip-forward":
		var reqPayload remoteForwardCancelRequest
		if err := gossh.Unmarshal(request.Payload, &reqPayload); err != nil {
			return locateError(ErrorScopeRequest, ErrorOperationParse, fmt.Errorf("parse cancel-tcpip-forward request: %w", err))
		}
		key := forwardKey{conn: conn, addr: net.JoinHostPort(reqPayload.BindAddr, strconv.Itoa(int(reqPayload.BindPort)))}
		h.Lock()
		f, ok := h.forwards[key]
		h.Unlock()
		if ok {
			f.close()
			return response.Accept(nil)
		}
		return response.Reject(nil)
	default:
		return response.Reject(nil)
	}
}

func openForwardedChannel(ctx context.Context, forwardDone <-chan struct{}, conn gossh.Conn, channelType string, payload []byte) (gossh.Channel, <-chan *gossh.Request, error) {
	type result struct {
		channel  gossh.Channel
		requests <-chan *gossh.Request
		err      error
	}
	timeout := time.NewTimer(forwardedChannelRegistrationTimeout)
	defer timeout.Stop()
	delay := time.Millisecond
	for {
		select {
		case <-ctx.Done():
			return nil, nil, context.Cause(ctx)
		case <-forwardDone:
			return nil, nil, net.ErrClosed
		default:
		}
		opened := make(chan result, 1)
		go func() {
			channel, requests, err := conn.OpenChannel(channelType, payload)
			opened <- result{channel: channel, requests: requests, err: err}
		}()
		var openedResult result
		select {
		case openedResult = <-opened:
		case <-ctx.Done():
			closeQuietly(conn)
			return nil, nil, context.Cause(ctx)
		case <-forwardDone:
			select {
			case openedResult = <-opened:
				if openedResult.err == nil {
					return openedResult.channel, openedResult.requests, nil
				}
				return nil, nil, net.ErrClosed
			case <-ctx.Done():
				closeQuietly(conn)
				return nil, nil, context.Cause(ctx)
			case <-timeout.C:
				closeQuietly(conn)
				return nil, nil, net.ErrClosed
			}
		case <-timeout.C:
			closeQuietly(conn)
			return nil, nil, fmt.Errorf("open %s channel: %w", channelType, context.DeadlineExceeded)
		}
		channel, requests, err := openedResult.channel, openedResult.requests, openedResult.err
		if !isForwardRegistrationRace(err) {
			return channel, requests, err
		}
		retry := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			retry.Stop()
			return nil, nil, context.Cause(ctx)
		case <-forwardDone:
			retry.Stop()
			return nil, nil, net.ErrClosed
		case <-timeout.C:
			retry.Stop()
			return nil, nil, err
		case <-retry.C:
		}
		if delay < 50*time.Millisecond {
			delay *= 2
		}
	}
}

func isForwardRegistrationRace(err error) bool {
	var openErr *gossh.OpenChannelError
	return errors.As(err, &openErr) && openErr.Reason == gossh.Prohibited && openErr.Message == "no forward for address"
}

func (h *ForwardedTCPHandler) logger() log.Logger {
	if v := h.Logger; v != nil {
		return v
	}
	return defaultForwardedTCPHandlerLoggerGetter()
}

func (h *ForwardedTCPHandler) loggerOfConnection(conn *gossh.ServerConn) log.Logger {
	return enrichLoggerForServerConnection(h.logger(), conn)
}

var defaultForwardedTCPHandlerLoggerGetter = sync.OnceValue[log.Logger](func() log.Logger {
	return log.GetLogger(names.CurrentPackageLoggerNameGenerator(0) + ".tcpForward")
})
