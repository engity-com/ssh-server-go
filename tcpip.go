package ssh

import (
	"net"
	"strconv"
	"sync"

	"github.com/echocat/slf4g"
	"github.com/echocat/slf4g/names"
	gossh "golang.org/x/crypto/ssh"
)

const (
	forwardedTCPChannelType = "forwarded-tcpip"
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
func DirectTCPIPHandler(srv *Server, sshConn *gossh.ServerConn, newChan gossh.NewChannel, ctx Context) {
	if newChan == nil {
		return
	}
	if srv == nil || sshConn == nil || ctx == nil {
		_ = newChan.Reject(gossh.ConnectionFailed, "missing server connection context")
		return
	}
	settings := serverSettingsFromContext(ctx, srv)
	d := localForwardChannelData{}
	if err := gossh.Unmarshal(newChan.ExtraData(), &d); err != nil {
		_ = newChan.Reject(gossh.ConnectionFailed, "error parsing forward data: "+err.Error())
		return
	}

	if settings.localPortForwardingCallback == nil || !settings.localPortForwardingCallback(ctx, d.DestAddr, d.DestPort) {
		_ = newChan.Reject(gossh.Prohibited, "port forwarding is disabled")
		return
	}

	dest := net.JoinHostPort(d.DestAddr, strconv.FormatInt(int64(d.DestPort), 10))

	finishAcquisition, ok := beginConnectionResourceAcquisition(ctx)
	if !ok {
		_ = newChan.Reject(gossh.ConnectionFailed, "connection is closing")
		return
	}
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", dest)
	if err != nil {
		finishAcquisition(nil)
		enrichLoggerForServerConnection(srv.logger(), sshConn).
			WithError(err).
			With("tcp.destination", dest).
			Warn("'direct-tcpip': failed to connect to destination")
		_ = newChan.Reject(gossh.ConnectionFailed, "connection failed")
		return
	}
	unregisterConn := finishAcquisition(func() { closeQuietly(conn) })
	defer unregisterConn()

	ch, reqs, err := newChan.Accept()
	if err != nil {
		closeQuietly(conn)
		return
	}
	go gossh.DiscardRequests(reqs)
	defer closeQuietly(ch)
	defer closeQuietly(conn)
	if err := FullDuplexCopy(ctx, conn, ch, nil); err != nil {
		enrichLoggerForServerConnection(srv.logger(), sshConn).
			WithError(err).
			With("tcp.remote", conn.RemoteAddr()).
			With("tcp.local", conn.LocalAddr()).
			Warn("'direct-tcpip': failed to forward connection")
	}
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

func (h *ForwardedTCPHandler) HandleSSHRequest(ctx Context, srv *Server, req *gossh.Request) (bool, []byte) {
	if h == nil || ctx == nil || srv == nil || req == nil {
		return false, []byte("missing server connection context")
	}
	conn, ok := ctx.Value(ContextKeyConn).(*gossh.ServerConn)
	if !ok || conn == nil {
		return false, []byte("missing server connection context")
	}
	h.Lock()
	if h.forwards == nil {
		h.forwards = make(map[forwardKey]*forward)
	}
	h.Unlock()
	settings := serverSettingsFromContext(ctx, srv)
	switch req.Type {
	case "tcpip-forward":
		var reqPayload remoteForwardRequest
		if err := gossh.Unmarshal(req.Payload, &reqPayload); err != nil {
			h.loggerOfConnection(conn).
				WithError(err).
				Warn("'tcpip-forward': cannot parse request")
			return false, []byte{}
		}
		if settings.reversePortForwardingCallback == nil || !settings.reversePortForwardingCallback(ctx, reqPayload.BindAddr, reqPayload.BindPort) {
			return false, []byte("port forwarding is disabled")
		}
		forwardLimiter, _ := ctx.Value(contextKeyForwardLimiter).(*resourceLimiter)
		if !forwardLimiter.reserve() {
			return false, []byte("too many reverse port forwards")
		}
		addr := net.JoinHostPort(reqPayload.BindAddr, strconv.Itoa(int(reqPayload.BindPort)))
		finishAcquisition, ok := beginConnectionResourceAcquisition(ctx)
		if !ok {
			forwardLimiter.release()
			return false, []byte{}
		}
		ln, err := new(net.ListenConfig).Listen(ctx, "tcp", addr)
		if err != nil {
			finishAcquisition(nil)
			forwardLimiter.release()
			h.loggerOfConnection(conn).
				WithError(err).
				With("bind.addr", reqPayload.BindAddr).
				With("bind.port", reqPayload.BindPort).
				Warn("'tcpip-forward': cannot listen to requested bind address/port")
			return false, []byte{}
		}
		_, destPortStr, _ := net.SplitHostPort(ln.Addr().String())
		destPort, _ := strconv.ParseUint(destPortStr, 10, 16)
		key := forwardKey{conn: conn, addr: net.JoinHostPort(reqPayload.BindAddr, destPortStr)}
		f := newForward(ln, forwardLimiter.release)
		unregisterForward := finishAcquisition(f.close)
		h.Lock()
		h.forwards[key] = f
		h.Unlock()
		started := startConnectionWorker(ctx, func() {
			defer unregisterForward()
			go func() {
				select {
				case <-ctx.Done():
					f.close()
				case <-f.done:
				}
			}()
			limiter, _ := ctx.Value(contextKeyChannelLimiter).(*connectionChannelLimiter)
			for {
				finishAcquisition, ok := beginConnectionResourceAcquisition(ctx)
				if !ok {
					break
				}
				c, err := ln.Accept()
				if err != nil {
					finishAcquisition(nil)
					// TODO: log accept failure
					break
				}
				unregisterConn := finishAcquisition(func() { closeQuietly(c) })
				originAddr, orignPortStr, _ := net.SplitHostPort(c.RemoteAddr().String())
				originPort, _ := strconv.ParseUint(orignPortStr, 10, 16)
				payload := gossh.Marshal(&remoteForwardChannelData{
					DestAddr:   reqPayload.BindAddr,
					DestPort:   uint32(destPort),
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
				if !startConnectionWorker(ctx, func() {
					defer unregisterConn()
					defer closeQuietly(c)
					defer limiter.release()
					ch, reqs, err := conn.OpenChannel(forwardedTCPChannelType, payload)
					if err != nil {
						h.loggerOfConnection(conn).
							WithError(err).
							With("tcp.remote", c.RemoteAddr()).
							With("tcp.local", c.LocalAddr()).
							Error("'tcpip-forward': cannot open channel of accepted connection, will close connection now...")
						return
					}
					defer closeQuietly(ch)
					go gossh.DiscardRequests(reqs)
					if err := FullDuplexCopy(ctx, c, ch, nil); err != nil {
						h.loggerOfConnection(conn).
							WithError(err).
							With("tcp.remote", c.RemoteAddr()).
							With("tcp.local", c.LocalAddr()).
							Warn("'tcpip-forward': failed to forward connection")
					}
				}) {
					unregisterConn()
					limiter.release()
					closeQuietly(c)
				}
			}
			h.Lock()
			if h.forwards[key] == f {
				delete(h.forwards, key)
			}
			h.Unlock()
			f.close()
		})
		if !started {
			unregisterForward()
			h.Lock()
			if h.forwards[key] == f {
				delete(h.forwards, key)
			}
			h.Unlock()
			f.close()
			return false, []byte{}
		}
		return true, gossh.Marshal(&remoteForwardSuccess{uint32(destPort)})

	case "cancel-tcpip-forward":
		var reqPayload remoteForwardCancelRequest
		if err := gossh.Unmarshal(req.Payload, &reqPayload); err != nil {
			h.loggerOfConnection(conn).
				WithError(err).
				Warn("'cancel-tcpip-forward': cannot parse payload channel")
			return false, []byte{}
		}
		key := forwardKey{conn: conn, addr: net.JoinHostPort(reqPayload.BindAddr, strconv.Itoa(int(reqPayload.BindPort)))}
		h.Lock()
		f, ok := h.forwards[key]
		if ok {
			delete(h.forwards, key)
		}
		h.Unlock()
		if ok {
			f.close()
		}
		return true, nil
	default:
		return false, nil
	}
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
