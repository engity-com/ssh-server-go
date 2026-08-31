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
	d := localForwardChannelData{}
	if err := gossh.Unmarshal(newChan.ExtraData(), &d); err != nil {
		_ = newChan.Reject(gossh.ConnectionFailed, "error parsing forward data: "+err.Error())
		return
	}

	if srv.LocalPortForwardingCallback == nil || !srv.LocalPortForwardingCallback(ctx, d.DestAddr, d.DestPort) {
		_ = newChan.Reject(gossh.Prohibited, "port forwarding is disabled")
		return
	}

	dest := net.JoinHostPort(d.DestAddr, strconv.FormatInt(int64(d.DestPort), 10))

	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", dest)
	if err != nil {
		_ = newChan.Reject(gossh.ConnectionFailed, err.Error())
		return
	}

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

	forwards map[string]net.Listener
	sync.Mutex
}

func (h *ForwardedTCPHandler) HandleSSHRequest(ctx Context, srv *Server, req *gossh.Request) (bool, []byte) {
	h.Lock()
	if h.forwards == nil {
		h.forwards = make(map[string]net.Listener)
	}
	h.Unlock()
	conn := ctx.Value(ContextKeyConn).(*gossh.ServerConn)
	switch req.Type {
	case "tcpip-forward":
		var reqPayload remoteForwardRequest
		if err := gossh.Unmarshal(req.Payload, &reqPayload); err != nil {
			h.loggerOfConnection(conn).
				WithError(err).
				Warn("'tcpip-forward': cannot parse request")
			return false, []byte{}
		}
		if srv.ReversePortForwardingCallback == nil || !srv.ReversePortForwardingCallback(ctx, reqPayload.BindAddr, reqPayload.BindPort) {
			return false, []byte("port forwarding is disabled")
		}
		addr := net.JoinHostPort(reqPayload.BindAddr, strconv.Itoa(int(reqPayload.BindPort)))
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			h.loggerOfConnection(conn).
				WithError(err).
				With("bind.addr", reqPayload.BindAddr).
				With("bind.port", reqPayload.BindPort).
				Warn("'tcpip-forward': cannot listen to requested bind address/port")
			return false, []byte{}
		}
		_, destPortStr, _ := net.SplitHostPort(ln.Addr().String())
		destPort, _ := strconv.Atoi(destPortStr)
		h.Lock()
		h.forwards[addr] = ln
		h.Unlock()
		go func() {
			<-ctx.Done()
			h.Lock()
			ln, ok := h.forwards[addr]
			h.Unlock()
			if ok {
				closeQuietly(ln)
			}
		}()
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					// TODO: log accept failure
					break
				}
				originAddr, orignPortStr, _ := net.SplitHostPort(c.RemoteAddr().String())
				originPort, _ := strconv.Atoi(orignPortStr)
				payload := gossh.Marshal(&remoteForwardChannelData{
					DestAddr:   reqPayload.BindAddr,
					DestPort:   uint32(destPort),
					OriginAddr: originAddr,
					OriginPort: uint32(originPort),
				})
				go func(c net.Conn, payload []byte) {
					defer closeQuietly(c)
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
				}(c, payload)
			}
			h.Lock()
			delete(h.forwards, addr)
			h.Unlock()
		}()
		return true, gossh.Marshal(&remoteForwardSuccess{uint32(destPort)})

	case "cancel-tcpip-forward":
		var reqPayload remoteForwardCancelRequest
		if err := gossh.Unmarshal(req.Payload, &reqPayload); err != nil {
			h.loggerOfConnection(conn).
				WithError(err).
				Warn("'cancel-tcpip-forward': cannot parse payload channel")
			return false, []byte{}
		}
		addr := net.JoinHostPort(reqPayload.BindAddr, strconv.Itoa(int(reqPayload.BindPort)))
		h.Lock()
		ln, ok := h.forwards[addr]
		h.Unlock()
		if ok {
			closeQuietly(ln)
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
