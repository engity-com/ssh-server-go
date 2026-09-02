package ssh

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/echocat/slf4g"
	"github.com/echocat/slf4g/names"
	gossh "golang.org/x/crypto/ssh"
)

const forwardedUnixChannelType = "forwarded-streamlocal@openssh.com"

type directStreamLocalChannelData struct {
	SocketPath string
	Reserved1  string
	Reserved2  uint32
}

// DirectStreamLocalHandler handles client-to-server Unix socket forwarding. It
// can be enabled under the direct-streamlocal@openssh.com channel type. The
// configured LocalUnixForwardingCallback owns path authorization and dialing.
func DirectStreamLocalHandler(srv *Server, sshConn *gossh.ServerConn, newChan gossh.NewChannel, ctx Context) {
	if newChan == nil {
		return
	}
	if srv == nil || sshConn == nil || ctx == nil {
		_ = newChan.Reject(gossh.ConnectionFailed, "missing server connection context")
		return
	}
	settings := serverSettingsFromContext(ctx, srv)
	var data directStreamLocalChannelData
	if err := gossh.Unmarshal(newChan.ExtraData(), &data); err != nil {
		enrichLoggerForServerConnection(srv.logger(), sshConn).
			WithError(err).
			Warn("'direct-streamlocal@openssh.com': cannot parse channel data")
		_ = newChan.Reject(gossh.ConnectionFailed, "invalid streamlocal channel data")
		return
	}
	if settings.localUnixForwardingCallback == nil {
		_ = newChan.Reject(gossh.Prohibited, "unix forwarding is disabled")
		return
	}

	conn, err := settings.localUnixForwardingCallback(ctx, data.SocketPath)
	if err != nil {
		if errors.Is(err, ErrServerPermissionDenied) {
			_ = newChan.Reject(gossh.Prohibited, "unix forwarding is denied")
			return
		}
		logger := enrichLoggerForServerConnection(srv.logger(), sshConn).
			With("streamlocal.path", data.SocketPath)
		if err != nil {
			logger = logger.WithError(err)
		}
		logger.Warn("'direct-streamlocal@openssh.com': failed to connect to destination")
		_ = newChan.Reject(gossh.ConnectionFailed, "connection failed")
		return
	}
	if conn == nil {
		enrichLoggerForServerConnection(srv.logger(), sshConn).
			With("streamlocal.path", data.SocketPath).
			Warn("'direct-streamlocal@openssh.com': callback returned no connection")
		_ = newChan.Reject(gossh.ConnectionFailed, "connection failed")
		return
	}

	channel, reqs, err := newChan.Accept()
	if err != nil {
		closeQuietly(conn)
		return
	}
	go gossh.DiscardRequests(reqs)
	defer closeQuietly(channel)
	defer closeQuietly(conn)
	if err := FullDuplexCopy(ctx, conn, channel, nil); err != nil {
		enrichLoggerForServerConnection(srv.logger(), sshConn).
			WithError(err).
			With("streamlocal.path", data.SocketPath).
			Warn("'direct-streamlocal@openssh.com': failed to forward connection")
	}
}

type remoteUnixForwardRequest struct {
	SocketPath string
}

type remoteUnixForwardChannelData struct {
	SocketPath string
	Reserved   string
}

// ForwardedUnixHandler handles server-to-client Unix socket forwarding. Add
// HandleSSHRequest under streamlocal-forward@openssh.com and
// cancel-streamlocal-forward@openssh.com. Forwarding remains disabled unless a
// ReverseUnixForwardingCallback is configured.
type ForwardedUnixHandler struct {
	Logger log.Logger

	forwards map[forwardKey]*forward
	sync.Mutex
}

func (h *ForwardedUnixHandler) HandleSSHRequest(ctx Context, srv *Server, req *gossh.Request) (bool, []byte) {
	if h == nil || ctx == nil || srv == nil || req == nil {
		return false, []byte("missing server connection context")
	}
	conn, ok := ctx.Value(ContextKeyConn).(*gossh.ServerConn)
	if !ok || conn == nil {
		return false, []byte("missing server connection context")
	}
	settings := serverSettingsFromContext(ctx, srv)

	switch req.Type {
	case "streamlocal-forward@openssh.com":
		var payload remoteUnixForwardRequest
		if err := gossh.Unmarshal(req.Payload, &payload); err != nil {
			h.loggerOfConnection(conn).WithError(err).
				Warn("'streamlocal-forward@openssh.com': cannot parse request")
			return false, nil
		}
		if settings.reverseUnixForwardingCallback == nil {
			return false, nil
		}
		key := forwardKey{conn: conn, addr: payload.SocketPath}
		h.Lock()
		_, duplicate := h.forwards[key]
		h.Unlock()
		if duplicate {
			return false, nil
		}
		forwardLimiter, _ := ctx.Value(contextKeyForwardLimiter).(*resourceLimiter)
		if !forwardLimiter.reserve() {
			return false, nil
		}
		listener, err := settings.reverseUnixForwardingCallback(ctx, payload.SocketPath)
		if err != nil {
			forwardLimiter.release()
			if !errors.Is(err, ErrServerPermissionDenied) {
				logger := h.loggerOfConnection(conn).With("streamlocal.path", payload.SocketPath)
				if err != nil {
					logger = logger.WithError(err)
				}
				logger.Warn("'streamlocal-forward@openssh.com': failed to create listener")
			}
			return false, nil
		}
		if listener == nil {
			forwardLimiter.release()
			h.loggerOfConnection(conn).With("streamlocal.path", payload.SocketPath).
				Warn("'streamlocal-forward@openssh.com': callback returned no listener")
			return false, nil
		}

		f := newForward(listener, forwardLimiter.release)
		h.Lock()
		if h.forwards == nil {
			h.forwards = make(map[forwardKey]*forward)
		}
		if _, duplicate = h.forwards[key]; duplicate {
			h.Unlock()
			f.close()
			return false, nil
		}
		h.forwards[key] = f
		h.Unlock()
		reply, _ := ctx.Value(contextKeyRequestReply).(*requestReply)

		started := startConnectionWorker(ctx, func() {
			stopCloseOnCancel := context.AfterFunc(ctx, f.close)
			defer stopCloseOnCancel()
			defer func() {
				f.close()
				f.waitForPendingOpens()
				h.removeForward(key, f)
			}()
			if reply != nil {
				select {
				case <-reply.done:
					if reply.err != nil {
						return
					}
				case <-ctx.Done():
					return
				}
			}
			h.forwardConnections(ctx, conn, payload.SocketPath, f)
		})
		if !started {
			h.removeForward(key, f)
			f.close()
			return false, nil
		}
		return true, nil

	case "cancel-streamlocal-forward@openssh.com":
		var payload remoteUnixForwardRequest
		if err := gossh.Unmarshal(req.Payload, &payload); err != nil {
			h.loggerOfConnection(conn).WithError(err).
				Warn("'cancel-streamlocal-forward@openssh.com': cannot parse request")
			return false, nil
		}
		key := forwardKey{conn: conn, addr: payload.SocketPath}
		h.Lock()
		forward, ok := h.forwards[key]
		h.Unlock()
		if ok {
			forward.close()
		}
		return ok, nil

	default:
		return false, nil
	}
}

func (h *ForwardedUnixHandler) forwardConnections(ctx Context, conn *gossh.ServerConn, socketPath string, f *forward) {
	limiter, _ := ctx.Value(contextKeyChannelLimiter).(*connectionChannelLimiter)
	for {
		accepted, err := f.listener.Accept()
		if err != nil {
			closeQuietly(accepted)
			if !isClosedError(err) {
				h.loggerOfConnection(conn).WithError(err).
					With("streamlocal.path", socketPath).
					Warn("'streamlocal-forward@openssh.com': listener stopped accepting")
			}
			return
		}
		if !limiter.reserve() {
			closeQuietly(accepted)
			h.loggerOfConnection(conn).With("streamlocal.path", socketPath).
				Warn("'streamlocal-forward@openssh.com': too many open SSH channels; rejecting connection")
			continue
		}
		if !f.beginOpen() {
			limiter.release()
			closeQuietly(accepted)
			return
		}
		if !startConnectionWorker(ctx, func() {
			defer limiter.release()
			defer closeQuietly(accepted)
			payload := gossh.Marshal(&remoteUnixForwardChannelData{SocketPath: socketPath})
			channel, reqs, err := openForwardedUnixChannel(ctx, f.done, conn, payload)
			f.endOpen()
			if err != nil {
				select {
				case <-f.done:
					return
				default:
				}
				h.loggerOfConnection(conn).WithError(err).
					With("streamlocal.path", socketPath).
					Warn("'streamlocal-forward@openssh.com': cannot open channel for accepted connection")
				return
			}
			defer closeQuietly(channel)
			go gossh.DiscardRequests(reqs)
			if err := FullDuplexCopy(ctx, accepted, channel, nil); err != nil {
				h.loggerOfConnection(conn).WithError(err).
					With("streamlocal.path", socketPath).
					Warn("'streamlocal-forward@openssh.com': failed to forward connection")
			}
		}) {
			f.endOpen()
			limiter.release()
			closeQuietly(accepted)
			return
		}
	}
}

func openForwardedUnixChannel(ctx context.Context, forwardDone <-chan struct{}, conn *gossh.ServerConn, payload []byte) (gossh.Channel, <-chan *gossh.Request, error) {
	// x/crypto/ssh registers ListenUnix after processing the success reply, so
	// an immediately accepted connection can briefly race that registration.
	for attempt := range 7 {
		select {
		case <-ctx.Done():
			return nil, nil, context.Cause(ctx)
		case <-forwardDone:
			return nil, nil, net.ErrClosed
		default:
		}
		channel, requests, err := conn.OpenChannel(forwardedUnixChannelType, payload)
		if !isStreamLocalForwardRegistrationRace(err) || attempt == 6 {
			return channel, requests, err
		}
		timer := time.NewTimer(time.Millisecond << attempt)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, nil, context.Cause(ctx)
		case <-forwardDone:
			timer.Stop()
			return nil, nil, net.ErrClosed
		case <-timer.C:
		}
	}
	panic("unreachable")
}

func isStreamLocalForwardRegistrationRace(err error) bool {
	var openErr *gossh.OpenChannelError
	return errors.As(err, &openErr) && openErr.Reason == gossh.Prohibited && openErr.Message == "no forward for address"
}

func (h *ForwardedUnixHandler) removeForward(key forwardKey, target *forward) {
	h.Lock()
	defer h.Unlock()
	if h.forwards[key] == target {
		delete(h.forwards, key)
	}
}

func (h *ForwardedUnixHandler) logger() log.Logger {
	if h.Logger != nil {
		return h.Logger
	}
	return defaultForwardedUnixHandlerLoggerGetter()
}

func (h *ForwardedUnixHandler) loggerOfConnection(conn *gossh.ServerConn) log.Logger {
	return enrichLoggerForServerConnection(h.logger(), conn)
}

var defaultForwardedUnixHandlerLoggerGetter = sync.OnceValue[log.Logger](func() log.Logger {
	return log.GetLogger(names.CurrentPackageLoggerNameGenerator(0) + ".unixForward")
})
