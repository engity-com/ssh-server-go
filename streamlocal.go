package ssh

import (
	"context"
	"errors"
	"fmt"
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
func DirectStreamLocalHandler(srv *Server, sshConn *gossh.ServerConn, newChan gossh.NewChannel, ctx Context) error {
	if newChan == nil {
		return nil
	}
	if srv == nil || sshConn == nil || ctx == nil {
		_ = newChan.Reject(gossh.ConnectionFailed, "missing server connection context")
		return nil
	}
	var data directStreamLocalChannelData
	if err := gossh.Unmarshal(newChan.ExtraData(), &data); err != nil {
		return locateError(ErrorScopeChannel, ErrorOperationParse, fmt.Errorf("parse direct-streamlocal channel data: %w", err))
	}
	if srv.LocalUnixForwardingCallback == nil {
		_ = newChan.Reject(gossh.Prohibited, "unix forwarding is disabled")
		return nil
	}

	finishAcquisition, ok := beginConnectionResourceAcquisition(ctx)
	if !ok {
		_ = newChan.Reject(gossh.ConnectionFailed, "connection is closing")
		return nil
	}
	conn, err := srv.LocalUnixForwardingCallback(ctx, sshConn, data.SocketPath)
	if err != nil {
		finishAcquisition(nil)
		if errors.Is(err, ErrServerPermissionDenied) {
			_ = newChan.Reject(gossh.Prohibited, "unix forwarding is denied")
			return nil
		}
		return locateError(ErrorScopeForwarding, ErrorOperationDial, fmt.Errorf("dial direct-streamlocal destination %q: %w", data.SocketPath, err))
	}
	if conn == nil {
		finishAcquisition(nil)
		return locateError(ErrorScopeForwarding, ErrorOperationDial, fmt.Errorf("dial direct-streamlocal destination %q: callback returned no connection", data.SocketPath))
	}
	unregisterConn := finishAcquisition(func() { closeQuietly(conn) })
	defer unregisterConn()

	channel, reqs, err := newChan.Accept()
	if err != nil {
		closeQuietly(conn)
		return locateError(ErrorScopeChannel, ErrorOperationAccept, fmt.Errorf("accept direct-streamlocal channel: %w", err))
	}
	go gossh.DiscardRequests(reqs)
	defer closeQuietly(channel)
	defer closeQuietly(conn)
	if err := FullDuplexCopy(ctx, conn, channel, nil); err != nil {
		return locateError(ErrorScopeForwarding, ErrorOperationForward, fmt.Errorf("forward direct-streamlocal connection: %w", err))
	}
	return nil
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

func (h *ForwardedUnixHandler) HandleSSHRequest(response RequestResponseWriter, request *Request) error {
	if h == nil || response == nil || request == nil {
		return errors.New("ssh: missing streamlocal forwarding request handler state")
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
	errorHandler := errorHandlerFromContext(ctx, srv)

	switch request.Type {
	case "streamlocal-forward@openssh.com":
		var payload remoteUnixForwardRequest
		if err := gossh.Unmarshal(request.Payload, &payload); err != nil {
			return locateError(ErrorScopeRequest, ErrorOperationParse, fmt.Errorf("parse streamlocal-forward request: %w", err))
		}
		if srv.ReverseUnixForwardingCallback == nil {
			return response.Reject(nil)
		}
		key := forwardKey{conn: conn, addr: payload.SocketPath}
		h.Lock()
		_, duplicate := h.forwards[key]
		h.Unlock()
		if duplicate {
			return response.Reject(nil)
		}
		forwardLimiter, _ := ctx.Value(contextKeyForwardLimiter).(*resourceLimiter)
		if !forwardLimiter.reserve() {
			return response.Reject(nil)
		}
		finishAcquisition, ok := beginConnectionResourceAcquisition(ctx)
		if !ok {
			forwardLimiter.release()
			return response.Reject(nil)
		}
		listener, err := srv.ReverseUnixForwardingCallback(ctx, conn, payload.SocketPath)
		if err != nil {
			finishAcquisition(nil)
			forwardLimiter.release()
			if !errors.Is(err, ErrServerPermissionDenied) {
				return locateError(ErrorScopeForwarding, ErrorOperationListen, fmt.Errorf("listen for streamlocal-forward on %q: %w", payload.SocketPath, err))
			}
			return response.Reject(nil)
		}
		if listener == nil {
			finishAcquisition(nil)
			forwardLimiter.release()
			return locateError(ErrorScopeForwarding, ErrorOperationListen, fmt.Errorf("listen for streamlocal-forward on %q: callback returned no listener", payload.SocketPath))
		}

		f := newForward(listener, forwardLimiter.release)
		unregisterForward := finishAcquisition(f.close)
		h.Lock()
		if h.forwards == nil {
			h.forwards = make(map[forwardKey]*forward)
		}
		if _, duplicate = h.forwards[key]; duplicate {
			h.Unlock()
			unregisterForward()
			f.close()
			return response.Reject(nil)
		}
		h.forwards[key] = f
		h.Unlock()
		responseState := request.response
		started := startConnectionWorker(ctx, func() {
			defer unregisterForward()
			stopCloseOnCancel := context.AfterFunc(ctx, f.close)
			defer stopCloseOnCancel()
			defer func() {
				f.close()
				f.waitForPendingOpens()
				h.removeForward(key, f)
			}()
			accepted, responseErr := responseState.wait(ctx)
			if responseErr != nil || !accepted {
				return
			}
			h.forwardConnections(ctx, conn, payload.SocketPath, f, errorHandler)
		})
		if !started {
			unregisterForward()
			h.removeForward(key, f)
			f.close()
			return response.Reject(nil)
		}
		return response.Accept(nil)

	case "cancel-streamlocal-forward@openssh.com":
		var payload remoteUnixForwardRequest
		if err := gossh.Unmarshal(request.Payload, &payload); err != nil {
			return locateError(ErrorScopeRequest, ErrorOperationParse, fmt.Errorf("parse cancel-streamlocal-forward request: %w", err))
		}
		key := forwardKey{conn: conn, addr: payload.SocketPath}
		h.Lock()
		forward, ok := h.forwards[key]
		h.Unlock()
		if ok {
			forward.close()
			return response.Accept(nil)
		}
		return response.Reject(nil)

	default:
		return response.Reject(nil)
	}
}

func (h *ForwardedUnixHandler) forwardConnections(ctx Context, conn *gossh.ServerConn, socketPath string, f *forward, errorHandler ErrorHandler) {
	limiter, _ := ctx.Value(contextKeyChannelLimiter).(*connectionChannelLimiter)
	var acceptDelay time.Duration
	for {
		finishAcquisition, ok := beginConnectionResourceAcquisition(ctx)
		if !ok {
			return
		}
		accepted, err := f.listener.Accept()
		if err != nil {
			finishAcquisition(nil)
			closeQuietly(accepted)
			if ctx.Err() == nil && !isClosedError(err) {
				if dispatchErrorOrEscalate(ctx, h.loggerOfConnection(conn), errorHandler, ErrorScopeForwarding, ErrorOperationAccept, err, nil, defaultLogAndFailErrorAction) {
					if !waitForRetry(ctx, &acceptDelay) {
						return
					}
					continue
				}
			}
			return
		}
		acceptDelay = 0
		unregisterConn := finishAcquisition(func() { closeQuietly(accepted) })
		if !limiter.reserve() {
			unregisterConn()
			closeQuietly(accepted)
			h.loggerOfConnection(conn).With("streamlocal.path", socketPath).
				Warn("'streamlocal-forward@openssh.com': too many open SSH channels; rejecting connection")
			continue
		}
		if !f.beginOpen() {
			unregisterConn()
			limiter.release()
			closeQuietly(accepted)
			return
		}
		if !startConnectionWorker(ctx, func() {
			defer unregisterConn()
			defer limiter.release()
			defer closeQuietly(accepted)
			payload := gossh.Marshal(&remoteUnixForwardChannelData{SocketPath: socketPath})
			var channel gossh.Channel
			var reqs <-chan *gossh.Request
			var err error
			func() {
				defer f.endOpen()
				channel, reqs, err = openForwardedChannel(ctx, f.done, conn, forwardedUnixChannelType, payload)
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
			defer closeQuietly(channel)
			go gossh.DiscardRequests(reqs)
			if err := FullDuplexCopy(ctx, accepted, channel, nil); err != nil {
				if !dispatchErrorOrEscalate(ctx, h.loggerOfConnection(conn), errorHandler, ErrorScopeForwarding, ErrorOperationForward, err, nil, defaultLogAndFailErrorAction) {
					f.close()
				}
			}
		}) {
			unregisterConn()
			f.endOpen()
			limiter.release()
			closeQuietly(accepted)
			return
		}
	}
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
