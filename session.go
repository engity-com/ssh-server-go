package ssh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/anmitsu/go-shlex"
	"github.com/echocat/slf4g"
	"github.com/echocat/slf4g/names"
	gossh "golang.org/x/crypto/ssh"
)

const (
	maxSessionErrorResponseBytes = 4096
	sessionErrorResponseTimeout  = time.Second
)

// Session provides access to information about an SSH session and methods
// to read and write to the SSH channel with an embedded Channel interface from
// crypto/ssh.
//
// When Command() returns an empty slice, the user requested a shell. Otherwise
// the user is performing an exec with those command arguments.
type Session interface {
	gossh.Channel

	// User returns the username used when establishing the SSH connection.
	User() string

	// RemoteAddr returns the net.Addr of the client side of the connection.
	RemoteAddr() net.Addr

	// LocalAddr returns the net.Addr of the server side of the connection.
	LocalAddr() net.Addr

	// Environ returns a copy of strings representing the environment set by the
	// user for this session, in the form "key=value".
	Environ() []string

	// Exit sends an exit status and then closes the session.
	Exit(code int) error

	// Command returns a shell parsed slice of arguments that were provided by the
	// user. Shell parsing splits the command string according to POSIX shell rules,
	// which considers quoting not just whitespace.
	Command() []string

	// RawCommand returns the exact command that was provided by the user.
	RawCommand() string

	// Subsystem returns the subsystem requested by the user.
	Subsystem() string

	// PublicKey returns the PublicKey used to authenticate. If a public key was not
	// used it will return nil.
	PublicKey() PublicKey

	// Context returns the connection's context. The returned context is always
	// non-nil and holds the same data as the Context passed into auth
	// handlers and callbacks.
	//
	// Values are inherited from the context passed to Serve or HandleConn. Its
	// cancellation and deadline are intentionally detached during graceful
	// shutdown. The connection context is canceled when the connection closes,
	// an I/O operation fails, or a hard shutdown begins.
	Context() Context

	// Permissions returns a copy of the Permissions object that was available for
	// setup in the auth handlers via the Context. Its map containers are copied;
	// arbitrary values stored in ExtraData are not recursively cloned.
	Permissions() Permissions

	// Pty returns the client's PTY request, a channel of effective window sizes,
	// and whether a PTY was accepted for this session. The channel initially
	// contains the size from the PTY request. If the receiver falls behind,
	// intermediate changes are coalesced and the latest size is retained. The
	// returned Pty and its TerminalModes map are snapshots and can be modified by
	// the caller.
	Pty() (Pty, <-chan Window, bool)

	// Signals registers a channel to receive signals sent from the client. The
	// channel must handle signal sends promptly. Blocked sends are canceled when
	// the channel is unregistered, the session exits, or its context is canceled.
	// Registering nil will unregister the channel from signal sends. During the
	// time no channel is registered signals are buffered up to a reasonable amount.
	// If there are buffered signals when a channel is registered, they will be
	// sent in order on the channel immediately after registering. The receiver
	// must unregister the channel before closing it.
	Signals(c chan<- Signal)

	// Break registers a channel to receive notifications of break requests sent
	// from the client. The channel must handle break requests, or it will block
	// the request handling loop. Registering nil will unregister the channel.
	// During the time that no channel is registered, breaks are ignored.
	// The receiver must unregister the channel before closing it.
	Break(c chan<- bool)
}

// SessionExitError requests a public message and exit status from a Handler or
// SubsystemHandler. It bypasses [ErrorHandler] unless sending the response
// fails. Wrapping preserves this behavior; joining another error routes the
// result through [ErrorHandler].
type SessionExitError struct {
	Code    int
	Message string
}

// NewSessionExitError creates a controlled session exit.
func NewSessionExitError(code int, message string) *SessionExitError {
	return &SessionExitError{Code: code, Message: message}
}

func (e *SessionExitError) Error() string {
	if e == nil {
		return "ssh: session exit requested"
	}
	if e.Message == "" {
		return fmt.Sprintf("ssh: session exit requested with code %d", e.Code)
	}
	return fmt.Sprintf("ssh: session exit requested with code %d: %s", e.Code, e.Message)
}

const (
	// Signal names are short RFC 4254 identifiers. Bounding their size prevents
	// clients from retaining packet-sized strings in every session buffer.
	maxSessionSignalBytes = 64
	maxSigBufSize         = 128
)

const (
	maxSessionEnvVariables = 128
	maxSessionEnvBytes     = 64 * 1024
)

func DefaultSessionHandler(srv *Server, conn *gossh.ServerConn, newChan gossh.NewChannel, ctx Context) error {
	ch, reqs, err := newChan.Accept()
	if err != nil {
		return locateError(ErrorScopeChannel, ErrorOperationAccept, err)
	}
	sess := &session{
		Channel:           ch,
		conn:              conn,
		handler:           srv.handler(),
		ptyCb:             srv.PtyCallback,
		sessReqCb:         srv.SessionRequestCallback,
		agentForwardingCb: srv.AgentForwardingCallback,
		subsystemHandlers: srv.subsystemHandlers(),
		errorHandler:      errorHandlerFromContext(ctx, srv),
		requestTimeout:    configuredDuration(srv.SessionRequestTimeout, DefaultSessionRequestTimeout),
		ctx:               &sessionAgentContext{Context: ctx},
		logger:            srv.Logger,
	}
	sess.handleRequests(reqs)
	if sess.handlerDone != nil {
		<-sess.handlerDone
	}
	return nil
}

type session struct {
	sync.Mutex
	sigConfigMu   sync.Mutex
	sigReplyMu    sync.Mutex
	breakConfigMu sync.Mutex
	breakReplyMu  sync.Mutex
	gossh.Channel
	conn              *gossh.ServerConn
	handler           Handler
	subsystemHandlers map[string]SubsystemHandler
	errorHandler      ErrorHandler
	handled           bool
	exited            bool
	pty               *Pty
	winch             chan Window
	env               []string
	envBytes          int
	ptyCb             PtyCallback
	sessReqCb         SessionRequestCallback
	agentForwardingCb AgentForwardingCallback
	rawCmd            string
	subsystem         string
	ctx               Context
	sigCh             chan<- Signal
	sigBuf            []Signal
	sigDrainCancel    chan struct{}
	sigDrainDone      chan struct{}
	sigSendCancel     chan struct{}
	sigSendWg         sync.WaitGroup
	sigSends          int
	breakCh           chan<- bool
	breakSendCancel   chan struct{}
	breakSendWg       sync.WaitGroup
	breakSends        int
	exiting           atomic.Bool
	requestStarted    atomic.Bool
	handlerDone       <-chan struct{}
	requestTimeout    time.Duration
	logger            log.Logger
}

func (sess *session) Write(p []byte) (n int, err error) {
	if sess.pty != nil {
		m := len(p)
		// normalize \n to \r\n when pty is accepted.
		// Terminal modes are exposed to applications but are not interpreted here.
		p = bytes.ReplaceAll(p, []byte{'\n'}, []byte{'\r', '\n'})
		p = bytes.ReplaceAll(p, []byte{'\r', '\r', '\n'}, []byte{'\r', '\n'})
		n, err = sess.Channel.Write(p)
		if n > m {
			n = m
		}
		return
	}
	return sess.Channel.Write(p)
}

func (sess *session) PublicKey() PublicKey {
	sessionKey := sess.ctx.Value(ContextKeyPublicKey)
	if sessionKey == nil {
		return nil
	}
	return sessionKey.(PublicKey)
}

func (sess *session) Permissions() Permissions {
	source := sess.ctx.Value(ContextKeyPermissions).(*Permissions).Permissions
	result := *source
	result.CriticalOptions = maps.Clone(source.CriticalOptions)
	result.Extensions = maps.Clone(source.Extensions)
	result.ExtraData = maps.Clone(source.ExtraData)
	return Permissions{Permissions: &result}
}

func (sess *session) Context() Context {
	return sess.ctx
}

func (sess *session) Exit(code int) error {
	if code < 0 || uint64(code) > uint64(math.MaxUint32) {
		return fmt.Errorf("ssh: invalid session exit status %d", code)
	}
	sess.Lock()
	sess.exiting.Store(true)
	sess.Unlock()
	sess.stopSignalDeliveryForExit()
	sess.sigReplyMu.Lock()
	defer sess.sigReplyMu.Unlock()
	sess.stopBreakDeliveryForExit()
	sess.breakReplyMu.Lock()
	defer sess.breakReplyMu.Unlock()
	sess.Lock()
	defer sess.Unlock()
	if sess.exited {
		return errors.New("Session.Exit called multiple times")
	}
	sess.exited = true

	status := struct{ Status uint32 }{uint32(code)} // #nosec G115 -- range checked above
	_, requestErr := sess.SendRequest("exit-status", false, gossh.Marshal(&status))
	return errors.Join(requestErr, sess.Close())
}

func (sess *session) User() string {
	return sess.conn.User()
}

func (sess *session) RemoteAddr() net.Addr {
	return sess.conn.RemoteAddr()
}

func (sess *session) LocalAddr() net.Addr {
	return sess.conn.LocalAddr()
}

func (sess *session) Environ() []string {
	return append([]string(nil), sess.env...)
}

func (sess *session) RawCommand() string {
	return sess.rawCmd
}

func (sess *session) Command() []string {
	cmd, _ := shlex.Split(sess.rawCmd, true)
	return append([]string(nil), cmd...)
}

func (sess *session) Subsystem() string {
	return sess.subsystem
}

func (sess *session) Pty() (Pty, <-chan Window, bool) {
	sess.Lock()
	defer sess.Unlock()
	if sess.pty != nil {
		return clonePty(*sess.pty), sess.winch, true
	}
	return Pty{}, sess.winch, false
}

func clonePty(pty Pty) Pty {
	pty.TerminalModes = maps.Clone(pty.TerminalModes)
	return pty
}

func (sess *session) Signals(c chan<- Signal) {
	sess.sigConfigMu.Lock()
	defer sess.sigConfigMu.Unlock()
	if sess.exiting.Load() {
		return
	}
	sess.setSignalChannelLocked(c)
}

func (sess *session) setSignalChannelLocked(c chan<- Signal) {
	sess.Lock()
	if sess.sigDrainCancel != nil {
		close(sess.sigDrainCancel)
		done := sess.sigDrainDone
		sess.Unlock()
		<-done
		sess.Lock()
	}
	if sess.sigSendCancel != nil {
		close(sess.sigSendCancel)
		sess.sigSendCancel = nil
	}
	sess.sigCh = nil
	sess.Unlock()
	sess.sigSendWg.Wait()
	sess.Lock()
	if c == nil {
		sess.Unlock()
		return
	}
	if len(sess.sigBuf) == 0 {
		sess.sigCh = c
		sess.sigSendCancel = make(chan struct{})
		sess.Unlock()
		return
	}
	cancel := make(chan struct{})
	done := make(chan struct{})
	sess.sigDrainCancel = cancel
	sess.sigDrainDone = done
	sess.Unlock()
	go sess.drainSignals(c, cancel, done)
}

func (sess *session) stopSignalDeliveryForExit() {
	sess.sigConfigMu.Lock()
	defer sess.sigConfigMu.Unlock()
	sess.setSignalChannelLocked(nil)
}

func (sess *session) drainSignals(target chan<- Signal, cancel <-chan struct{}, done chan struct{}) {
	defer func() {
		sess.Lock()
		if sess.sigDrainDone == done {
			sess.sigDrainCancel = nil
			sess.sigDrainDone = nil
		}
		sess.Unlock()
		close(done)
	}()
	for {
		sess.Lock()
		buffered := append([]Signal(nil), sess.sigBuf...)
		sess.sigBuf = nil
		if len(buffered) == 0 {
			sess.sigCh = target
			sess.sigSendCancel = make(chan struct{})
			sess.sigDrainCancel = nil
			sess.sigDrainDone = nil
			sess.Unlock()
			return
		}
		sess.Unlock()

		for i, sig := range buffered {
			delivered, contextDone, channelClosed := sendSignal(target, sig, cancel, sess.ctx.Done())
			if channelClosed || !delivered {
				if !contextDone {
					sess.requeueSignals(buffered[i:])
				}
				return
			}
		}
	}
}

func (sess *session) requeueSignals(signals []Signal) {
	sess.Lock()
	defer sess.Unlock()
	signals = append(append([]Signal(nil), signals...), sess.sigBuf...)
	if len(signals) > maxSigBufSize {
		signals = signals[:maxSigBufSize]
	}
	sess.sigBuf = signals
	sess.sigDrainCancel = nil
	sess.sigDrainDone = nil
}

func (sess *session) Break(c chan<- bool) {
	sess.breakConfigMu.Lock()
	defer sess.breakConfigMu.Unlock()
	if sess.exiting.Load() {
		return
	}
	sess.setBreakChannelLocked(c)
}

func (sess *session) setBreakChannelLocked(c chan<- bool) {
	sess.Lock()
	if sess.breakSendCancel != nil {
		close(sess.breakSendCancel)
		sess.breakSendCancel = nil
	}
	sess.breakCh = nil
	sess.Unlock()
	sess.breakSendWg.Wait()
	sess.Lock()
	if c != nil {
		sess.breakCh = c
		sess.breakSendCancel = make(chan struct{})
	}
	sess.Unlock()
}

func (sess *session) stopBreakDeliveryForExit() {
	sess.exiting.Store(true)
	sess.breakConfigMu.Lock()
	defer sess.breakConfigMu.Unlock()
	sess.setBreakChannelLocked(nil)
}

func (sess *session) deliverBreak() bool {
	sess.Lock()
	breakCh := sess.breakCh
	breakSendCancel := sess.breakSendCancel
	if breakCh != nil {
		sess.breakSendWg.Add(1)
		sess.breakSends++
	}
	sess.Unlock()
	if breakCh == nil {
		return false
	}
	delivered, channelClosed := sendBreak(breakCh, breakSendCancel, sess.ctx.Done())
	sess.Lock()
	sess.breakSends--
	if channelClosed && sess.breakCh == breakCh {
		sess.breakCh = nil
		sess.breakSendCancel = nil
	}
	sess.Unlock()
	sess.breakSendWg.Done()
	return delivered
}

func sendSignal(target chan<- Signal, signal Signal, cancel, contextDone <-chan struct{}) (delivered, canceledByContext, channelClosed bool) {
	defer func() {
		if recover() != nil {
			delivered = false
			channelClosed = true
		}
	}()
	select {
	case target <- signal:
		return true, false, false
	case <-cancel:
		return false, false, false
	case <-contextDone:
		return false, true, false
	}
}

func sendBreak(target chan<- bool, cancel, contextDone <-chan struct{}) (delivered, channelClosed bool) {
	defer func() {
		if recover() != nil {
			delivered = false
			channelClosed = true
		}
	}()
	select {
	case target <- true:
		return true, false
	case <-cancel:
		return false, false
	case <-contextDone:
		return false, false
	}
}

func (sess *session) deliverBreakAndReply(reply func(bool)) {
	sess.breakReplyMu.Lock()
	defer sess.breakReplyMu.Unlock()
	reply(sess.deliverBreak())
}

func (sess *session) handleSignalRequest(req *gossh.Request) bool {
	sess.sigReplyMu.Lock()
	defer sess.sigReplyMu.Unlock()
	var payload struct{ Signal string }
	if err := gossh.Unmarshal(req.Payload, &payload); err != nil {
		_ = req.Reply(false, nil)
		return true
	}
	if len(payload.Signal) > maxSessionSignalBytes {
		_ = req.Reply(false, nil)
		return true
	}
	sess.Lock()
	if sess.exiting.Load() {
		sess.Unlock()
		_ = req.Reply(false, nil)
		return false
	}
	sigCh := sess.sigCh
	var sigSendCancel <-chan struct{}
	if sigCh == nil {
		if len(sess.sigBuf) < maxSigBufSize {
			sess.sigBuf = append(sess.sigBuf, Signal(payload.Signal))
		}
	} else {
		sigSendCancel = sess.sigSendCancel
		sess.sigSendWg.Add(1)
		sess.sigSends++
	}
	sess.Unlock()
	if sigCh == nil {
		_ = req.Reply(true, nil)
		return true
	}
	delivered, contextDone, channelClosed := sendSignal(sigCh, Signal(payload.Signal), sigSendCancel, sess.ctx.Done())
	sess.Lock()
	sess.sigSends--
	if channelClosed {
		if sess.sigCh == sigCh {
			sess.sigCh = nil
			sess.sigSendCancel = nil
		}
	}
	sess.Unlock()
	sess.sigSendWg.Done()
	_ = req.Reply(delivered, nil)
	return !contextDone
}

func (sess *session) startHandler(handler func(Session) error) {
	done := make(chan struct{})
	sess.handlerDone = done
	go func() {
		defer close(done)
		err := handler(sess)
		if requestedExit, ok := exclusiveSessionExitError(err); ok {
			sess.Lock()
			exited := sess.exited
			sess.Unlock()
			if !exited {
				if exitErr := sess.applyExitError(requestedExit); exitErr != nil {
					dispatchErrorOrEscalate(sess.ctx, sess.getLogger(), sess.errorHandler, ErrorScopeSession, ErrorOperationReply, exitErr, nil, defaultLogAndFailErrorAction)
				}
			}
			return
		}
		canContinue := err == nil
		closeRequested := false
		if err != nil {
			response := newErrorResponse(sess.respondToError)
			var filteredErr error
			canContinue, filteredErr = dispatchError(sess.ctx, sess.getLogger(), sess.errorHandler, ErrorScopeSession, ErrorOperationHandle, err, response, defaultLogAndFailErrorAction)
			_, responseErr := response.result()
			responseFailureHandled := false
			if filteredErr != nil {
				if responseErr != nil && !errors.Is(responseErr, ErrErrorResponseUnsupported) && isOnlyError(filteredErr, responseErr) {
					logDispatchErrorEscalate(sess.getLogger(), ErrorScopeSession, ErrorOperationReply, responseErr, err)
					closeQuietly(sess)
					responseFailureHandled = true
				} else {
					logDispatchErrorEscalate(sess.getLogger(), ErrorScopeSession, ErrorOperationHandle, filteredErr, err)
					closeQuietly(sess.conn)
				}
				canContinue = false
			}
			closeRequested = response.closeRequested()
			if responseErr != nil && !errors.Is(responseErr, ErrErrorResponseUnsupported) && !responseFailureHandled {
				logDispatchErrorEscalate(sess.getLogger(), ErrorScopeSession, ErrorOperationReply, responseErr, err)
				closeQuietly(sess)
				canContinue = false
			}
		}
		sess.Lock()
		exited := sess.exited
		sess.Unlock()
		if closeRequested {
			closeQuietly(sess)
			return
		}
		if !exited {
			status := 0
			if err != nil && !canContinue {
				status = 1
			}
			if exitErr := sess.Exit(status); exitErr != nil {
				dispatchErrorOrEscalate(sess.ctx, sess.getLogger(), sess.errorHandler, ErrorScopeSession, ErrorOperationReply, exitErr, nil, defaultLogAndFailErrorAction)
			}
		}
	}()
}

func exclusiveSessionExitError(err error) (*SessionExitError, bool) {
	if err == nil {
		return nil, false
	}
	if exitErr, ok := err.(*SessionExitError); ok && exitErr != nil {
		return exitErr, true
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		var result *SessionExitError
		for _, child := range joined.Unwrap() {
			exitErr, exclusive := exclusiveSessionExitError(child)
			if !exclusive || result != nil {
				return nil, false
			}
			result = exitErr
		}
		return result, result != nil
	}
	if wrapped := errors.Unwrap(err); wrapped != nil {
		return exclusiveSessionExitError(wrapped)
	}
	var exitErr *SessionExitError
	if errors.As(err, &exitErr) && exitErr != nil {
		return exitErr, true
	}
	return nil, false
}

func (sess *session) applyExitError(exitErr *SessionExitError) error {
	var responseErr error
	if exitErr.Message != "" {
		responseErr = sess.respondToError([]byte(exitErr.Message), false)
	}
	return errors.Join(responseErr, sess.Exit(exitErr.Code))
}

func (sess *session) respondToError(message []byte, closeAfterResponse bool) error {
	return sess.respondToErrorWithin(message, closeAfterResponse, sessionErrorResponseTimeout)
}

func (sess *session) respondToErrorWithin(message []byte, closeAfterResponse bool, timeout time.Duration) error {
	if len(message) > maxSessionErrorResponseBytes {
		message = message[:maxSessionErrorResponseBytes]
	}
	message = append([]byte(nil), message...)
	written := make(chan error, 1)
	go func() {
		n, err := sess.Stderr().Write(message)
		if err == nil && n != len(message) {
			err = io.ErrShortWrite
		}
		written <- err
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	var err error
	select {
	case err = <-written:
	case <-sess.ctx.Done():
		err = context.Cause(sess.ctx)
		closeSSHConnection(sess.ctx)
	case <-timer.C:
		err = fmt.Errorf("write session error response: %w", context.DeadlineExceeded)
		closeSSHConnection(sess.ctx)
	}
	if closeAfterResponse {
		closeQuietly(sess.conn)
	}
	return err
}

func (sess *session) handleRequests(reqs <-chan *gossh.Request) {
	var requestTimer *time.Timer
	if sess.requestTimeout > 0 {
		requestTimer = time.AfterFunc(sess.requestTimeout, func() {
			if !sess.requestStarted.Load() {
				closeSSHConnection(sess.ctx)
			}
		})
		defer requestTimer.Stop()
	}
	defer func() {
		if sess.winch != nil {
			close(sess.winch)
		}
	}()

	for req := range reqs {
		switch req.Type {
		case "shell", "exec":
			if sess.handled || sess.handler == nil {
				_ = req.Reply(false, nil)
				continue
			}

			var payload = struct{ Value string }{}
			if req.Type == "exec" {
				if err := gossh.Unmarshal(req.Payload, &payload); err != nil {
					_ = req.Reply(false, nil)
					continue
				}
			}
			sess.rawCmd = payload.Value
			sess.subsystem = ""

			// If there's a session policy callback, we need to confirm before
			// accepting the session.
			if sess.sessReqCb != nil {
				allowed, err := sess.sessReqCb(sess, req.Type)
				if err != nil {
					sess.rawCmd = ""
					if !sess.handleCallbackError(req, fmt.Errorf("authorize %s session request: %w", req.Type, err)) {
						return
					}
					continue
				}
				if !allowed {
					sess.rawCmd = ""
					_ = req.Reply(false, nil)
					continue
				}
			}

			sess.handled = true
			if !sess.reply(req, true) {
				return
			}
			sess.requestStarted.Store(true)
			if requestTimer != nil {
				requestTimer.Stop()
			}

			sess.startHandler(sess.handler)
		case "subsystem":
			if sess.handled {
				_ = req.Reply(false, nil)
				continue
			}

			var payload = struct{ Value string }{}
			if err := gossh.Unmarshal(req.Payload, &payload); err != nil {
				_ = req.Reply(false, nil)
				continue
			}
			sess.subsystem = payload.Value
			sess.rawCmd = ""

			// If there's a session policy callback, we need to confirm before
			// accepting the session.
			if sess.sessReqCb != nil {
				allowed, err := sess.sessReqCb(sess, req.Type)
				if err != nil {
					sess.subsystem = ""
					if !sess.handleCallbackError(req, fmt.Errorf("authorize subsystem session request: %w", err)) {
						return
					}
					continue
				}
				if !allowed {
					sess.subsystem = ""
					_ = req.Reply(false, nil)
					continue
				}
			}

			handler := sess.subsystemHandlers[payload.Value]
			if handler == nil {
				handler = sess.subsystemHandlers["default"]
			}
			if handler == nil {
				sess.subsystem = ""
				_ = req.Reply(false, nil)
				continue
			}

			sess.handled = true
			if !sess.reply(req, true) {
				return
			}
			sess.requestStarted.Store(true)
			if requestTimer != nil {
				requestTimer.Stop()
			}

			sess.startHandler(handler)
		case "env":
			if sess.handled {
				_ = req.Reply(false, nil)
				continue
			}
			var kv struct{ Key, Value string }
			if err := gossh.Unmarshal(req.Payload, &kv); err != nil {
				_ = req.Reply(false, nil)
				continue
			}
			envBytes := len(kv.Key) + 1 + len(kv.Value)
			if len(sess.env) >= maxSessionEnvVariables || sess.envBytes+envBytes > maxSessionEnvBytes {
				_ = req.Reply(false, nil)
				continue
			}
			sess.env = append(sess.env, fmt.Sprintf("%s=%s", kv.Key, kv.Value))
			sess.envBytes += envBytes
			_ = req.Reply(true, nil)
		case "signal":
			if !sess.handleSignalRequest(req) {
				return
			}
		case "pty-req":
			if sess.handled || sess.pty != nil {
				_ = req.Reply(false, nil)
				continue
			}
			ptyReq, ok := parsePtyRequest(req.Payload)
			if !ok {
				_ = req.Reply(false, nil)
				continue
			}
			if sess.ptyCb != nil {
				allowed, err := sess.ptyCb(sess.ctx, sess, clonePty(ptyReq))
				if err != nil {
					if !sess.handleCallbackError(req, fmt.Errorf("authorize PTY request: %w", err)) {
						return
					}
					continue
				}
				if !allowed {
					_ = req.Reply(false, nil)
					continue
				}
			}
			sess.pty = &ptyReq
			sess.winch = make(chan Window, 1)
			sess.winch <- ptyReq.Window
			_ = req.Reply(ok, nil)
		case "window-change":
			if sess.pty == nil {
				_ = req.Reply(false, nil)
				continue
			}
			win, ok := parseWinchRequest(req.Payload)
			if ok {
				sess.Lock()
				win = mergeWindow(sess.pty.Window, win)
				sess.pty.Window = win
				select {
				case sess.winch <- win:
				default:
					select {
					case <-sess.winch:
					default:
					}
					select {
					case sess.winch <- win:
					default:
					}
				}
				sess.Unlock()
			}
			_ = req.Reply(ok, nil)
		case agentRequestType:
			if sess.agentForwardingCb == nil {
				_ = req.Reply(false, nil)
				continue
			}
			allowed, err := sess.agentForwardingCb(sess.ctx, sess)
			if err != nil {
				if !sess.handleCallbackError(req, fmt.Errorf("authorize agent forwarding: %w", err)) {
					return
				}
				continue
			}
			if !allowed {
				_ = req.Reply(false, nil)
				continue
			}
			SetAgentRequested(sess.ctx)
			if !sess.reply(req, true) {
				return
			}
		case "break":
			sess.deliverBreakAndReply(func(ok bool) {
				_ = req.Reply(ok, nil)
			})
		default:
			sess.getLogger().
				With("request", req.Type).
				Debug("unknown request")
			_ = req.Reply(false, nil)
		}
	}
}

func (sess *session) reply(req *gossh.Request, accepted bool) bool {
	if err := req.Reply(accepted, nil); err != nil {
		dispatchErrorOrEscalate(sess.ctx, sess.getLogger(), sess.errorHandler, ErrorScopeSession, ErrorOperationReply, err, nil, defaultLogAndFailErrorAction)
		closeSSHConnection(sess.ctx)
		return false
	}
	return true
}

func (sess *session) handleCallbackError(req *gossh.Request, callbackErr error) bool {
	response := newErrorResponse(func(message []byte, _ bool) error {
		return sess.respondToError(message, false)
	})
	canContinue, filteredErr := dispatchError(sess.ctx, sess.getLogger(), sess.errorHandler, ErrorScopeSession, ErrorOperationHandle, callbackErr, response, defaultLogAndFailErrorAction)
	_, responseErr := response.result()
	closeRequested := response.closeRequested()
	if err := req.Reply(false, nil); err != nil {
		dispatchErrorOrEscalate(sess.ctx, sess.getLogger(), sess.errorHandler, ErrorScopeSession, ErrorOperationReply, errors.Join(callbackErr, err), nil, defaultLogAndFailErrorAction)
		responseFailureHandled := false
		if filteredErr != nil {
			if responseErr != nil && !errors.Is(responseErr, ErrErrorResponseUnsupported) && isOnlyError(filteredErr, responseErr) {
				logDispatchErrorEscalate(sess.getLogger(), ErrorScopeSession, ErrorOperationReply, responseErr, callbackErr)
				responseFailureHandled = true
			} else {
				logDispatchErrorEscalate(sess.getLogger(), ErrorScopeSession, ErrorOperationHandle, filteredErr, callbackErr)
			}
		}
		if responseErr != nil && !errors.Is(responseErr, ErrErrorResponseUnsupported) && !responseFailureHandled {
			logDispatchErrorEscalate(sess.getLogger(), ErrorScopeSession, ErrorOperationReply, responseErr, callbackErr)
		}
		if closeRequested || (filteredErr != nil && !responseFailureHandled) {
			closeSSHConnection(sess.ctx)
		} else {
			closeQuietly(sess)
		}
		return false
	}
	if filteredErr != nil {
		if responseErr != nil && !errors.Is(responseErr, ErrErrorResponseUnsupported) && isOnlyError(filteredErr, responseErr) {
			logDispatchErrorEscalate(sess.getLogger(), ErrorScopeSession, ErrorOperationReply, responseErr, callbackErr)
			if closeRequested {
				closeSSHConnection(sess.ctx)
			} else {
				closeQuietly(sess)
			}
		} else {
			logDispatchErrorEscalate(sess.getLogger(), ErrorScopeSession, ErrorOperationHandle, filteredErr, callbackErr)
			closeSSHConnection(sess.ctx)
		}
		return false
	}
	if responseErr != nil && !errors.Is(responseErr, ErrErrorResponseUnsupported) {
		logDispatchErrorEscalate(sess.getLogger(), ErrorScopeSession, ErrorOperationReply, responseErr, callbackErr)
		if closeRequested {
			closeSSHConnection(sess.ctx)
		} else {
			closeQuietly(sess)
		}
		return false
	}
	if closeRequested {
		closeSSHConnection(sess.ctx)
		return false
	}
	if !canContinue {
		closeQuietly(sess)
		return false
	}
	return true
}

func mergeWindow(current, update Window) Window {
	if update.Width != 0 {
		current.Width = update.Width
	}
	if update.Height != 0 {
		current.Height = update.Height
	}
	if update.WidthPixels != 0 {
		current.WidthPixels = update.WidthPixels
	}
	if update.HeightPixels != 0 {
		current.HeightPixels = update.HeightPixels
	}
	return current
}

func (sess *session) getLogger() log.Logger {
	v := sess.logger
	if v == nil {
		v = defaultSessionLoggerGetter()
	}
	return enrichLoggerForServerConnection(v, sess.conn)
}

var defaultSessionLoggerGetter = sync.OnceValue[log.Logger](func() log.Logger {
	return log.GetLogger(names.CurrentPackageLoggerNameGenerator(0) + ".session")
})
