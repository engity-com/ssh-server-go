package ssh

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/anmitsu/go-shlex"
	"github.com/echocat/slf4g"
	"github.com/echocat/slf4g/names"
	gossh "golang.org/x/crypto/ssh"
)

// Session provides access to information about an SSH session and methods
// to read and write to the SSH channel with an embedded Channel interface from
// crypto/ssh.
//
// When Command() returns an empty slice, the user requested a shell. Otherwise
// the user is performing an exec with those command arguments.
//
// TODO: Signals
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
	// The context is canceled when the client's connection closes or I/O
	// operation fails.
	Context() Context

	// Permissions returns a copy of the Permissions object that was available for
	// setup in the auth handlers via the Context.
	Permissions() Permissions

	// Pty returns PTY information, a channel of window size changes, and a boolean
	// of whether a PTY was accepted for this session.
	Pty() (Pty, <-chan Window, bool)

	// Signals registers a channel to receive signals sent from the client. The
	// channel must handle signal sends, or it will block the SSH request loop.
	// Registering nil will unregister the channel from signal sends. During the
	// time no channel is registered signals are buffered up to a reasonable amount.
	// If there are buffered signals when a channel is registered, they will be
	// sent in order on the channel immediately after registering.
	Signals(c chan<- Signal)

	// Break registers a channel to receive notifications of break requests sent
	// from the client. The channel must handle break requests, or it will block
	// the request handling loop. Registering nil will unregister the channel.
	// During the time that no channel is registered, breaks are ignored.
	Break(c chan<- bool)
}

// maxSigBufSize is how many signals will be buffered
// when there is no signal channel specified
const maxSigBufSize = 128

const (
	maxSessionEnvVariables = 128
	maxSessionEnvBytes     = 64 * 1024
)

func DefaultSessionHandler(srv *Server, conn *gossh.ServerConn, newChan gossh.NewChannel, ctx Context) {
	settings := serverSettingsFromContext(ctx, srv)
	ch, reqs, err := newChan.Accept()
	if err != nil {
		logger := settings.logger
		if logger == nil {
			logger = srv.logger()
		}
		enrichLoggerForServerConnection(logger, conn).
			WithError(err).
			Warn("failed to accept new channel")
		return
	}
	sess := &session{
		Channel:           ch,
		conn:              conn,
		handler:           settings.handler,
		ptyCb:             settings.ptyCallback,
		sessReqCb:         settings.sessionRequestCallback,
		subsystemHandlers: settings.subsystemHandlers,
		ctx:               ctx,
		logger:            settings.logger,
	}
	sess.handleRequests(reqs)
}

type session struct {
	sync.Mutex
	sigConfigMu   sync.Mutex
	breakConfigMu sync.Mutex
	gossh.Channel
	conn              *gossh.ServerConn
	handler           Handler
	subsystemHandlers map[string]SubsystemHandler
	handled           bool
	exited            bool
	pty               *Pty
	winch             chan Window
	env               []string
	envBytes          int
	ptyCb             PtyCallback
	sessReqCb         SessionRequestCallback
	rawCmd            string
	subsystem         string
	ctx               Context
	sigCh             chan<- Signal
	sigBuf            []Signal
	sigDrainCancel    chan struct{}
	sigDrainDone      chan struct{}
	sigSendCancel     chan struct{}
	sigSendWg         sync.WaitGroup
	breakCh           chan<- bool
	breakSendCancel   chan struct{}
	breakSendWg       sync.WaitGroup
	breakSends        int
	logger            log.Logger
}

func (sess *session) Write(p []byte) (n int, err error) {
	if sess.pty != nil {
		m := len(p)
		// normalize \n to \r\n when pty is accepted.
		// this is a hardcoded shortcut since we don't support terminal modes.
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
	// use context permissions because its properly
	// wrapped and easier to dereference
	perms := sess.ctx.Value(ContextKeyPermissions).(*Permissions)
	return *perms
}

func (sess *session) Context() Context {
	return sess.ctx
}

func (sess *session) Exit(code int) error {
	sess.Lock()
	defer sess.Unlock()
	if sess.exited {
		return errors.New("Session.Exit called multiple times")
	}
	sess.exited = true

	status := struct{ Status uint32 }{uint32(code)}
	_, err := sess.SendRequest("exit-status", false, gossh.Marshal(&status))
	if err != nil {
		return err
	}
	return sess.Close()
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
		return *sess.pty, sess.winch, true
	}
	return Pty{}, sess.winch, false
}

func (sess *session) Signals(c chan<- Signal) {
	sess.sigConfigMu.Lock()
	defer sess.sigConfigMu.Unlock()

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
			select {
			case target <- sig:
			case <-cancel:
				sess.requeueSignals(buffered[i:])
				return
			case <-sess.ctx.Done():
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
	delivered := false
	select {
	case breakCh <- true:
		delivered = true
	case <-breakSendCancel:
	case <-sess.ctx.Done():
	}
	sess.Lock()
	sess.breakSends--
	sess.Unlock()
	sess.breakSendWg.Done()
	return delivered
}

func (sess *session) handleRequests(reqs <-chan *gossh.Request) {
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
			if sess.sessReqCb != nil && !sess.sessReqCb(sess, req.Type) {
				sess.rawCmd = ""
				_ = req.Reply(false, nil)
				continue
			}

			sess.handled = true
			_ = req.Reply(true, nil)

			startConnectionWorker(sess.ctx, func() {
				sess.handler(sess)
				_ = sess.Exit(0)
			})
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
			if sess.sessReqCb != nil && !sess.sessReqCb(sess, req.Type) {
				sess.subsystem = ""
				_ = req.Reply(false, nil)
				continue
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
			_ = req.Reply(true, nil)

			startConnectionWorker(sess.ctx, func() {
				handler(sess)
				_ = sess.Exit(0)
			})
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
			var payload struct{ Signal string }
			if err := gossh.Unmarshal(req.Payload, &payload); err != nil {
				continue
			}
			sess.Lock()
			sigCh := sess.sigCh
			var sigSendCancel <-chan struct{}
			if sigCh == nil {
				if len(sess.sigBuf) < maxSigBufSize {
					sess.sigBuf = append(sess.sigBuf, Signal(payload.Signal))
				}
			} else {
				sigSendCancel = sess.sigSendCancel
				sess.sigSendWg.Add(1)
			}
			sess.Unlock()
			if sigCh != nil {
				contextDone := false
				select {
				case sigCh <- Signal(payload.Signal):
				case <-sigSendCancel:
				case <-sess.ctx.Done():
					contextDone = true
				}
				sess.sigSendWg.Done()
				if contextDone {
					return
				}
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
				ok := sess.ptyCb(sess.ctx, ptyReq)
				if !ok {
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
			// TODO: option/callback to allow agent forwarding
			SetAgentRequested(sess.ctx)
			_ = req.Reply(true, nil)
		case "break":
			ok := sess.deliverBreak()
			_ = req.Reply(ok, nil)
		default:
			sess.getLogger().
				With("request", req.Type).
				Debug("unknown request")
			_ = req.Reply(false, nil)
		}
	}
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
