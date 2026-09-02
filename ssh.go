package ssh

import (
	"crypto/subtle"
	"net"
	"sync"

	gossh "golang.org/x/crypto/ssh"
)

type Signal string

// POSIX signals as listed in RFC 4254 Section 6.10.
const (
	SIGABRT Signal = "ABRT"
	SIGALRM Signal = "ALRM"
	SIGFPE  Signal = "FPE"
	SIGHUP  Signal = "HUP"
	SIGILL  Signal = "ILL"
	SIGINT  Signal = "INT"
	SIGKILL Signal = "KILL"
	SIGPIPE Signal = "PIPE"
	SIGQUIT Signal = "QUIT"
	SIGSEGV Signal = "SEGV"
	SIGTERM Signal = "TERM"
	SIGUSR1 Signal = "USR1"
	SIGUSR2 Signal = "USR2"
)

// DefaultHandler is the default Handler used by Serve.
var DefaultHandler Handler

var defaultHandlerMu sync.RWMutex

func getDefaultHandler() Handler {
	defaultHandlerMu.RLock()
	defer defaultHandlerMu.RUnlock()
	return DefaultHandler
}

// Option is a functional option handler for Server.
type Option func(*Server) error

// Handler is a callback for handling established SSH sessions.
type Handler func(Session)

// BannerHandler is a callback for displaying the server banner.
type BannerHandler func(ctx Context) string

// PublicKeyHandler is a callback for performing public key authentication.
type PublicKeyHandler func(ctx Context, key PublicKey) bool

// PasswordHandler is a callback for performing password authentication.
type PasswordHandler func(ctx Context, password string) bool

// KeyboardInteractiveHandler is a callback for performing keyboard-interactive authentication.
type KeyboardInteractiveHandler func(ctx Context, challenger gossh.KeyboardInteractiveChallenge) bool

// PtyCallback is a hook for allowing PTY sessions.
type PtyCallback func(ctx Context, pty Pty) bool

// SessionRequestCallback is a callback for allowing or denying SSH sessions.
type SessionRequestCallback func(sess Session, requestType string) bool

// AgentForwardingCallback is a hook for allowing agent forwarding per session.
// A nil callback denies agent forwarding.
type AgentForwardingCallback func(ctx Context) bool

// ConnCallback is a hook for new connections before handling.
// It allows wrapping for timeouts and limiting by returning
// the net.Conn that will be used as the underlying connection.
// Implementations must return promptly and honor Context cancellation; network
// deadlines cannot forcibly stop callback code that blocks without doing I/O.
type ConnCallback func(ctx Context, conn net.Conn) net.Conn

// LocalPortForwardingCallback is a hook for allowing port forwarding
type LocalPortForwardingCallback func(ctx Context, destinationHost string, destinationPort uint32) bool

// ReversePortForwardingCallback is a hook for allowing reverse port forwarding
type ReversePortForwardingCallback func(ctx Context, bindHost string, bindPort uint32) bool

// ServerConfigCallback customizes a fresh per-connection server config. Public
// key multi-factor authentication must return PartialSuccessError from
// VerifiedPublicKeyCallback, after key ownership has been proven. Configuring a
// PasswordCallback, PublicKeyCallback, or KeyboardInteractiveCallback together
// with the corresponding high-level Server handler rejects that auth method with
// ErrServerAuthCallbackConflict rather than silently replacing either policy.
type ServerConfigCallback func(ctx Context, config *gossh.ServerConfig)

// ConnectionFailedCallback is a hook for reporting failed connections
// Please note: the net.Conn is likely to be closed at this point
type ConnectionFailedCallback func(conn net.Conn, err error)

// DisconnectCallback is called exactly once after a successfully established
// SSH connection ends. The Context is canceled, the connection is closed, and
// connection workers have stopped before the callback runs. Implementations must
// return promptly. Panics from the callback are not recovered.
type DisconnectCallback func(ctx Context, conn net.Conn)

// Window represents the size of a PTY window.
type Window struct {
	Width  int
	Height int
}

// Pty represents a PTY request and configuration.
type Pty struct {
	Term   string
	Window Window
	// HELP WANTED: terminal modes!
}

// Serve accepts incoming SSH connections on the listener l, creating a new
// connection goroutine for each. The connection goroutines read requests and
// then calls handler to handle sessions. Handler is typically nil, in which
// case the DefaultHandler is used.
func Serve(l net.Listener, handler Handler, options ...Option) error {
	srv := &Server{Handler: handler}
	for _, option := range options {
		if err := srv.SetOption(option); err != nil {
			return err
		}
	}
	return srv.Serve(l)
}

// ListenAndServe listens on the TCP network address addr and then calls Serve
// with handler to handle sessions on incoming connections. Handler is typically
// nil, in which case the DefaultHandler is used.
func ListenAndServe(addr string, handler Handler, options ...Option) error {
	srv := &Server{Addr: addr, Handler: handler}
	for _, option := range options {
		if err := srv.SetOption(option); err != nil {
			return err
		}
	}
	return srv.ListenAndServe()
}

// Handle registers the handler as the DefaultHandler.
func Handle(handler Handler) {
	defaultHandlerMu.Lock()
	defer defaultHandlerMu.Unlock()
	DefaultHandler = handler
}

// KeysEqual is constant time compare of the keys to avoid timing attacks.
func KeysEqual(ak, bk PublicKey) bool {
	// avoid panic if one of the keys is nil, return false instead
	if ak == nil || bk == nil {
		return false
	}

	a := ak.Marshal()
	b := bk.Marshal()
	return len(a) == len(b) && subtle.ConstantTimeCompare(a, b) == 1
}
