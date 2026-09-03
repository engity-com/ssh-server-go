package ssh

import (
	"context"
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

// Handler is a callback for handling established SSH sessions. A returned error
// is passed to ErrorHandler. Unless it is handled with canContinue set to true,
// the server attempts to end the session with exit status 1. An explicit prior
// call to Session.Exit takes precedence, and closing the connection from the
// ErrorResponder can prevent delivery of an automatic exit status. A returned
// SessionExitError requests a controlled message and exit status without
// invoking ErrorHandler when both can be delivered successfully.
type Handler func(Session) error

// BannerHandler resolves the server banner for a connection. A returned error
// aborts the SSH handshake.
type BannerHandler func(ctx Context, conn gossh.ConnMetadata) (string, error)

// PublicKeyHandler is a callback for performing public key authentication.
// Returning false, nil denies the authentication attempt. A non-nil error
// aborts the SSH handshake.
type PublicKeyHandler func(ctx Context, conn gossh.ConnMetadata, key PublicKey) (bool, error)

// PasswordHandler is a callback for performing password authentication.
// Returning false, nil denies the authentication attempt. A non-nil error
// aborts the SSH handshake.
type PasswordHandler func(ctx Context, conn gossh.ConnMetadata, password string) (bool, error)

// KeyboardInteractiveHandler is a callback for performing keyboard-interactive
// authentication. Returning false, nil denies the authentication attempt. A
// non-nil error aborts the SSH handshake.
type KeyboardInteractiveHandler func(ctx Context, conn gossh.ConnMetadata, challenger gossh.KeyboardInteractiveChallenge) (bool, error)

// PtyCallback is a hook for allowing PTY sessions. The Pty contains the
// client's requested metadata; this package does not allocate or configure an
// operating-system PTY. Returning false, nil denies the request. A non-nil
// error is passed to ErrorHandler and ends the session by default.
type PtyCallback func(ctx Context, sess Session, pty Pty) (bool, error)

// SessionRequestCallback is a callback for allowing or denying SSH sessions.
// Returning false, nil denies the request. A non-nil error is passed to
// ErrorHandler and ends the session by default.
type SessionRequestCallback func(sess Session, requestType string) (bool, error)

// AgentForwardingCallback is a hook for allowing agent forwarding per session.
// A nil callback or false, nil denies agent forwarding. A non-nil error is
// passed to ErrorHandler and ends the session by default.
type AgentForwardingCallback func(ctx Context, sess Session) (bool, error)

// ConnCallback is a hook for new connections before handling.
// It allows wrapping for timeouts and limiting by returning
// the net.Conn that will be used as the underlying connection.
// Implementations must return promptly and honor Context cancellation; network
// deadlines cannot forcibly stop callback code that blocks without doing I/O.
// Returning nil, nil drops the connection without reporting an operational
// error. A non-nil error aborts the SSH handshake. A returned connection must
// own the input connection and close it when the returned connection is closed.
type ConnCallback func(ctx Context, conn net.Conn) (net.Conn, error)

// LocalPortForwardingCallback is a hook for allowing port forwarding. Returning
// false, nil denies the request; a non-nil error is passed to ErrorHandler.
type LocalPortForwardingCallback func(ctx Context, conn gossh.ConnMetadata, destinationHost string, destinationPort uint32) (bool, error)

// ReversePortForwardingCallback is a hook for allowing reverse port forwarding.
// Returning false, nil denies the request; a non-nil error is passed to
// ErrorHandler.
type ReversePortForwardingCallback func(ctx Context, conn gossh.ConnMetadata, bindHost string, bindPort uint32) (bool, error)

// LocalUnixForwardingCallback handles a direct-streamlocal@openssh.com request.
// A successful callback transfers ownership of the returned connection to the
// server. Return [ErrServerPermissionDenied] to reject the request without
// exposing an operational error to the client. Implementations must honor
// context cancellation.
type LocalUnixForwardingCallback func(ctx Context, conn gossh.ConnMetadata, socketPath string) (net.Conn, error)

// ReverseUnixForwardingCallback handles a streamlocal-forward@openssh.com
// request. A successful callback transfers ownership of the returned listener
// to the server. Close must unblock Accept. Return [ErrServerPermissionDenied]
// to reject the request without exposing an operational error to the client.
// Path validation, socket creation, permissions, and stale-file handling are
// application policy. Callbacks returning a *net.UnixListener must also choose
// appropriate unlink-on-close behavior. Implementations must honor context
// cancellation.
type ReverseUnixForwardingCallback func(ctx Context, conn gossh.ConnMetadata, socketPath string) (net.Listener, error)

// ServerConfigCallback customizes a fresh per-connection server config. A
// returned error aborts the SSH handshake. Public
// key multi-factor authentication must return PartialSuccessError from
// VerifiedPublicKeyCallback, after key ownership has been proven. Configuring a
// PasswordCallback, PublicKeyCallback, or KeyboardInteractiveCallback together
// with the corresponding high-level Server handler rejects that auth method with
// ErrServerAuthCallbackConflict rather than silently replacing either policy.
type ServerConfigCallback func(ctx Context, conn net.Conn, config *gossh.ServerConfig) error

// ConnectionFailedCallback is a hook for reporting failed connections. The
// net.Conn is likely to be closed at this point. A returned error is joined with
// the connection failure before it is passed to ErrorHandler.
type ConnectionFailedCallback func(ctx Context, conn net.Conn, err error) error

// DisconnectCallback is called exactly once after a successfully established
// SSH connection ends. The Context is canceled, the connection is closed, and
// connection workers have stopped before the callback runs. Implementations must
// return promptly. A returned error is passed to ErrorHandler. Panics from the
// callback are not recovered.
type DisconnectCallback func(ctx Context, conn net.Conn) error

// Window represents the informational dimensions of a PTY window. Width and
// Height are measured in characters; WidthPixels and HeightPixels describe the
// drawable area. A zero value in an initial PTY request means unspecified. A
// zero value in a later window change leaves that dimension unchanged.
type Window struct {
	Width        int
	Height       int
	WidthPixels  int
	HeightPixels int
}

// Pty represents the metadata in an accepted PTY request. This package exposes
// the requested values but does not allocate or configure an operating-system
// PTY and does not interpret or apply TerminalModes.
type Pty struct {
	Term   string
	Window Window
	// TerminalModes contains the initial RFC 4254 terminal modes requested by
	// the client. Callers may modify the map; each API boundary returns a copy.
	TerminalModes gossh.TerminalModes
}

// Serve accepts incoming SSH connections on the listener l, creating a new
// connection goroutine for each. The connection goroutines read requests and
// then calls handler to handle sessions. Handler is typically nil, in which
// case the DefaultHandler is used. Canceling ctx stops this Serve scope. The
// returned error contains the context cause and may contain cleanup errors or
// ErrGracefulShutdownTimeout; callers should inspect it with errors.Is.
func Serve(ctx context.Context, l net.Listener, handler Handler, options ...Option) error {
	srv := &Server{Handler: handler}
	for _, option := range options {
		if err := srv.SetOption(option); err != nil {
			return err
		}
	}
	return srv.Serve(ctx, l)
}

// ListenAndServe listens on the TCP network address addr and then calls Serve
// with handler to handle sessions on incoming connections. Handler is typically
// nil, in which case the DefaultHandler is used. Canceling ctx stops the server.
// The returned error contains the context cause and may contain cleanup errors
// or ErrGracefulShutdownTimeout; callers should inspect it with errors.Is.
func ListenAndServe(ctx context.Context, addr string, handler Handler, options ...Option) error {
	srv := &Server{Addr: addr, Handler: handler}
	for _, option := range options {
		if err := srv.SetOption(option); err != nil {
			return err
		}
	}
	return srv.ListenAndServe(ctx)
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
