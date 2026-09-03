package ssh

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/echocat/slf4g"
	"github.com/echocat/slf4g/names"
	gossh "golang.org/x/crypto/ssh"
)

var (
	// ErrGracefulShutdownTimeout is joined into the returned error when a
	// context-triggered graceful shutdown exceeds its configured period.
	ErrGracefulShutdownTimeout = errors.New("ssh: graceful shutdown timeout")

	ErrServerPermissionDenied     = errors.New("permission denied")
	ErrServerHostSignerRequired   = errors.New("ssh: at least one persistent host signer is required")
	ErrServerClientAuthRequired   = errors.New("ssh: at least one client authentication method is required")
	ErrServerAuthCallbackConflict = errors.New("ssh: conflicting authentication callbacks")
	ErrChannelResponseAlreadySent = errors.New("ssh: channel response was already sent")
	ErrChannelResponseNotSent     = errors.New("ssh: channel handler returned without accepting or rejecting the channel")
)

// SubsystemHandler handles a named SSH subsystem. Returned errors have the same
// ErrorHandler and exit-status semantics as Handler errors.
type SubsystemHandler func(s Session) error

// DefaultSubsystemHandlers is used by servers with nil SubsystemHandlers. It
// must not be mutated while any such server is serving connections.
var DefaultSubsystemHandlers = map[string]SubsystemHandler{}

// DefaultRequestHandlers is used by servers with nil RequestHandlers. It must
// not be mutated while any such server is serving connections.
var DefaultRequestHandlers = map[string]RequestHandler{}

// ChannelHandler handles one channel synchronously. It should not return until
// ownership of the channel and its associated resources has ended. Returning
// an error reports it to ErrorHandler.
type ChannelHandler func(srv *Server, conn *gossh.ServerConn, newChan gossh.NewChannel, ctx Context) error

type trackedNewChannel struct {
	gossh.NewChannel
	mu              sync.Mutex
	answerAttempted bool
	answerComplete  bool
	answerErr       error
	accepted        gossh.Channel
}

func (c *trackedNewChannel) Accept() (gossh.Channel, <-chan *gossh.Request, error) {
	if !c.beginAnswer() {
		return nil, nil, ErrChannelResponseAlreadySent
	}
	channel, requests, err := c.NewChannel.Accept()
	if err != nil {
		err = locateError(ErrorScopeChannel, ErrorOperationAccept, err)
	}
	c.completeAccept(channel, err)
	return channel, requests, err
}

func (c *trackedNewChannel) Reject(reason gossh.RejectionReason, message string) error {
	if !c.beginAnswer() {
		return ErrChannelResponseAlreadySent
	}
	err := c.NewChannel.Reject(reason, message)
	if err != nil {
		err = locateError(ErrorScopeChannel, ErrorOperationReply, err)
	}
	c.completeAnswer(err)
	return err
}

func (c *trackedNewChannel) beginAnswer() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.answerAttempted {
		return false
	}
	c.answerAttempted = true
	return true
}

func (c *trackedNewChannel) completeAnswer(err error) {
	c.mu.Lock()
	c.answerComplete = true
	c.answerErr = err
	c.mu.Unlock()
}

func (c *trackedNewChannel) completeAccept(channel gossh.Channel, err error) {
	c.mu.Lock()
	c.answerComplete = true
	c.answerErr = err
	if err == nil {
		c.accepted = channel
	}
	c.mu.Unlock()
}

func (c *trackedNewChannel) closeAccepted() {
	c.mu.Lock()
	accepted := c.accepted
	c.accepted = nil
	c.mu.Unlock()
	closeQuietly(accepted)
}

func (c *trackedNewChannel) respondToError(message []byte) error {
	if !c.beginAnswer() {
		return ErrErrorResponseUnsupported
	}
	err := c.NewChannel.Reject(gossh.ConnectionFailed, string(message))
	c.completeAnswer(err)
	return err
}

func (c *trackedNewChannel) rejectUnhandledError() {
	if !c.beginAnswer() {
		return
	}
	c.completeAnswer(c.NewChannel.Reject(gossh.ConnectionFailed, "connection failed"))
}

func (c *trackedNewChannel) answerResult() (attempted bool, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.answerAttempted && !c.answerComplete {
		return true, errErrorResponseIncomplete
	}
	return c.answerAttempted, c.answerErr
}

// DefaultChannelHandlers is used by servers with nil ChannelHandlers. It must
// not be mutated while any such server is serving connections.
var DefaultChannelHandlers = map[string]ChannelHandler{
	"session": DefaultSessionHandler,
}

// GracefulShutdownHandler determines how long a context-triggered shutdown
// waits for connections to drain before closing them. A returned error forces
// immediate shutdown.
type GracefulShutdownHandler func(context.Context) (time.Duration, error)

const (
	DefaultHandshakeTimeout                = 2 * time.Minute
	DefaultIdleTimeout                     = time.Duration(0)
	DefaultMaxTimeout                      = time.Duration(0)
	DefaultSessionRequestTimeout           = 30 * time.Second
	DefaultMaxStartupsStart                = 10
	DefaultMaxStartupsRate                 = 30
	DefaultMaxStartupsFull                 = 100
	DefaultMaxSessionsPerConnection        = 10
	DefaultMaxChannelsPerConnection        = 64
	DefaultMaxReverseForwardsPerConnection = 16
	DefaultMaxConnections                  = 256
	DefaultMaxChannels                     = 64
	DefaultMaxReverseForwards              = 256
	defaultMaxConcurrentErrorHandlers      = 64
)

// MaxStartupsConfig limits concurrent unauthenticated connections using the
// OpenSSH start:rate:full random early-drop model.
type MaxStartupsConfig struct {
	Start int // number of unauthenticated connections before random early drop begins
	Rate  int // initial drop probability in percent, clamped to 0..100
	Full  int // hard limit for unauthenticated connections; nonpositive disables the limit
}

// Server configures an SSH server. Its zero value is valid and does not require
// client authentication.
//
// Configure Server and its referenced values before the first [Server.Serve] or
// [Server.HandleConn] call. It must not be copied or modified after first use,
// but may be reused concurrently. Each call owns independent runtime state and
// limits.
type Server struct {
	Logger log.Logger

	Addr                   string                 // TCP address to listen on, ":22" if empty
	Handler                Handler                // handler to invoke, ssh.DefaultHandler if nil
	HostSigners            []Signer               // private keys for the host key, must have at least one
	RequireHostSigners     bool                   // reject startup without an explicitly configured host signer
	RequireClientAuth      bool                   // reject connections without an effective, non-anonymous client authentication method
	Version                string                 // server version to be sent before the initial handshake
	Ciphers                Ciphers                // allowed ciphers, DefaultCiphers if empty
	KeyExchanges           KeyExchanges           // allowed key exchanges, DefaultKeyExchanges if empty
	MessageAuthentications MessageAuthentications // allowed MACs, DefaultMessageAuthentications if empty

	BannerHandler                 BannerHandler                 // server banner handler
	KeyboardInteractiveHandler    KeyboardInteractiveHandler    // keyboard-interactive authentication handler
	PasswordHandler               PasswordHandler               // password authentication handler
	PublicKeyHandler              PublicKeyHandler              // public key authentication handler
	PtyCallback                   PtyCallback                   // callback for allowing PTY sessions, allows all if nil
	ConnCallback                  ConnCallback                  // optional callback for wrapping net.Conn before handling
	LocalPortForwardingCallback   LocalPortForwardingCallback   // callback for allowing local port forwarding, denies all if nil
	ReversePortForwardingCallback ReversePortForwardingCallback // callback for allowing reverse port forwarding, denies all if nil
	LocalUnixForwardingCallback   LocalUnixForwardingCallback   // callback for local Unix forwarding, denies all if nil
	ReverseUnixForwardingCallback ReverseUnixForwardingCallback // callback for reverse Unix forwarding, denies all if nil
	ServerConfigCallback          ServerConfigCallback          // callback for detailed SSH options; same-method auth conflicts are rejected
	SessionRequestCallback        SessionRequestCallback        // callback for allowing or denying SSH sessions
	AgentForwardingCallback       AgentForwardingCallback       // callback for allowing agent forwarding, denies all if nil

	ConnectionFailedCallback ConnectionFailedCallback // callback to report connection failures
	DisconnectCallback       DisconnectCallback       // callback after an established SSH connection ends
	ErrorHandler             ErrorHandler             // central callback for operational server and handler errors
	// GracefulShutdownHandler determines how long a context-triggered shutdown
	// waits for connections to drain before closing them. It is called once with
	// the original canceled context after the listener has been closed and must
	// return promptly. Nil or a nonpositive result disables graceful shutdown.
	GracefulShutdownHandler GracefulShutdownHandler

	// ProxyProtocol enables PROXY protocol processing when non-nil. Connection
	// wrapping occurs before ConnCallback and the SSH handshake. Do not pass
	// connections already wrapped by go-proxyproto when this is configured.
	ProxyProtocol *ProxyProtocolConfig

	// Timeout fields use their Default* value when nil. A configured duration
	// less than or equal to zero disables that timeout.
	HandshakeTimeout *time.Duration // timeout until successful authentication, default 2 minutes
	IdleTimeout      *time.Duration // timeout when no activity, disabled by default
	MaxTimeout       *time.Duration // absolute connection timeout, disabled by default
	// SessionRequestTimeout limits how long an accepted session channel may wait
	// for shell, exec, or subsystem. The default is 30 seconds.
	SessionRequestTimeout *time.Duration

	// Limit fields use their Default* value when nil. A configured value less
	// than or equal to zero disables that limit, meaning no limit is enforced.
	// MaxStartups is disabled when Full is less than or equal to zero.
	MaxStartups                     *MaxStartupsConfig
	MaxSessionsPerConnection        *int
	MaxChannelsPerConnection        *int
	MaxReverseForwardsPerConnection *int
	MaxConnections                  *int // authenticated connections per Serve or HandleConn call
	MaxChannels                     *int // active channels per Serve or HandleConn call
	MaxReverseForwards              *int // active reverse-forward listeners per Serve or HandleConn call

	// ChannelHandlers allow overriding the built-in session handlers or provide
	// extensions to the protocol, such as tcpip forwarding. By default, only the
	// "session" handler is enabled.
	ChannelHandlers map[string]ChannelHandler

	// RequestHandlers allow overriding the server-level request handlers or
	// provide extensions to the protocol, such as tcpip forwarding. By default,
	// no handlers are enabled.
	RequestHandlers map[string]RequestHandler

	// SubsystemHandlers are handlers which are similar to the usual SSH command
	// handlers, but handle named subsystems.
	SubsystemHandlers map[string]SubsystemHandler

	prepareOnce          sync.Once
	prepareDone          chan struct{}
	prepareErr           error
	generatedHostSigners []Signer
}

func (srv *Server) prepare(ctx context.Context) error {
	srv.prepareOnce.Do(func() {
		srv.prepareDone = make(chan struct{})
		go func() {
			defer close(srv.prepareDone)
			if len(srv.HostSigners) != 0 {
				return
			}
			if srv.RequireHostSigners {
				srv.prepareErr = ErrServerHostSignerRequired
				return
			}
			signer, err := generateSigner()
			if err != nil {
				srv.prepareErr = err
				return
			}
			srv.generatedHostSigners = []Signer{signer}
		}()
	})
	select {
	case <-srv.prepareDone:
		return srv.prepareErr
	case <-ctx.Done():
		return context.Cause(ctx)
	}
}

func (srv *Server) handler() Handler {
	if srv.Handler != nil {
		return srv.Handler
	}
	return getDefaultHandler()
}

func (srv *Server) channelHandlers() map[string]ChannelHandler {
	if srv.ChannelHandlers != nil {
		return srv.ChannelHandlers
	}
	return DefaultChannelHandlers
}

func (srv *Server) requestHandlers() map[string]RequestHandler {
	if srv.RequestHandlers != nil {
		return srv.RequestHandlers
	}
	return DefaultRequestHandlers
}

func (srv *Server) subsystemHandlers() map[string]SubsystemHandler {
	if srv.SubsystemHandlers != nil {
		return srv.SubsystemHandlers
	}
	return DefaultSubsystemHandlers
}

func (srv *Server) hostSigners() []Signer {
	if len(srv.HostSigners) != 0 {
		return srv.HostSigners
	}
	return srv.generatedHostSigners
}

func (srv *Server) config(ctx Context) *gossh.ServerConfig {
	_ = srv.prepare(context.Background())
	config, _ := srv.configForConnection(ctx, nil, newHandshakeCallbackFailure(nil))
	return config
}

func (srv *Server) configForConnection(ctx Context, transport net.Conn, callbackFailure *handshakeCallbackFailure) (*gossh.ServerConfig, error) {
	config := &gossh.ServerConfig{}
	if v := srv.ServerConfigCallback; v != nil {
		if err := v(ctx, transport, config); err != nil {
			return nil, err
		}
	}
	customBannerCallback := config.BannerCallback
	customPasswordCallback := config.PasswordCallback
	customPublicKeyCallback := config.PublicKeyCallback
	customKeyboardInteractiveCallback := config.KeyboardInteractiveCallback
	ctx.SetValue(contextKeyAuthConflicts, authCallbackConflicts{
		password:            srv.PasswordHandler != nil,
		publicKey:           srv.PublicKeyHandler != nil,
		keyboardInteractive: srv.KeyboardInteractiveHandler != nil,
	})
	preAuthConnCallback := config.PreAuthConnCallback
	if preAuthConnCallback != nil {
		config.PreAuthConnCallback = func(conn gossh.ServerPreAuthConn) {
			applyConnMetadata(ctx, conn)
			preAuthConnCallback(conn)
		}
	}
	publicKeyState := &publicKeyAuthState{}
	authLogCallback := config.AuthLogCallback
	config.AuthLogCallback = func(conn gossh.ConnMetadata, method string, err error) {
		applyConnMetadata(ctx, conn)
		publicKeyState.finishAttempt(ctx, method, err)
		if authLogCallback != nil {
			authLogCallback(conn, method, err)
		}
	}
	if !srv.Ciphers.IsEmpty() || len(config.Ciphers) == 0 {
		ciphers := srv.Ciphers
		if ciphers.IsEmpty() {
			ciphers = DefaultCiphers
		}
		config.Ciphers = make([]string, len(ciphers))
		for i, cipher := range ciphers {
			config.Ciphers[i] = cipher.String()
		}
	}
	if !srv.KeyExchanges.IsEmpty() || len(config.KeyExchanges) == 0 {
		keyExchanges := srv.KeyExchanges
		if keyExchanges.IsEmpty() {
			keyExchanges = DefaultKeyExchanges
		}
		config.KeyExchanges = make([]string, len(keyExchanges))
		for i, keyExchange := range keyExchanges {
			config.KeyExchanges[i] = keyExchange.String()
		}
	}
	if !srv.MessageAuthentications.IsEmpty() || len(config.MACs) == 0 {
		messageAuthentications := srv.MessageAuthentications
		if messageAuthentications.IsEmpty() {
			messageAuthentications = DefaultMessageAuthentications
		}
		config.MACs = make([]string, len(messageAuthentications))
		for i, messageAuthentication := range messageAuthentications {
			config.MACs[i] = messageAuthentication.String()
		}
	}
	for _, signer := range srv.hostSigners() {
		config.AddHostKey(signer)
	}
	if !srv.RequireClientAuth && srv.PasswordHandler == nil && srv.PublicKeyHandler == nil && srv.KeyboardInteractiveHandler == nil &&
		config.PasswordCallback == nil && config.PublicKeyCallback == nil &&
		config.KeyboardInteractiveCallback == nil && config.GSSAPIWithMICConfig == nil {
		config.NoClientAuth = true
	}
	if srv.Version != "" {
		config.ServerVersion = "SSH-2.0-" + srv.Version
	}
	if v := srv.BannerHandler; v != nil {
		config.BannerCallback = func(conn gossh.ConnMetadata) string {
			applyConnMetadata(ctx, conn)
			banner, err := v(ctx, conn)
			if err != nil {
				_ = callbackFailure.record(err)
				return ""
			}
			return banner
		}
	} else if customBannerCallback != nil {
		config.BannerCallback = func(conn gossh.ConnMetadata) string {
			applyConnMetadata(ctx, conn)
			return customBannerCallback(conn)
		}
	}
	if config.NoClientAuth {
		noClientAuthCallback := config.NoClientAuthCallback
		config.NoClientAuthCallback = func(conn gossh.ConnMetadata) (*gossh.Permissions, error) {
			applyConnMetadata(ctx, conn)
			permissions := beginAuthAttempt(ctx)
			if noClientAuthCallback != nil {
				var err error
				permissions, err = noClientAuthCallback(conn)
				if err != nil {
					return permissions, wrapAuthError(ctx, err)
				}
			}
			publishAuthPermissions(ctx, permissions)
			return permissions, nil
		}
	}
	if v := srv.PasswordHandler; v != nil {
		if customPasswordCallback != nil {
			config.PasswordCallback = func(gossh.ConnMetadata, []byte) (*gossh.Permissions, error) {
				return nil, ErrServerAuthCallbackConflict
			}
		} else {
			config.PasswordCallback = func(conn gossh.ConnMetadata, password []byte) (*gossh.Permissions, error) {
				applyConnMetadata(ctx, conn)
				permissions := beginAuthAttempt(ctx)
				ok, err := v(ctx, conn, string(password))
				if err != nil {
					return permissions, callbackFailure.record(err)
				}
				if !ok {
					return permissions, ErrServerPermissionDenied
				}
				return permissions, nil
			}
		}
	} else if config.PasswordCallback != nil {
		config.PasswordCallback = wrapPasswordCallback(ctx, config.PasswordCallback)
	}
	if v := srv.PublicKeyHandler; v != nil {
		verifiedPublicKeyCallback := config.VerifiedPublicKeyCallback
		if customPublicKeyCallback != nil {
			config.PublicKeyCallback = func(gossh.ConnMetadata, gossh.PublicKey) (*gossh.Permissions, error) {
				return nil, ErrServerAuthCallbackConflict
			}
		} else {
			config.PublicKeyCallback = func(conn gossh.ConnMetadata, key gossh.PublicKey) (*gossh.Permissions, error) {
				applyConnMetadata(ctx, conn)
				permissions := beginAuthAttempt(ctx)
				ok, err := v(ctx, conn, key)
				if err != nil {
					return permissions, callbackFailure.record(err)
				}
				if !ok {
					return permissions, ErrServerPermissionDenied
				}
				return permissions, nil
			}
		}
		config.VerifiedPublicKeyCallback = func(conn gossh.ConnMetadata, key gossh.PublicKey, permissions *gossh.Permissions, signatureAlgorithm string) (*gossh.Permissions, error) {
			applyConnMetadata(ctx, conn)
			if verifiedPublicKeyCallback != nil {
				var err error
				permissions, err = verifiedPublicKeyCallback(conn, key, permissions, signatureAlgorithm)
				if err != nil {
					publicKeyState.recordVerified(key, err)
					return permissions, wrapAuthError(ctx, err)
				}
			}
			publicKeyState.recordVerified(key, nil)
			publishAuthPermissions(ctx, permissions)
			return permissions, nil
		}
	} else {
		if v := config.PublicKeyCallback; v != nil {
			config.PublicKeyCallback = wrapPublicKeyCallback(ctx, v)
		}
		sourceVerifiedPublicKeyCallback := config.VerifiedPublicKeyCallback
		config.VerifiedPublicKeyCallback = func(conn gossh.ConnMetadata, key gossh.PublicKey, permissions *gossh.Permissions, signatureAlgorithm string) (*gossh.Permissions, error) {
			applyConnMetadata(ctx, conn)
			if sourceVerifiedPublicKeyCallback != nil {
				var err error
				permissions, err = sourceVerifiedPublicKeyCallback(conn, key, permissions, signatureAlgorithm)
				if err != nil {
					publicKeyState.recordVerified(key, err)
					return permissions, wrapAuthError(ctx, err)
				}
			}
			publicKeyState.recordVerified(key, nil)
			publishAuthPermissions(ctx, permissions)
			return permissions, nil
		}
	}
	if v := srv.KeyboardInteractiveHandler; v != nil {
		if customKeyboardInteractiveCallback != nil {
			config.KeyboardInteractiveCallback = func(gossh.ConnMetadata, gossh.KeyboardInteractiveChallenge) (*gossh.Permissions, error) {
				return nil, ErrServerAuthCallbackConflict
			}
		} else {
			config.KeyboardInteractiveCallback = func(conn gossh.ConnMetadata, challenger gossh.KeyboardInteractiveChallenge) (*gossh.Permissions, error) {
				applyConnMetadata(ctx, conn)
				permissions := beginAuthAttempt(ctx)
				ok, err := v(ctx, conn, challenger)
				if err != nil {
					return permissions, callbackFailure.record(err)
				}
				if !ok {
					return permissions, ErrServerPermissionDenied
				}
				return permissions, nil
			}
		}
	} else if config.KeyboardInteractiveCallback != nil {
		config.KeyboardInteractiveCallback = wrapKeyboardInteractiveCallback(ctx, config.KeyboardInteractiveCallback)
	}
	config.GSSAPIWithMICConfig = wrapGSSAPIWithMICConfig(ctx, config.GSSAPIWithMICConfig)
	return config, nil
}

type handshakeCallbackFailure struct {
	mu        sync.Mutex
	transport net.Conn
	err       error
}

func newHandshakeCallbackFailure(transport net.Conn) *handshakeCallbackFailure {
	return &handshakeCallbackFailure{transport: transport}
}

func (f *handshakeCallbackFailure) record(err error) error {
	if err == nil {
		return nil
	}
	f.mu.Lock()
	if f.err == nil {
		f.err = err
	}
	f.mu.Unlock()
	closeQuietly(f.transport)
	return err
}

func (f *handshakeCallbackFailure) result() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.err
}

func beginAuthAttempt(ctx Context) *gossh.Permissions {
	permissions := &gossh.Permissions{}
	publishAuthPermissions(ctx, permissions)
	return permissions
}

type publicKeyAuthState struct {
	candidate PublicKey
	pending   PublicKey
}

func (state *publicKeyAuthState) recordVerified(key PublicKey, err error) {
	if err == nil {
		state.candidate = key
		return
	}
	if _, partial := errors.AsType[*gossh.PartialSuccessError](err); partial {
		state.candidate = key
		return
	}
	state.candidate = nil
}

func (state *publicKeyAuthState) finishAttempt(ctx Context, method string, err error) {
	if method != "publickey" {
		if err == nil && state.pending != nil {
			ctx.SetValue(ContextKeyPublicKey, state.pending)
		}
		return
	}
	candidate := state.candidate
	state.candidate = nil
	if err == nil {
		if candidate != nil {
			state.pending = candidate
			ctx.SetValue(ContextKeyPublicKey, candidate)
		}
		return
	}
	if _, partial := errors.AsType[*gossh.PartialSuccessError](err); partial {
		state.pending = candidate
		ctx.SetValue(ContextKeyPublicKey, candidate)
		return
	}
	if state.pending == nil {
		ctx.SetValue(ContextKeyPublicKey, nil)
	}
}

func publishAuthPermissions(ctx Context, permissions *gossh.Permissions) {
	if permissions == nil {
		permissions = &gossh.Permissions{}
	}
	ctx.SetValue(ContextKeyPermissions, &Permissions{permissions})
}

func wrapPasswordCallback(ctx Context, callback func(gossh.ConnMetadata, []byte) (*gossh.Permissions, error)) func(gossh.ConnMetadata, []byte) (*gossh.Permissions, error) {
	return func(conn gossh.ConnMetadata, password []byte) (*gossh.Permissions, error) {
		applyConnMetadata(ctx, conn)
		beginAuthAttempt(ctx)
		permissions, err := callback(conn, password)
		if err == nil {
			publishAuthPermissions(ctx, permissions)
		}
		return permissions, wrapAuthError(ctx, err)
	}
}

func wrapPublicKeyCallback(ctx Context, callback func(gossh.ConnMetadata, gossh.PublicKey) (*gossh.Permissions, error)) func(gossh.ConnMetadata, gossh.PublicKey) (*gossh.Permissions, error) {
	return func(conn gossh.ConnMetadata, key gossh.PublicKey) (*gossh.Permissions, error) {
		applyConnMetadata(ctx, conn)
		beginAuthAttempt(ctx)
		permissions, err := callback(conn, key)
		return permissions, wrapAuthError(ctx, err)
	}
}

func wrapKeyboardInteractiveCallback(ctx Context, callback func(gossh.ConnMetadata, gossh.KeyboardInteractiveChallenge) (*gossh.Permissions, error)) func(gossh.ConnMetadata, gossh.KeyboardInteractiveChallenge) (*gossh.Permissions, error) {
	return func(conn gossh.ConnMetadata, challenger gossh.KeyboardInteractiveChallenge) (*gossh.Permissions, error) {
		applyConnMetadata(ctx, conn)
		beginAuthAttempt(ctx)
		permissions, err := callback(conn, challenger)
		if err == nil {
			publishAuthPermissions(ctx, permissions)
		}
		return permissions, wrapAuthError(ctx, err)
	}
}

func wrapGSSAPIWithMICConfig(ctx Context, config *gossh.GSSAPIWithMICConfig) *gossh.GSSAPIWithMICConfig {
	if config == nil || config.AllowLogin == nil {
		return config
	}
	result := *config
	allowLogin := config.AllowLogin
	result.AllowLogin = func(conn gossh.ConnMetadata, srcName string) (*gossh.Permissions, error) {
		applyConnMetadata(ctx, conn)
		beginAuthAttempt(ctx)
		permissions, err := allowLogin(conn, srcName)
		if err == nil {
			publishAuthPermissions(ctx, permissions)
		}
		return permissions, wrapAuthError(ctx, err)
	}
	return &result
}

func wrapAuthError(ctx Context, err error) error {
	if partial, ok := errors.AsType[*gossh.PartialSuccessError](err); ok {
		result := *partial
		result.Next = wrapAuthCallbacks(ctx, partial.Next)
		return &result
	}
	return err
}

func wrapAuthCallbacks(ctx Context, callbacks gossh.ServerAuthCallbacks) gossh.ServerAuthCallbacks {
	conflicts, _ := ctx.Value(contextKeyAuthConflicts).(authCallbackConflicts)
	if callbacks.PasswordCallback != nil {
		if conflicts.password {
			callbacks.PasswordCallback = func(gossh.ConnMetadata, []byte) (*gossh.Permissions, error) {
				return nil, ErrServerAuthCallbackConflict
			}
		} else {
			callbacks.PasswordCallback = wrapPasswordCallback(ctx, callbacks.PasswordCallback)
		}
	}
	if callbacks.PublicKeyCallback != nil {
		if conflicts.publicKey {
			callbacks.PublicKeyCallback = func(gossh.ConnMetadata, gossh.PublicKey) (*gossh.Permissions, error) {
				return nil, ErrServerAuthCallbackConflict
			}
		} else {
			callbacks.PublicKeyCallback = wrapPublicKeyCallback(ctx, callbacks.PublicKeyCallback)
		}
	}
	if callbacks.KeyboardInteractiveCallback != nil {
		if conflicts.keyboardInteractive {
			callbacks.KeyboardInteractiveCallback = func(gossh.ConnMetadata, gossh.KeyboardInteractiveChallenge) (*gossh.Permissions, error) {
				return nil, ErrServerAuthCallbackConflict
			}
		} else {
			callbacks.KeyboardInteractiveCallback = wrapKeyboardInteractiveCallback(ctx, callbacks.KeyboardInteractiveCallback)
		}
	}
	callbacks.GSSAPIWithMICConfig = wrapGSSAPIWithMICConfig(ctx, callbacks.GSSAPIWithMICConfig)
	return callbacks
}

type authCallbackConflicts struct {
	password            bool
	publicKey           bool
	keyboardInteractive bool
}

// Handle sets the Handler for the server. It must only be called before the
// server's first Serve or HandleConn call.
func (srv *Server) Handle(fn Handler) {
	srv.Handler = fn
}

// Serve accepts incoming connections on the Listener l, creating a new
// connection goroutine for each. The connection goroutines read requests and then
// calls srv.Handler to handle sessions. Canceling ctx closes the listener and
// stops this Serve scope; other concurrent Serve calls on srv are unaffected.
// Serve returns the context cause after draining or forcibly closing the
// scope's connections. Limits and ErrorHandler concurrency are independent for
// each Serve call. A forced shutdown after a positive graceful period also
// returns ErrGracefulShutdownTimeout.
func (srv *Server) Serve(ctx context.Context, l net.Listener) error {
	scope, err := srv.newServeContext(ctx, l)
	if err != nil {
		return err
	}
	defer scope.finish()

	errorHandler := scope.errorHandler
	logger := srv.Logger
	if logger == nil {
		logger = srv.logger()
	}

	var tempDelay time.Duration
	for {
		conn, acceptErr := l.Accept()
		if acceptErr != nil {
			if ctx.Err() != nil {
				return scope.shutdown(ctx)
			}
			canContinue, filteredErr := dispatchError(ctx, logger, errorHandler, ErrorScopeServer, ErrorOperationAccept, acceptErr, nil, func(ctx context.Context, logger log.Logger, es ErrorScope, eo ErrorOperation, err error) (bool, error) {
				if ne, ok := errors.AsType[net.Error](err); ok && ne.Temporary() {
					return true, nil
				}
				return false, err
			})
			if ctx.Err() != nil {
				return scope.shutdown(ctx)
			}
			if filteredErr != nil {
				return errors.Join(filteredErr, scope.force(filteredErr))
			}
			if canContinue && !isClosedError(acceptErr) {
				if !waitForRetry(ctx, &tempDelay) {
					return scope.shutdown(ctx)
				}
				continue
			}
			return scope.force(acceptErr)
		}
		tempDelay = 0
		if active := scope.trackConnection(conn); active != nil {
			go func() {
				_ = srv.handleConn(scope.parent, conn, active, true)
			}()
		}
	}
}

// HandleConn handles one connection until it finishes or ctx is canceled. It
// does not invoke ConnectionFailedCallback. Unhandled connection failures are
// returned directly; ErrorHandler can handle or transform them. On cancellation,
// the returned error contains the context cause and may contain cleanup errors
// or ErrGracefulShutdownTimeout. Limits and ErrorHandler concurrency belong to
// this HandleConn call and are not shared with Serve calls on the same Server.
func (srv *Server) HandleConn(ctx context.Context, newConn net.Conn) error {
	scope, err := srv.newServeContext(ctx, nil)
	if err != nil {
		closeQuietly(newConn)
		return err
	}
	defer scope.finish()
	active := scope.trackConnection(newConn)
	if active == nil {
		if ctx.Err() != nil {
			return scope.shutdown(ctx)
		}
		return nil
	}
	result := make(chan error, 1)
	go func() {
		result <- srv.handleConn(scope.parent, newConn, active, false)
	}()
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		select {
		case err := <-result:
			return err
		default:
			return scope.shutdown(ctx)
		}
	}
}

func (srv *Server) handleConn(parent context.Context, newConn net.Conn, active *activeConn, reportFailure bool) (resultErr error) {
	scope := active.scope
	tracked := true
	defer func() {
		if tracked {
			active.scope.untrackConnection(active)
		}
	}()
	ctx, cancelCause := newContextWithParent(parent, srv)
	cancel := func() { cancelCause(context.Canceled) }
	defer cancel()
	fail := func(conn net.Conn, err error) error {
		if reportFailure {
			if v := srv.ConnectionFailedCallback; v != nil {
				err = errors.Join(err, v(ctx, conn, err))
			}
		}
		logger := srv.Logger
		if logger == nil {
			logger = srv.logger()
		}
		defaultAction := defaultClosingConnectionErrorAction
		if reportFailure {
			defaultAction = defaultClosingConnectionAndLogErrorAction
		}
		_, err = dispatchError(ctx, logger, scope.errorHandler, ErrorScopeConnection, ErrorOperationHandshake, err, nil, defaultAction)
		return err
	}
	ctx.SetValue(contextKeyServeContext, scope)
	ctx.SetValue(contextKeyConnectionResources, active.resources)
	if !active.scope.updateCancel(active, cancelCause) {
		closeQuietly(newConn)
		return active.scope.connectionCause(active)
	}
	handshakeTimeout := configuredDuration(srv.HandshakeTimeout, DefaultHandshakeTimeout)
	var handshakeDeadline time.Time
	if handshakeTimeout > 0 {
		handshakeDeadline = active.acceptedAt.Add(handshakeTimeout)
	}
	maxTimeout := configuredDuration(srv.MaxTimeout, DefaultMaxTimeout)
	var maxDeadline time.Time
	if maxTimeout > 0 {
		maxDeadline = active.acceptedAt.Add(maxTimeout)
	}
	handshakeTimer := cancelAt(handshakeDeadline, func() {
		if active.scope.isHandshaking(active) {
			cancelCause(context.DeadlineExceeded)
		}
	})
	if handshakeTimer != nil {
		defer handshakeTimer.Stop()
	}
	maxTimer := cancelAt(maxDeadline, func() { cancelCause(context.DeadlineExceeded) })
	if maxTimer != nil {
		defer maxTimer.Stop()
	}
	if v := srv.ProxyProtocol; v != nil {
		proxyConn, err := wrapProxyProtocolConn(newConn, *v)
		if err != nil {
			closeQuietly(newConn)
			return fail(newConn, err)
		}
		newConn = proxyConn
		if !active.scope.updateConnection(active, proxyConn) {
			closeQuietly(proxyConn)
			return active.scope.connectionCause(active)
		}
	}
	_ = newConn.SetDeadline(earliestDeadline(handshakeDeadline, maxDeadline))
	if v := srv.ConnCallback; v != nil {
		cbConn, err := v(ctx, newConn)
		if err != nil {
			if cbConn != nil {
				closeQuietly(cbConn)
			} else {
				closeQuietly(newConn)
			}
			return fail(newConn, err)
		}
		if cbConn == nil {
			closeQuietly(newConn)
			return nil
		}
		newConn = cbConn
		if !active.scope.updateConnection(active, cbConn) {
			closeQuietly(cbConn)
			return active.scope.connectionCause(active)
		}
	}
	idleTimeout := configuredDuration(srv.IdleTimeout, DefaultIdleTimeout)
	conn := &serverConn{
		Conn:              newConn,
		idleTimeout:       idleTimeout,
		handshakeDeadline: handshakeDeadline,
		maxDeadline:       maxDeadline,
		closeCanceler:     cancel,
	}
	conn.updateDeadline()
	defer closeQuietly(conn)
	callbackFailure := newHandshakeCallbackFailure(conn)
	serverConfig, err := srv.configForConnection(ctx, conn, callbackFailure)
	if err != nil {
		closeQuietly(conn)
		return fail(conn, err)
	}
	if srv.RequireClientAuth && !serverConfigHasClientAuth(serverConfig) {
		err := ErrServerClientAuthRequired
		closeQuietly(conn)
		return fail(conn, err)
	}
	sshConn, chans, reqs, err := gossh.NewServerConn(conn, serverConfig)
	if err != nil {
		if callbackErr := callbackFailure.result(); callbackErr != nil {
			err = callbackErr
		}
		closeQuietly(conn)
		return fail(conn, err)
	}
	ctx.SetValue(ContextKeyConn, sshConn)
	ctx.SetValue(contextKeyCloseConnection, sync.OnceFunc(func() {
		_ = conn.SetDeadline(time.Now())
		closeQuietly(conn)
	}))
	applyConnMetadata(ctx, sshConn)
	publishAuthPermissions(ctx, sshConn.Permissions)
	connectionLimiter := resourceLimiter{
		limit:  int64(configuredLimit(srv.MaxConnections, DefaultMaxConnections)),
		active: &scope.authenticatedConnections,
	}
	connectionReserved := connectionLimiter.reserve()
	defer func() {
		if connectionReserved {
			connectionLimiter.release()
		}
	}()
	if v := srv.DisconnectCallback; v != nil {
		defer func() {
			cancel()
			closeQuietly(sshConn)
			callbackErr := v(ctx, conn)
			if callbackErr != nil {
				logger := srv.Logger
				if logger == nil {
					logger = srv.logger()
				}
				defaultAction := defaultClosingConnectionErrorAction
				if reportFailure {
					defaultAction = defaultClosingConnectionAndLogErrorAction
				}
				_, filteredErr := dispatchError(ctx, logger, scope.errorHandler, ErrorScopeConnection, ErrorOperationHandle, callbackErr, nil, defaultAction)
				resultErr = errors.Join(resultErr, filteredErr)
			}
			if tracked {
				active.scope.untrackConnection(active)
				tracked = false
			}
		}()
	}
	if !connectionReserved {
		return nil
	}
	active.scope.releaseStartup(active)
	if handshakeTimer != nil {
		handshakeTimer.Stop()
	}
	conn.clearHandshakeDeadline()
	maxSessions := configuredLimit(srv.MaxSessionsPerConnection, DefaultMaxSessionsPerConnection)
	maxChannels := configuredLimit(srv.MaxChannelsPerConnection, DefaultMaxChannelsPerConnection)
	globalChannelLimiter := &resourceLimiter{
		limit:  int64(configuredLimit(srv.MaxChannels, DefaultMaxChannels)),
		active: &scope.globalChannels,
	}
	channelLimiter := &connectionChannelLimiter{limit: int64(maxChannels), global: globalChannelLimiter}
	ctx.SetValue(contextKeyChannelLimiter, channelLimiter)
	var activeReverseForwards atomic.Int64
	globalForwardLimiter := &resourceLimiter{
		limit:  int64(configuredLimit(srv.MaxReverseForwards, DefaultMaxReverseForwards)),
		active: &scope.globalReverseForwards,
	}
	forwardLimiter := &resourceLimiter{
		limit:  int64(configuredLimit(srv.MaxReverseForwardsPerConnection, DefaultMaxReverseForwardsPerConnection)),
		active: &activeReverseForwards,
		parent: globalForwardLimiter,
	}
	ctx.SetValue(contextKeyForwardLimiter, forwardLimiter)
	workers := &connectionWorkers{}
	ctx.SetValue(contextKeyConnectionWorkers, workers)
	workers.goRun(func() {
		srv.handleRequests(ctx, reqs, scope)
	})
	var activeSessions atomic.Int64
	channelHandlers := srv.channelHandlers()
	for ch := range chans {
		handler := channelHandlers[ch.ChannelType()]
		if handler == nil {
			handler = channelHandlers["default"]
		}
		if handler == nil {
			_ = ch.Reject(gossh.UnknownChannelType, "unsupported channel type")
			continue
		}
		if !channelLimiter.reserve() {
			_ = ch.Reject(gossh.ResourceShortage, "too many open channels")
			continue
		}
		isSession := ch.ChannelType() == "session"
		sessionReserved := !isSession || maxSessions <= 0 || activeSessions.Add(1) <= int64(maxSessions)
		if !sessionReserved {
			activeSessions.Add(-1)
			channelLimiter.release()
			_ = ch.Reject(gossh.ResourceShortage, "too many open sessions")
			continue
		}
		workers.goRun(func() {
			defer func() {
				if isSession && maxSessions > 0 {
					activeSessions.Add(-1)
				}
				channelLimiter.release()
			}()
			trackedChannel := &trackedNewChannel{NewChannel: ch}
			defer trackedChannel.closeAccepted()
			handlerErr := handler(srv, sshConn, trackedChannel, ctx)
			logger := srv.Logger
			if logger == nil {
				logger = srv.logger()
			}
			logger = enrichLoggerForServerConnection(logger, sshConn)
			attempted, answerErr := trackedChannel.answerResult()
			if handlerErr == nil && !attempted {
				handlerErr = locateError(ErrorScopeChannel, ErrorOperationReply, ErrChannelResponseNotSent)
			}
			if handlerErr == nil {
				if answerErr != nil {
					dispatchErrorOrEscalate(ctx, logger, scope.errorHandler, ErrorScopeChannel, ErrorOperationReply, answerErr, nil, defaultLogAndFailErrorAction)
					closeQuietly(sshConn)
				}
				return
			}
			response := newErrorResponse(func(message []byte, closeAfterResponse bool) error {
				if closeAfterResponse {
					defer closeQuietly(sshConn)
				}
				return trackedChannel.respondToError(message)
			})
			defaultAction := func(ctx context.Context, logger log.Logger, scope ErrorScope, operation ErrorOperation, err error) (bool, error) {
				attempted, responseErr := response.result()
				if !attempted {
					responseErr = response.send([]byte("connection failed"), false)
				}
				_, _ = defaultLogAndFailErrorAction(ctx, logger, scope, operation, err)
				if responseErr != nil && !errors.Is(responseErr, ErrErrorResponseUnsupported) {
					return false, responseErr
				}
				return true, nil
			}
			canContinue, dispatchErr := dispatchError(
				ctx,
				logger,
				scope.errorHandler,
				ErrorScopeChannel,
				ErrorOperationHandle,
				handlerErr,
				response,
				defaultAction,
			)
			attempted, responseErr := response.result()
			if !attempted {
				trackedChannel.rejectUnhandledError()
			}
			_, answerErr = trackedChannel.answerResult()
			if answerErr != nil {
				if dispatchErr != nil && errors.Is(dispatchErr, answerErr) {
					scope, operation := resolveErrorLocation(ErrorScopeChannel, ErrorOperationReply, answerErr)
					logDispatchErrorEscalate(logger, scope, operation, dispatchErr, handlerErr)
				} else if !errors.Is(handlerErr, answerErr) {
					dispatchErrorOrEscalate(ctx, logger, scope.errorHandler, ErrorScopeChannel, ErrorOperationReply, answerErr, nil, defaultLogAndFailErrorAction)
				}
				closeQuietly(sshConn)
			} else if dispatchErr != nil {
				logDispatchErrorEscalate(logger, ErrorScopeChannel, ErrorOperationHandle, dispatchErr, handlerErr)
				closeQuietly(sshConn)
			} else if responseErr != nil && !errors.Is(responseErr, ErrErrorResponseUnsupported) {
				logDispatchErrorEscalate(logger, ErrorScopeChannel, ErrorOperationReply, responseErr, handlerErr)
				closeQuietly(sshConn)
			} else if !canContinue {
				closeQuietly(sshConn)
			}
		})
	}
	cancel()
	closeQuietly(sshConn)
	active.resources.closeAll()
	active.scope.untrackConnection(active)
	tracked = false
	workers.closeAndWait()
	return nil
}

func serverConfigHasClientAuth(config *gossh.ServerConfig) bool {
	return !config.NoClientAuth && (config.PasswordCallback != nil || config.PublicKeyCallback != nil ||
		config.KeyboardInteractiveCallback != nil || config.GSSAPIWithMICConfig != nil &&
		config.GSSAPIWithMICConfig.AllowLogin != nil && config.GSSAPIWithMICConfig.Server != nil)
}

type connectionChannelLimiter struct {
	limit  int64
	active atomic.Int64
	global *resourceLimiter
}

func (l *connectionChannelLimiter) reserve() bool {
	if l == nil {
		return true
	}
	if l.limit > 0 && l.active.Add(1) > l.limit {
		l.active.Add(-1)
		return false
	}
	if l.global != nil && !l.global.reserve() {
		if l.limit > 0 {
			l.active.Add(-1)
		}
		return false
	}
	return true
}

func (l *connectionChannelLimiter) release() {
	if l != nil && l.limit > 0 {
		l.active.Add(-1)
	}
	if l != nil && l.global != nil {
		l.global.release()
	}
}

type resourceLimiter struct {
	limit  int64
	active *atomic.Int64
	parent *resourceLimiter
}

func (l *resourceLimiter) reserve() bool {
	if l == nil {
		return true
	}
	localReserved := false
	if l.limit > 0 && l.active != nil {
		if l.active.Add(1) > l.limit {
			l.active.Add(-1)
			return false
		}
		localReserved = true
	}
	if l.parent != nil && !l.parent.reserve() {
		if localReserved {
			l.active.Add(-1)
		}
		return false
	}
	return true
}

func (l *resourceLimiter) release() {
	if l != nil && l.limit > 0 && l.active != nil {
		l.active.Add(-1)
	}
	if l != nil && l.parent != nil {
		l.parent.release()
	}
}

func configuredDuration(value *time.Duration, defaultValue time.Duration) time.Duration {
	if value == nil {
		return defaultValue
	}
	if *value <= 0 {
		return 0
	}
	return *value
}

func earliestDeadline(deadlines ...time.Time) time.Time {
	var result time.Time
	for _, deadline := range deadlines {
		if !deadline.IsZero() && (result.IsZero() || deadline.Before(result)) {
			result = deadline
		}
	}
	return result
}

func cancelAt(deadline time.Time, cancel context.CancelFunc) *time.Timer {
	if deadline.IsZero() {
		return nil
	}
	return time.AfterFunc(time.Until(deadline), cancel)
}

func waitForRetry(ctx context.Context, delay *time.Duration) bool {
	if *delay == 0 {
		*delay = 5 * time.Millisecond
	} else {
		*delay *= 2
	}
	if *delay > time.Second {
		*delay = time.Second
	}
	timer := time.NewTimer(*delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func configuredLimit(value *int, defaultValue int) int {
	if value == nil {
		return defaultValue
	}
	if *value <= 0 {
		return 0
	}
	return *value
}

func (srv *Server) handleRequests(ctx Context, in <-chan *gossh.Request, scope *serveContext) {
	requestHandlers := srv.requestHandlers()
	for raw := range in {
		request := newRequest(ctx, srv, raw)
		handler := requestHandlers[request.Type]
		if handler == nil {
			handler = requestHandlers["default"]
		}
		if handler == nil {
			err := request.response.respond(false, nil, false)
			request.response.expire()
			request.response.release()
			if err != nil {
				srv.handleRequestReplyError(ctx, scope, err)
				return
			}
			continue
		}

		handlerErr := handler(request.response, request)
		request.response.expire()
		attempted, _, _, _ := request.response.result()
		if handlerErr == nil && !attempted && request.wantReply {
			handlerErr = locateError(ErrorScopeRequest, ErrorOperationReply, ErrRequestResponseNotSent)
		}

		canContinue := true
		if handlerErr != nil {
			response := newErrorResponse(func(message []byte, closeAfterResponse bool) error {
				if closeAfterResponse {
					defer closeSSHConnection(ctx)
				}
				if !request.wantReply {
					return ErrErrorResponseUnsupported
				}
				return request.response.rejectFromErrorHandler(message)
			})
			logger := srv.Logger
			if logger == nil {
				logger = srv.logger()
			}

			var dispatchErr error
			defaultAction := func(ctx context.Context, logger log.Logger, scope ErrorScope, operation ErrorOperation, err error) (bool, error) {
				attempted, responseErr := response.result()
				if !attempted {
					responseErr = response.send(nil, false)
				}
				_, _ = defaultLogAndFailErrorAction(ctx, logger, scope, operation, err)
				if responseErr != nil && !errors.Is(responseErr, ErrErrorResponseUnsupported) {
					return false, responseErr
				}
				return true, nil
			}
			canContinue, dispatchErr = dispatchError(ctx, logger, scope.errorHandler, ErrorScopeRequest, ErrorOperationHandle, handlerErr, response, defaultAction)
			if dispatchErr != nil {
				scope, operation := resolveErrorLocation(ErrorScopeRequest, ErrorOperationHandle, handlerErr)
				logDispatchErrorEscalate(logger, scope, operation, dispatchErr, handlerErr)
				closeSSHConnection(ctx)
				request.response.completeWithoutResponse()
				request.response.release()
				return
			}
		}

		attempted, complete, _, responseErr := request.response.result()
		if attempted && !complete {
			responseErr = ErrRequestResponseIncomplete
		}
		if responseErr != nil {
			request.response.release()
			if handlerErr == nil || !errors.Is(handlerErr, responseErr) {
				srv.handleRequestReplyError(ctx, scope, responseErr)
			} else {
				// The handler already returned this reply failure through ErrorHandler.
				closeSSHConnection(ctx)
			}
			return
		}
		if !attempted {
			if request.wantReply {
				responseErr = request.response.respond(false, nil, false)
			} else {
				request.response.completeWithoutResponse()
			}
			if responseErr != nil {
				request.response.release()
				srv.handleRequestReplyError(ctx, scope, responseErr)
				return
			}
		}
		request.response.release()
		if !canContinue {
			closeSSHConnection(ctx)
			return
		}
	}
}

func (srv *Server) handleRequestReplyError(ctx Context, scope *serveContext, err error) {
	logger := srv.Logger
	if logger == nil {
		logger = srv.logger()
	}
	dispatchErrorOrEscalate(ctx, logger, scope.errorHandler, ErrorScopeRequest, ErrorOperationReply, err, nil, defaultClosingConnectionAndLogErrorAction)
	// A failed reply leaves the global request stream in an unusable state even
	// when the ErrorHandler otherwise permits continuation.
	closeSSHConnection(ctx)
}

// ListenAndServe listens on the TCP network address srv.Addr and then calls
// Serve with ctx to handle incoming connections. If srv.Addr is blank, ":22"
// is used. Its return value has the same error semantics as Serve.
func (srv *Server) ListenAndServe(ctx context.Context) error {
	addr := srv.Addr
	if addr == "" {
		addr = ":22"
	}
	ln, err := new(net.ListenConfig).Listen(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	return srv.Serve(ctx, ln)
}

// AddHostKey adds a private key as a host key. If an existing host key exists
// with the same algorithm, it is overwritten. Each server config must have at
// least one host key. It must only be called before the server's first Serve or
// HandleConn call.
func (srv *Server) AddHostKey(key Signer) {
	// these are later added via AddHostKey on ServerConfig, which performs the
	// check for one of every algorithm.

	// This check is based on the AddHostKey method from the x/crypto/ssh
	// library. This allows us to only keep one active key for each type on a
	// server at once, so repeated setup calls do not grow this list.
	for i, k := range srv.HostSigners {
		if k.PublicKey().Type() == key.PublicKey().Type() {
			srv.HostSigners[i] = key
			return
		}
	}

	srv.HostSigners = append(srv.HostSigners, key)
}

// SetOption runs a functional option against the server. It must only be called
// before the server's first Serve or HandleConn call.
func (srv *Server) SetOption(option Option) error {
	return option(srv)
}

func (srv *Server) effectiveMaxStartups() MaxStartupsConfig {
	if srv.MaxStartups == nil {
		return MaxStartupsConfig{
			Start: DefaultMaxStartupsStart,
			Rate:  DefaultMaxStartupsRate,
			Full:  DefaultMaxStartupsFull,
		}
	}
	result := *srv.MaxStartups
	if result.Full <= 0 {
		return MaxStartupsConfig{}
	}
	if result.Start < 0 {
		result.Start = 0
	}
	if result.Start > result.Full {
		result.Start = result.Full
	}
	if result.Rate < 0 {
		result.Rate = 0
	} else if result.Rate > 100 {
		result.Rate = 100
	}
	return result
}

func maxStartupsDropRate(current int, config MaxStartupsConfig) int {
	if config.Full <= 0 {
		return 0
	}
	if current >= config.Full {
		return 100
	}
	if current < config.Start {
		return 0
	}
	if config.Start >= config.Full {
		return 0
	}
	return config.Rate + (100-config.Rate)*(current-config.Start)/(config.Full-config.Start)
}

func (srv *Server) logger() log.Logger {
	v := srv.Logger
	if v != nil {
		return v
	}
	return defaultServerLoggerGetter()
}

var defaultServerLoggerGetter = sync.OnceValue[log.Logger](func() log.Logger {
	return log.GetLogger(names.CurrentPackageLoggerNameGenerator(0) + ".server")
})
