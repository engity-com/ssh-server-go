package ssh

import (
	"context"
	"errors"
	"io"
	"maps"
	"math/rand/v2"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/echocat/slf4g"
	"github.com/echocat/slf4g/names"
	gossh "golang.org/x/crypto/ssh"
)

var (
	// ErrServerClosed is returned by [Server.Serve] and [Server.ListenAndServe]
	// after a call to [Server.Shutdown] or [Server.Close].
	ErrServerClosed = errors.New("ssh: Server closed")

	ErrServerPermissionDenied     = errors.New("permission denied")
	ErrServerHostSignerRequired   = errors.New("ssh: at least one persistent host signer is required")
	ErrServerRunning              = errors.New("ssh: server configuration cannot be changed while running")
	ErrServerClientAuthRequired   = errors.New("ssh: at least one client authentication method is required")
	ErrServerAuthCallbackConflict = errors.New("ssh: conflicting authentication callbacks")
)

type SubsystemHandler func(s Session)

var DefaultSubsystemHandlers = map[string]SubsystemHandler{}

type RequestHandler func(ctx Context, srv *Server, req *gossh.Request) (ok bool, payload []byte)

var DefaultRequestHandlers = map[string]RequestHandler{}

// ChannelHandler handles one channel synchronously. It should not return until
// ownership of the channel and its associated resources has ended.
type ChannelHandler func(srv *Server, conn *gossh.ServerConn, newChan gossh.NewChannel, ctx Context)

var DefaultChannelHandlers = map[string]ChannelHandler{
	"session": DefaultSessionHandler,
}

const (
	DefaultHandshakeTimeout                = 2 * time.Minute
	DefaultIdleTimeout                     = time.Duration(0)
	DefaultMaxTimeout                      = time.Duration(0)
	DefaultMaxStartupsStart                = 10
	DefaultMaxStartupsRate                 = 30
	DefaultMaxStartupsFull                 = 100
	DefaultMaxSessionsPerConnection        = 10
	DefaultMaxChannelsPerConnection        = 64
	DefaultMaxReverseForwardsPerConnection = 16
	DefaultMaxConnections                  = 256
	DefaultMaxChannels                     = 1024
)

// MaxStartupsConfig limits concurrent unauthenticated connections using the
// OpenSSH start:rate:full random early-drop model.
type MaxStartupsConfig struct {
	Start int // number of unauthenticated connections before random early drop begins
	Rate  int // initial drop probability in percent, clamped to 0..100
	Full  int // hard limit for unauthenticated connections; nonpositive disables the limit
}

// Server defines parameters for running an SSH server. The zero value for
// Server is a valid configuration. When both PasswordHandler and
// PublicKeyHandler are nil, no client authentication is performed. Public
// fields and pointed-to configuration values must not be mutated while the
// server is running; use synchronized methods for supported runtime updates.
type Server struct {
	Logger log.Logger

	Addr                   string                 // TCP address to listen on, ":22" if empty
	Handler                Handler                // handler to invoke, ssh.DefaultHandler if nil
	HostSigners            []Signer               // private keys for the host key, must have at least one
	RequireHostSigners     bool                   // reject startup without an explicitly configured host signer
	RequireClientAuth      bool                   // reject connections without an effective, non-anonymous client authentication method
	Version                string                 // server version to be sent before the initial handshake
	Banner                 string                 // server banner
	Ciphers                Ciphers                // allowed ciphers, DefaultCiphers if empty
	KeyExchanges           KeyExchanges           // allowed key exchanges, DefaultKeyExchanges if empty
	MessageAuthentications MessageAuthentications // allowed MACs, DefaultMessageAuthentications if empty

	BannerHandler                 BannerHandler                 // server banner handler, overrides Banner
	KeyboardInteractiveHandler    KeyboardInteractiveHandler    // keyboard-interactive authentication handler
	PasswordHandler               PasswordHandler               // password authentication handler
	PublicKeyHandler              PublicKeyHandler              // public key authentication handler
	PtyCallback                   PtyCallback                   // callback for allowing PTY sessions, allows all if nil
	ConnCallback                  ConnCallback                  // optional callback for wrapping net.Conn before handling
	LocalPortForwardingCallback   LocalPortForwardingCallback   // callback for allowing local port forwarding, denies all if nil
	ReversePortForwardingCallback ReversePortForwardingCallback // callback for allowing reverse port forwarding, denies all if nil
	ServerConfigCallback          ServerConfigCallback          // callback for detailed SSH options; same-method auth conflicts are rejected
	SessionRequestCallback        SessionRequestCallback        // callback for allowing or denying SSH sessions
	AgentForwardingCallback       AgentForwardingCallback       // callback for allowing agent forwarding, denies all if nil

	ConnectionFailedCallback ConnectionFailedCallback // callback to report connection failures
	DisconnectCallback       DisconnectCallback       // callback after an established SSH connection ends

	// Timeout fields use their Default* value when nil. A configured duration
	// less than or equal to zero disables that timeout.
	HandshakeTimeout *time.Duration // timeout until successful authentication, default 2 minutes
	IdleTimeout      *time.Duration // timeout when no activity, disabled by default
	MaxTimeout       *time.Duration // absolute connection timeout, disabled by default

	// Limit fields use their Default* value when nil. A configured value less
	// than or equal to zero disables that limit, meaning no limit is enforced.
	// MaxStartups is disabled when Full is less than or equal to zero.
	MaxStartups                     *MaxStartupsConfig
	MaxSessionsPerConnection        *int
	MaxChannelsPerConnection        *int
	MaxReverseForwardsPerConnection *int
	MaxConnections                  *int // authenticated connections across the server
	MaxChannels                     *int // active channels across all connections

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

	configMu                 sync.Mutex
	mu                       sync.RWMutex
	generatedHostKey         PublicKey
	listeners                map[net.Listener]struct{}
	conns                    map[*gossh.ServerConn]struct{}
	activeConns              map[*activeConn]struct{}
	startups                 int
	authenticatedConnections *atomic.Int64
	globalChannels           *atomic.Int64
	configuring              bool
	doneChan                 chan struct{}
	drainedChan              chan struct{}
}

type activeConn struct {
	conn            net.Conn
	cancel          context.CancelFunc
	acceptedAt      time.Time
	handshaking     bool
	startupReserved bool
	closed          bool
}

type connectionSettings struct {
	logger                        log.Logger
	connCallback                  ConnCallback
	connectionFailedCallback      ConnectionFailedCallback
	disconnectCallback            DisconnectCallback
	handler                       Handler
	ptyCallback                   PtyCallback
	sessionRequestCallback        SessionRequestCallback
	agentForwardingCallback       AgentForwardingCallback
	localPortForwardingCallback   LocalPortForwardingCallback
	reversePortForwardingCallback ReversePortForwardingCallback
	channelHandlers               map[string]ChannelHandler
	requestHandlers               map[string]RequestHandler
	subsystemHandlers             map[string]SubsystemHandler
	handshakeTimeout              time.Duration
	idleTimeout                   time.Duration
	maxTimeout                    time.Duration
	maxConnections                int
	maxChannels                   int
	maxSessionsPerConnection      int
	maxChannelsPerConnection      int
	maxReverseForwards            int
	authenticatedConnections      *atomic.Int64
	globalChannels                *atomic.Int64
	requireClientAuth             bool
}

func (srv *Server) connectionSettings() *connectionSettings {
	srv.mu.RLock()
	defer srv.mu.RUnlock()
	channelHandlers := maps.Clone(srv.ChannelHandlers)
	if channelHandlers == nil {
		channelHandlers = maps.Clone(DefaultChannelHandlers)
	}
	requestHandlers := maps.Clone(srv.RequestHandlers)
	if requestHandlers == nil {
		requestHandlers = maps.Clone(DefaultRequestHandlers)
	}
	subsystemHandlers := maps.Clone(srv.SubsystemHandlers)
	if subsystemHandlers == nil {
		subsystemHandlers = maps.Clone(DefaultSubsystemHandlers)
	}
	handler := srv.Handler
	if handler == nil {
		handler = getDefaultHandler()
	}
	return &connectionSettings{
		logger:                        srv.Logger,
		connCallback:                  srv.ConnCallback,
		connectionFailedCallback:      srv.ConnectionFailedCallback,
		disconnectCallback:            srv.DisconnectCallback,
		handler:                       handler,
		ptyCallback:                   srv.PtyCallback,
		sessionRequestCallback:        srv.SessionRequestCallback,
		agentForwardingCallback:       srv.AgentForwardingCallback,
		localPortForwardingCallback:   srv.LocalPortForwardingCallback,
		reversePortForwardingCallback: srv.ReversePortForwardingCallback,
		channelHandlers:               channelHandlers,
		requestHandlers:               requestHandlers,
		subsystemHandlers:             subsystemHandlers,
		handshakeTimeout:              configuredDuration(srv.HandshakeTimeout, DefaultHandshakeTimeout),
		idleTimeout:                   configuredDuration(srv.IdleTimeout, DefaultIdleTimeout),
		maxTimeout:                    configuredDuration(srv.MaxTimeout, DefaultMaxTimeout),
		maxConnections:                configuredLimit(srv.MaxConnections, DefaultMaxConnections),
		maxChannels:                   configuredLimit(srv.MaxChannels, DefaultMaxChannels),
		maxSessionsPerConnection:      configuredLimit(srv.MaxSessionsPerConnection, DefaultMaxSessionsPerConnection),
		maxChannelsPerConnection:      configuredLimit(srv.MaxChannelsPerConnection, DefaultMaxChannelsPerConnection),
		maxReverseForwards:            configuredLimit(srv.MaxReverseForwardsPerConnection, DefaultMaxReverseForwardsPerConnection),
		authenticatedConnections:      srv.authenticatedConnections,
		globalChannels:                srv.globalChannels,
		requireClientAuth:             srv.RequireClientAuth,
	}
}

func (srv *Server) fallbackConnectionSettings() *connectionSettings {
	srv.mu.RLock()
	defer srv.mu.RUnlock()
	handler := srv.Handler
	if handler == nil {
		handler = getDefaultHandler()
	}
	return &connectionSettings{
		logger:                        srv.Logger,
		handler:                       handler,
		ptyCallback:                   srv.PtyCallback,
		sessionRequestCallback:        srv.SessionRequestCallback,
		agentForwardingCallback:       srv.AgentForwardingCallback,
		localPortForwardingCallback:   srv.LocalPortForwardingCallback,
		reversePortForwardingCallback: srv.ReversePortForwardingCallback,
		subsystemHandlers:             maps.Clone(srv.SubsystemHandlers),
		maxReverseForwards:            configuredLimit(srv.MaxReverseForwardsPerConnection, DefaultMaxReverseForwardsPerConnection),
	}
}

func (srv *Server) ensureHostSigner() error {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	if len(srv.HostSigners) == 0 {
		if srv.RequireHostSigners {
			return ErrServerHostSignerRequired
		}
		signer, err := generateSigner()
		if err != nil {
			return err
		}
		srv.HostSigners = append(srv.HostSigners, signer)
		srv.generatedHostKey = signer.PublicKey()
	} else if srv.RequireHostSigners && srv.onlyGeneratedHostSignersLocked() {
		return ErrServerHostSignerRequired
	}
	return nil
}

func (srv *Server) onlyGeneratedHostSignersLocked() bool {
	if srv.generatedHostKey == nil {
		return false
	}
	for _, signer := range srv.HostSigners {
		if !KeysEqual(signer.PublicKey(), srv.generatedHostKey) {
			return false
		}
	}
	return true
}

func (srv *Server) ensureHandlers() {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	if srv.RequestHandlers == nil {
		srv.RequestHandlers = maps.Clone(DefaultRequestHandlers)
		if srv.RequestHandlers == nil {
			srv.RequestHandlers = map[string]RequestHandler{}
		}
	}
	if srv.ChannelHandlers == nil {
		srv.ChannelHandlers = maps.Clone(DefaultChannelHandlers)
		if srv.ChannelHandlers == nil {
			srv.ChannelHandlers = map[string]ChannelHandler{}
		}
	}
	if srv.SubsystemHandlers == nil {
		srv.SubsystemHandlers = maps.Clone(DefaultSubsystemHandlers)
		if srv.SubsystemHandlers == nil {
			srv.SubsystemHandlers = map[string]SubsystemHandler{}
		}
	}
	if srv.Handler == nil {
		srv.Handler = getDefaultHandler()
	}
}

func (srv *Server) config(ctx Context) *gossh.ServerConfig {
	srv.mu.RLock()
	serverConfigCallback := srv.ServerConfigCallback
	ciphers := append(Ciphers(nil), srv.Ciphers...)
	keyExchanges := append(KeyExchanges(nil), srv.KeyExchanges...)
	messageAuthentications := append(MessageAuthentications(nil), srv.MessageAuthentications...)
	hostSigners := append([]Signer(nil), srv.HostSigners...)
	passwordHandler := srv.PasswordHandler
	publicKeyHandler := srv.PublicKeyHandler
	keyboardInteractiveHandler := srv.KeyboardInteractiveHandler
	version := srv.Version
	banner := srv.Banner
	bannerHandler := srv.BannerHandler
	requireClientAuth := srv.RequireClientAuth
	srv.mu.RUnlock()

	config := &gossh.ServerConfig{}
	if serverConfigCallback != nil {
		serverConfigCallback(ctx, config)
	}
	customBannerCallback := config.BannerCallback
	customPasswordCallback := config.PasswordCallback
	customPublicKeyCallback := config.PublicKeyCallback
	customKeyboardInteractiveCallback := config.KeyboardInteractiveCallback
	ctx.SetValue(contextKeyAuthConflicts, authCallbackConflicts{
		password:            passwordHandler != nil,
		publicKey:           publicKeyHandler != nil,
		keyboardInteractive: keyboardInteractiveHandler != nil,
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
	if !ciphers.IsEmpty() || len(config.Ciphers) == 0 {
		if ciphers.IsEmpty() {
			ciphers = DefaultCiphers
		}
		config.Ciphers = make([]string, len(ciphers))
		for i, cipher := range ciphers {
			config.Ciphers[i] = cipher.String()
		}
	}
	if !keyExchanges.IsEmpty() || len(config.KeyExchanges) == 0 {
		if keyExchanges.IsEmpty() {
			keyExchanges = DefaultKeyExchanges
		}
		config.KeyExchanges = make([]string, len(keyExchanges))
		for i, keyExchange := range keyExchanges {
			config.KeyExchanges[i] = keyExchange.String()
		}
	}
	if !messageAuthentications.IsEmpty() || len(config.MACs) == 0 {
		if messageAuthentications.IsEmpty() {
			messageAuthentications = DefaultMessageAuthentications
		}
		config.MACs = make([]string, len(messageAuthentications))
		for i, messageAuthentication := range messageAuthentications {
			config.MACs[i] = messageAuthentication.String()
		}
	}
	for _, signer := range hostSigners {
		config.AddHostKey(signer)
	}
	if !requireClientAuth && passwordHandler == nil && publicKeyHandler == nil && keyboardInteractiveHandler == nil &&
		config.PasswordCallback == nil && config.PublicKeyCallback == nil &&
		config.KeyboardInteractiveCallback == nil && config.GSSAPIWithMICConfig == nil {
		config.NoClientAuth = true
	}
	if version != "" {
		config.ServerVersion = "SSH-2.0-" + version
	}
	if banner != "" {
		config.BannerCallback = func(_ gossh.ConnMetadata) string {
			return banner
		}
	}
	if bannerHandler != nil {
		config.BannerCallback = func(conn gossh.ConnMetadata) string {
			applyConnMetadata(ctx, conn)
			return bannerHandler(ctx)
		}
	} else if banner == "" && customBannerCallback != nil {
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
	if passwordHandler != nil {
		if customPasswordCallback != nil {
			config.PasswordCallback = func(gossh.ConnMetadata, []byte) (*gossh.Permissions, error) {
				return nil, ErrServerAuthCallbackConflict
			}
		} else {
			config.PasswordCallback = func(conn gossh.ConnMetadata, password []byte) (*gossh.Permissions, error) {
				applyConnMetadata(ctx, conn)
				permissions := beginAuthAttempt(ctx)
				if ok := passwordHandler(ctx, string(password)); !ok {
					return permissions, ErrServerPermissionDenied
				}
				return permissions, nil
			}
		}
	} else if config.PasswordCallback != nil {
		config.PasswordCallback = wrapPasswordCallback(ctx, config.PasswordCallback)
	}
	if publicKeyHandler != nil {
		verifiedPublicKeyCallback := config.VerifiedPublicKeyCallback
		if customPublicKeyCallback != nil {
			config.PublicKeyCallback = func(gossh.ConnMetadata, gossh.PublicKey) (*gossh.Permissions, error) {
				return nil, ErrServerAuthCallbackConflict
			}
		} else {
			config.PublicKeyCallback = func(conn gossh.ConnMetadata, key gossh.PublicKey) (*gossh.Permissions, error) {
				applyConnMetadata(ctx, conn)
				permissions := beginAuthAttempt(ctx)
				if ok := publicKeyHandler(ctx, key); !ok {
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
	} else if config.PublicKeyCallback != nil {
		config.PublicKeyCallback = wrapPublicKeyCallback(ctx, config.PublicKeyCallback)
		verifiedPublicKeyCallback := config.VerifiedPublicKeyCallback
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
		verifiedPublicKeyCallback := config.VerifiedPublicKeyCallback
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
	}
	if keyboardInteractiveHandler != nil {
		if customKeyboardInteractiveCallback != nil {
			config.KeyboardInteractiveCallback = func(gossh.ConnMetadata, gossh.KeyboardInteractiveChallenge) (*gossh.Permissions, error) {
				return nil, ErrServerAuthCallbackConflict
			}
		} else {
			config.KeyboardInteractiveCallback = func(conn gossh.ConnMetadata, challenger gossh.KeyboardInteractiveChallenge) (*gossh.Permissions, error) {
				applyConnMetadata(ctx, conn)
				permissions := beginAuthAttempt(ctx)
				if ok := keyboardInteractiveHandler(ctx, challenger); !ok {
					return permissions, ErrServerPermissionDenied
				}
				return permissions, nil
			}
		}
	} else if config.KeyboardInteractiveCallback != nil {
		config.KeyboardInteractiveCallback = wrapKeyboardInteractiveCallback(ctx, config.KeyboardInteractiveCallback)
	}
	config.GSSAPIWithMICConfig = wrapGSSAPIWithMICConfig(ctx, config.GSSAPIWithMICConfig)
	return config
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
	if _, partial := err.(*gossh.PartialSuccessError); partial {
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
	if _, partial := err.(*gossh.PartialSuccessError); partial {
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
	partial, ok := err.(*gossh.PartialSuccessError)
	if !ok {
		return err
	}
	result := *partial
	result.Next = wrapAuthCallbacks(ctx, partial.Next)
	return &result
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

// Handle sets the Handler for the server.
func (srv *Server) Handle(fn Handler) {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	srv.Handler = fn
}

// Close immediately closes all active listeners and all active
// connections.
//
// Close returns any error returned from closing the Server's
// underlying Listener(s).
func (srv *Server) Close() error {
	srv.mu.Lock()
	srv.closeDoneChanLocked()
	listeners := srv.listenersLocked()
	connections := make([]io.Closer, 0, len(srv.conns)+len(srv.activeConns))
	for c := range srv.conns {
		connections = append(connections, c)
	}
	cancels := make([]context.CancelFunc, 0, len(srv.activeConns))
	for c := range srv.activeConns {
		c.closed = true
		if c.cancel != nil {
			cancels = append(cancels, c.cancel)
		}
		connections = append(connections, c.conn)
	}
	srv.maybeCloseDrainedLocked()
	srv.mu.Unlock()

	for _, cancel := range cancels {
		cancel()
	}
	err := closeListeners(listeners)
	for _, conn := range connections {
		closeQuietly(conn)
	}
	return err
}

// Shutdown gracefully shuts down the server without interrupting any
// active connections. Shutdown works by first closing all open
// listeners, and then waiting indefinitely for connections to close.
// If the provided context expires before the shutdown is complete,
// then the context's error is returned.
func (srv *Server) Shutdown(ctx context.Context) error {
	srv.mu.Lock()
	srv.closeDoneChanLocked()
	listeners := srv.listenersLocked()
	drained := srv.getDrainedChanLocked()
	srv.mu.Unlock()
	err := closeListeners(listeners)

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-drained:
		return err
	}
}

// Serve accepts incoming connections on the Listener l, creating a new
// connection goroutine for each. The connection goroutines read requests and then
// calls srv.Handler to handle sessions.
//
// Serve always returns a non-nil error.
func (srv *Server) Serve(l net.Listener) error {
	for {
		srv.waitForPreviousGeneration()
		srv.configMu.Lock()
		srv.ensureHandlers()
		if err := srv.ensureHostSigner(); err != nil {
			srv.configMu.Unlock()
			closeQuietly(l)
			return err
		}
		if srv.trackListener(l, true) {
			srv.configMu.Unlock()
			break
		}
		srv.configMu.Unlock()
	}
	defer closeQuietly(l)
	var tempDelay time.Duration

	defer srv.trackListener(l, false)
	for {
		conn, e := l.Accept()
		if e != nil {
			select {
			case <-srv.getDoneChan():
				return ErrServerClosed
			default:
			}
			if ne, ok := errors.AsType[net.Error](e); ok && ne.Temporary() {
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if v := 1 * time.Second; tempDelay > v {
					tempDelay = v
				}
				time.Sleep(tempDelay)
				continue
			}
			return e
		}
		if active := srv.trackActiveConn(conn, false); active != nil {
			go srv.handleConn(conn, active)
		}
	}
}

func (srv *Server) HandleConn(newConn net.Conn) {
	active := srv.trackActiveConn(newConn, true)
	if active == nil {
		return
	}
	srv.configMu.Lock()
	srv.ensureHandlers()
	if err := srv.ensureHostSigner(); err != nil {
		srv.mu.RLock()
		connectionFailedCallback := srv.ConnectionFailedCallback
		srv.mu.RUnlock()
		srv.configMu.Unlock()
		srv.untrackActiveConn(active)
		closeQuietly(newConn)
		if connectionFailedCallback != nil {
			connectionFailedCallback(newConn, err)
		}
		return
	}
	settings := srv.connectionSettings()
	srv.configMu.Unlock()
	srv.handleConn(newConn, active, settings)
}

func (srv *Server) handleConn(newConn net.Conn, active *activeConn, settings ...*connectionSettings) {
	tracked := true
	defer func() {
		if tracked {
			srv.untrackActiveConn(active)
		}
	}()
	ctx, cancel := newContext(srv)
	defer cancel()
	connectionSettings := srv.connectionSettings()
	if len(settings) > 0 {
		connectionSettings = settings[0]
	}
	ctx.SetValue(contextKeyServerSettings, connectionSettings)
	if !srv.updateActiveCancel(active, cancel) {
		closeQuietly(newConn)
		return
	}
	handshakeTimeout := connectionSettings.handshakeTimeout
	var handshakeDeadline time.Time
	if handshakeTimeout > 0 {
		handshakeDeadline = active.acceptedAt.Add(handshakeTimeout)
	}
	maxTimeout := connectionSettings.maxTimeout
	var maxDeadline time.Time
	if maxTimeout > 0 {
		maxDeadline = active.acceptedAt.Add(maxTimeout)
	}
	handshakeTimer := cancelAt(handshakeDeadline, func() {
		srv.mu.RLock()
		handshaking := active.handshaking
		srv.mu.RUnlock()
		if handshaking {
			cancel()
		}
	})
	if handshakeTimer != nil {
		defer handshakeTimer.Stop()
	}
	maxTimer := cancelAt(maxDeadline, cancel)
	if maxTimer != nil {
		defer maxTimer.Stop()
	}
	_ = newConn.SetDeadline(earliestDeadline(handshakeDeadline, maxDeadline))
	if connectionSettings.connCallback != nil {
		cbConn := connectionSettings.connCallback(ctx, newConn)
		if cbConn == nil {
			closeQuietly(newConn)
			return
		}
		newConn = cbConn
		if !srv.updateActiveConn(active, cbConn) {
			closeQuietly(cbConn)
			return
		}
	}
	idleTimeout := connectionSettings.idleTimeout
	conn := &serverConn{
		Conn:              newConn,
		idleTimeout:       idleTimeout,
		handshakeDeadline: handshakeDeadline,
		maxDeadline:       maxDeadline,
		closeCanceler:     cancel,
	}
	conn.updateDeadline()
	defer closeQuietly(conn)
	serverConfig := srv.config(ctx)
	if connectionSettings.requireClientAuth && !serverConfigHasClientAuth(serverConfig) {
		err := ErrServerClientAuthRequired
		srv.releaseStartup(active)
		closeQuietly(conn)
		srv.untrackActiveConn(active)
		tracked = false
		if connectionSettings.connectionFailedCallback != nil {
			connectionSettings.connectionFailedCallback(conn, err)
		}
		return
	}
	sshConn, chans, reqs, err := gossh.NewServerConn(conn, serverConfig)
	if err != nil {
		srv.releaseStartup(active)
		closeQuietly(conn)
		srv.untrackActiveConn(active)
		tracked = false
		if connectionSettings.connectionFailedCallback != nil {
			connectionSettings.connectionFailedCallback(conn, err)
		}
		return
	}
	srv.releaseStartup(active)
	ctx.SetValue(ContextKeyConn, sshConn)
	applyConnMetadata(ctx, sshConn)
	publishAuthPermissions(ctx, sshConn.Permissions)
	if connectionSettings.disconnectCallback != nil {
		defer func() {
			cancel()
			closeQuietly(sshConn)
			srv.untrackActiveConn(active)
			tracked = false
			connectionSettings.disconnectCallback(ctx, conn)
		}()
	}
	connectionLimiter := resourceLimiter{
		limit:  int64(connectionSettings.maxConnections),
		active: connectionSettings.authenticatedConnections,
	}
	if !connectionLimiter.reserve() {
		return
	}
	defer connectionLimiter.release()
	if handshakeTimer != nil {
		handshakeTimer.Stop()
	}
	conn.clearHandshakeDeadline()
	srv.trackConn(sshConn, true)
	defer srv.trackConn(sshConn, false)

	maxSessions := connectionSettings.maxSessionsPerConnection
	maxChannels := connectionSettings.maxChannelsPerConnection
	globalChannelLimiter := &resourceLimiter{
		limit:  int64(connectionSettings.maxChannels),
		active: connectionSettings.globalChannels,
	}
	channelLimiter := &connectionChannelLimiter{limit: int64(maxChannels), global: globalChannelLimiter}
	ctx.SetValue(contextKeyChannelLimiter, channelLimiter)
	workers := &connectionWorkers{}
	ctx.SetValue(contextKeyConnectionWorkers, workers)
	workers.goRun(func() {
		srv.handleRequests(ctx, reqs, connectionSettings.requestHandlers)
	})
	var activeSessions atomic.Int64
	for ch := range chans {
		handler := connectionSettings.channelHandlers[ch.ChannelType()]
		if handler == nil {
			handler = connectionSettings.channelHandlers["default"]
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
			handler(srv, sshConn, ch, ctx)
		})
	}
	cancel()
	closeQuietly(sshConn)
	workers.closeAndWait()
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
}

func (l *resourceLimiter) reserve() bool {
	if l == nil || l.limit <= 0 || l.active == nil {
		return true
	}
	if l.active.Add(1) <= l.limit {
		return true
	}
	l.active.Add(-1)
	return false
}

func (l *resourceLimiter) release() {
	if l != nil && l.limit > 0 && l.active != nil {
		l.active.Add(-1)
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

func configuredLimit(value *int, defaultValue int) int {
	if value == nil {
		return defaultValue
	}
	if *value <= 0 {
		return 0
	}
	return *value
}

func (srv *Server) handleRequests(ctx Context, in <-chan *gossh.Request, handlers map[string]RequestHandler) {
	for req := range in {
		handler := handlers[req.Type]
		if handler == nil {
			handler = handlers["default"]
		}
		if handler == nil {
			if err := req.Reply(false, nil); err != nil {
				return
			}
			continue
		}
		/*reqCtx, cancel := context.WithCancel(ctx)
		defer cancel() */
		ret, payload := handler(ctx, srv, req)
		if err := req.Reply(ret, payload); err != nil {
			return
		}
	}
}

// ListenAndServe listens on the TCP network address srv.Addr and then calls
// Serve to handle incoming connections. If srv.Addr is blank, ":22" is used.
// ListenAndServe always returns a non-nil error.
func (srv *Server) ListenAndServe() error {
	addr := srv.Addr
	if addr == "" {
		addr = ":22"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return srv.Serve(ln)
}

// AddHostKey adds a private key as a host key. If an existing host key exists
// with the same algorithm, it is overwritten. Each server config must have at
// least one host key.
func (srv *Server) AddHostKey(key Signer) {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	srv.generatedHostKey = nil

	// these are later added via AddHostKey on ServerConfig, which performs the
	// check for one of every algorithm.

	// This check is based on the AddHostKey method from the x/crypto/ssh
	// library. This allows us to only keep one active key for each type on a
	// server at once. So, if you're dynamically updating keys at runtime, this
	// list will not keep growing.
	for i, k := range srv.HostSigners {
		if k.PublicKey().Type() == key.PublicKey().Type() {
			srv.HostSigners[i] = key
			return
		}
	}

	srv.HostSigners = append(srv.HostSigners, key)
}

// SetOption runs a functional option against the server.
func (srv *Server) SetOption(option Option) error {
	srv.configMu.Lock()
	defer srv.configMu.Unlock()
	srv.mu.Lock()
	running := len(srv.listeners) > 0 || len(srv.activeConns) > 0
	if running {
		srv.mu.Unlock()
		return ErrServerRunning
	}
	srv.configuring = true
	srv.mu.Unlock()
	defer func() {
		srv.mu.Lock()
		srv.configuring = false
		srv.mu.Unlock()
	}()
	return option(srv)
}

func (srv *Server) getDoneChan() <-chan struct{} {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	return srv.getDoneChanLocked()
}

func (srv *Server) getDoneChanLocked() chan struct{} {
	if srv.doneChan == nil {
		srv.doneChan = make(chan struct{})
	}
	return srv.doneChan
}

func (srv *Server) closeDoneChanLocked() {
	ch := srv.getDoneChanLocked()
	select {
	case <-ch:
		// Already closed. Don't close again.
	default:
		// Safe to close here. We're the only closer, guarded
		// by srv.mu.
		close(ch)
	}
}

func (srv *Server) listenersLocked() []net.Listener {
	listeners := make([]net.Listener, 0, len(srv.listeners))
	for ln := range srv.listeners {
		listeners = append(listeners, ln)
	}
	return listeners
}

func closeListeners(listeners []net.Listener) error {
	var err error
	for _, ln := range listeners {
		if cErr := ln.Close(); cErr != nil && !isClosedError(cErr) && err == nil {
			err = cErr
		}
	}
	return err
}

func (srv *Server) trackListener(ln net.Listener, add bool) bool {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	if srv.listeners == nil {
		srv.listeners = make(map[net.Listener]struct{})
	}
	if add {
		if srv.isDoneLocked() && (len(srv.listeners) != 0 || len(srv.activeConns) != 0) {
			return false
		}
		if len(srv.listeners) == 0 && len(srv.activeConns) == 0 {
			srv.resetGenerationLocked()
		}
		srv.listeners[ln] = struct{}{}
	} else {
		delete(srv.listeners, ln)
		srv.maybeCloseDrainedLocked()
	}
	return true
}

func (srv *Server) trackConn(c *gossh.ServerConn, add bool) {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	if srv.conns == nil {
		srv.conns = make(map[*gossh.ServerConn]struct{})
	}
	if add {
		srv.conns[c] = struct{}{}
	} else {
		delete(srv.conns, c)
	}
}

func (srv *Server) trackActiveConn(conn net.Conn, allowReset bool) *activeConn {
	srv.mu.Lock()
	if srv.configuring {
		srv.mu.Unlock()
		closeQuietly(conn)
		return nil
	}
	if allowReset && len(srv.listeners) == 0 && len(srv.activeConns) == 0 {
		srv.resetGenerationLocked()
	}
	if srv.doneChan != nil {
		select {
		case <-srv.doneChan:
			if allowReset && len(srv.listeners) == 0 && len(srv.activeConns) == 0 {
				srv.resetGenerationLocked()
			} else {
				srv.mu.Unlock()
				closeQuietly(conn)
				return nil
			}
		default:
		}
	}
	maxStartups := srv.effectiveMaxStartups()
	dropRate := maxStartupsDropRate(srv.startups, maxStartups)
	if dropRate >= 100 || dropRate > 0 && int(rand.UintN(100)) < dropRate {
		srv.mu.Unlock()
		closeQuietly(conn)
		return nil
	}
	active := &activeConn{
		conn:            conn,
		acceptedAt:      time.Now(),
		handshaking:     true,
		startupReserved: maxStartups.Full > 0,
	}
	if srv.activeConns == nil {
		srv.activeConns = make(map[*activeConn]struct{})
	}
	if srv.authenticatedConnections == nil || srv.globalChannels == nil {
		srv.authenticatedConnections = &atomic.Int64{}
		srv.globalChannels = &atomic.Int64{}
	}
	srv.activeConns[active] = struct{}{}
	if active.startupReserved {
		srv.startups++
	}
	srv.mu.Unlock()
	return active
}

func (srv *Server) updateActiveConn(active *activeConn, conn net.Conn) bool {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if _, ok := srv.activeConns[active]; !ok || active.closed {
		return false
	}
	active.conn = conn
	return true
}

func (srv *Server) updateActiveCancel(active *activeConn, cancel context.CancelFunc) bool {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if _, ok := srv.activeConns[active]; !ok || active.closed {
		return false
	}
	active.cancel = cancel
	return true
}

func (srv *Server) untrackActiveConn(active *activeConn) {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if active.startupReserved {
		srv.startups--
		active.startupReserved = false
	}
	active.handshaking = false
	delete(srv.activeConns, active)
	srv.maybeCloseDrainedLocked()
}

func (srv *Server) waitForPreviousGeneration() {
	for {
		srv.mu.Lock()
		if !srv.isDoneLocked() || len(srv.listeners) == 0 && len(srv.activeConns) == 0 {
			srv.mu.Unlock()
			return
		}
		drained := srv.getDrainedChanLocked()
		srv.mu.Unlock()
		<-drained
	}
}

func (srv *Server) resetGenerationLocked() {
	srv.doneChan = make(chan struct{})
	srv.drainedChan = make(chan struct{})
	srv.authenticatedConnections = &atomic.Int64{}
	srv.globalChannels = &atomic.Int64{}
}

func (srv *Server) isDoneLocked() bool {
	if srv.doneChan == nil {
		return false
	}
	select {
	case <-srv.doneChan:
		return true
	default:
		return false
	}
}

func (srv *Server) getDrainedChanLocked() chan struct{} {
	if srv.drainedChan == nil {
		srv.drainedChan = make(chan struct{})
	}
	srv.maybeCloseDrainedLocked()
	return srv.drainedChan
}

func (srv *Server) maybeCloseDrainedLocked() {
	if len(srv.listeners) != 0 || len(srv.activeConns) != 0 {
		return
	}
	if srv.drainedChan == nil {
		srv.drainedChan = make(chan struct{})
	}
	select {
	case <-srv.drainedChan:
	default:
		close(srv.drainedChan)
	}
}

func (srv *Server) releaseStartup(active *activeConn) {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	active.handshaking = false
	if active.startupReserved {
		srv.startups--
		active.startupReserved = false
	}
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
	srv.mu.RLock()
	v := srv.Logger
	srv.mu.RUnlock()
	if v != nil {
		return v
	}
	return defaultServerLoggerGetter()
}

var defaultServerLoggerGetter = sync.OnceValue[log.Logger](func() log.Logger {
	return log.GetLogger(names.CurrentPackageLoggerNameGenerator(0) + ".server")
})
