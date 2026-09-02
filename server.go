package ssh

import (
	"context"
	"errors"
	"maps"
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

// GracefulShutdownHandler determines how long a context-triggered shutdown
// waits for connections to drain before closing them.
type GracefulShutdownHandler func(context.Context) time.Duration

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
	LocalUnixForwardingCallback   LocalUnixForwardingCallback   // callback for local Unix forwarding, denies all if nil
	ReverseUnixForwardingCallback ReverseUnixForwardingCallback // callback for reverse Unix forwarding, denies all if nil
	ServerConfigCallback          ServerConfigCallback          // callback for detailed SSH options; same-method auth conflicts are rejected
	SessionRequestCallback        SessionRequestCallback        // callback for allowing or denying SSH sessions
	AgentForwardingCallback       AgentForwardingCallback       // callback for allowing agent forwarding, denies all if nil

	ConnectionFailedCallback ConnectionFailedCallback // callback to report connection failures
	DisconnectCallback       DisconnectCallback       // callback after an established SSH connection ends
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
	scopes                   map[*serveScope]struct{}
	startups                 int
	authenticatedConnections *atomic.Int64
	globalChannels           *atomic.Int64
	configuring              bool
}

type connectionSettings struct {
	logger                        log.Logger
	serverConfigCallback          ServerConfigCallback
	ciphers                       Ciphers
	keyExchanges                  KeyExchanges
	messageAuthentications        MessageAuthentications
	hostSigners                   []Signer
	passwordHandler               PasswordHandler
	publicKeyHandler              PublicKeyHandler
	keyboardInteractiveHandler    KeyboardInteractiveHandler
	version                       string
	banner                        string
	bannerHandler                 BannerHandler
	connCallback                  ConnCallback
	connectionFailedCallback      ConnectionFailedCallback
	disconnectCallback            DisconnectCallback
	handler                       Handler
	ptyCallback                   PtyCallback
	sessionRequestCallback        SessionRequestCallback
	agentForwardingCallback       AgentForwardingCallback
	localPortForwardingCallback   LocalPortForwardingCallback
	reversePortForwardingCallback ReversePortForwardingCallback
	localUnixForwardingCallback   LocalUnixForwardingCallback
	reverseUnixForwardingCallback ReverseUnixForwardingCallback
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
	proxyProtocol                 *ProxyProtocolConfig
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
	proxyProtocol := srv.ProxyProtocol
	if proxyProtocol != nil {
		config := *proxyProtocol
		proxyProtocol = &config
	}
	return &connectionSettings{
		logger:                        srv.Logger,
		serverConfigCallback:          srv.ServerConfigCallback,
		ciphers:                       append(Ciphers(nil), srv.Ciphers...),
		keyExchanges:                  append(KeyExchanges(nil), srv.KeyExchanges...),
		messageAuthentications:        append(MessageAuthentications(nil), srv.MessageAuthentications...),
		hostSigners:                   append([]Signer(nil), srv.HostSigners...),
		passwordHandler:               srv.PasswordHandler,
		publicKeyHandler:              srv.PublicKeyHandler,
		keyboardInteractiveHandler:    srv.KeyboardInteractiveHandler,
		version:                       srv.Version,
		banner:                        srv.Banner,
		bannerHandler:                 srv.BannerHandler,
		connCallback:                  srv.ConnCallback,
		connectionFailedCallback:      srv.ConnectionFailedCallback,
		disconnectCallback:            srv.DisconnectCallback,
		handler:                       handler,
		ptyCallback:                   srv.PtyCallback,
		sessionRequestCallback:        srv.SessionRequestCallback,
		agentForwardingCallback:       srv.AgentForwardingCallback,
		localPortForwardingCallback:   srv.LocalPortForwardingCallback,
		reversePortForwardingCallback: srv.ReversePortForwardingCallback,
		localUnixForwardingCallback:   srv.LocalUnixForwardingCallback,
		reverseUnixForwardingCallback: srv.ReverseUnixForwardingCallback,
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
		proxyProtocol:                 proxyProtocol,
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
		localUnixForwardingCallback:   srv.LocalUnixForwardingCallback,
		reverseUnixForwardingCallback: srv.ReverseUnixForwardingCallback,
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
	return srv.configWithSettings(ctx, srv.connectionSettings())
}

func (srv *Server) configWithSettings(ctx Context, settings *connectionSettings) *gossh.ServerConfig {
	config := &gossh.ServerConfig{}
	if settings.serverConfigCallback != nil {
		settings.serverConfigCallback(ctx, config)
	}
	customBannerCallback := config.BannerCallback
	customPasswordCallback := config.PasswordCallback
	customPublicKeyCallback := config.PublicKeyCallback
	customKeyboardInteractiveCallback := config.KeyboardInteractiveCallback
	ctx.SetValue(contextKeyAuthConflicts, authCallbackConflicts{
		password:            settings.passwordHandler != nil,
		publicKey:           settings.publicKeyHandler != nil,
		keyboardInteractive: settings.keyboardInteractiveHandler != nil,
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
	if !settings.ciphers.IsEmpty() || len(config.Ciphers) == 0 {
		ciphers := settings.ciphers
		if ciphers.IsEmpty() {
			ciphers = DefaultCiphers
		}
		config.Ciphers = make([]string, len(ciphers))
		for i, cipher := range ciphers {
			config.Ciphers[i] = cipher.String()
		}
	}
	if !settings.keyExchanges.IsEmpty() || len(config.KeyExchanges) == 0 {
		keyExchanges := settings.keyExchanges
		if keyExchanges.IsEmpty() {
			keyExchanges = DefaultKeyExchanges
		}
		config.KeyExchanges = make([]string, len(keyExchanges))
		for i, keyExchange := range keyExchanges {
			config.KeyExchanges[i] = keyExchange.String()
		}
	}
	if !settings.messageAuthentications.IsEmpty() || len(config.MACs) == 0 {
		messageAuthentications := settings.messageAuthentications
		if messageAuthentications.IsEmpty() {
			messageAuthentications = DefaultMessageAuthentications
		}
		config.MACs = make([]string, len(messageAuthentications))
		for i, messageAuthentication := range messageAuthentications {
			config.MACs[i] = messageAuthentication.String()
		}
	}
	for _, signer := range settings.hostSigners {
		config.AddHostKey(signer)
	}
	if !settings.requireClientAuth && settings.passwordHandler == nil && settings.publicKeyHandler == nil && settings.keyboardInteractiveHandler == nil &&
		config.PasswordCallback == nil && config.PublicKeyCallback == nil &&
		config.KeyboardInteractiveCallback == nil && config.GSSAPIWithMICConfig == nil {
		config.NoClientAuth = true
	}
	if settings.version != "" {
		config.ServerVersion = "SSH-2.0-" + settings.version
	}
	if settings.banner != "" {
		config.BannerCallback = func(_ gossh.ConnMetadata) string {
			return settings.banner
		}
	}
	if settings.bannerHandler != nil {
		config.BannerCallback = func(conn gossh.ConnMetadata) string {
			applyConnMetadata(ctx, conn)
			return settings.bannerHandler(ctx)
		}
	} else if settings.banner == "" && customBannerCallback != nil {
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
	if settings.passwordHandler != nil {
		if customPasswordCallback != nil {
			config.PasswordCallback = func(gossh.ConnMetadata, []byte) (*gossh.Permissions, error) {
				return nil, ErrServerAuthCallbackConflict
			}
		} else {
			config.PasswordCallback = func(conn gossh.ConnMetadata, password []byte) (*gossh.Permissions, error) {
				applyConnMetadata(ctx, conn)
				permissions := beginAuthAttempt(ctx)
				if ok := settings.passwordHandler(ctx, string(password)); !ok {
					return permissions, ErrServerPermissionDenied
				}
				return permissions, nil
			}
		}
	} else if config.PasswordCallback != nil {
		config.PasswordCallback = wrapPasswordCallback(ctx, config.PasswordCallback)
	}
	if settings.publicKeyHandler != nil {
		verifiedPublicKeyCallback := config.VerifiedPublicKeyCallback
		if customPublicKeyCallback != nil {
			config.PublicKeyCallback = func(gossh.ConnMetadata, gossh.PublicKey) (*gossh.Permissions, error) {
				return nil, ErrServerAuthCallbackConflict
			}
		} else {
			config.PublicKeyCallback = func(conn gossh.ConnMetadata, key gossh.PublicKey) (*gossh.Permissions, error) {
				applyConnMetadata(ctx, conn)
				permissions := beginAuthAttempt(ctx)
				if ok := settings.publicKeyHandler(ctx, key); !ok {
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
	if settings.keyboardInteractiveHandler != nil {
		if customKeyboardInteractiveCallback != nil {
			config.KeyboardInteractiveCallback = func(gossh.ConnMetadata, gossh.KeyboardInteractiveChallenge) (*gossh.Permissions, error) {
				return nil, ErrServerAuthCallbackConflict
			}
		} else {
			config.KeyboardInteractiveCallback = func(conn gossh.ConnMetadata, challenger gossh.KeyboardInteractiveChallenge) (*gossh.Permissions, error) {
				applyConnMetadata(ctx, conn)
				permissions := beginAuthAttempt(ctx)
				if ok := settings.keyboardInteractiveHandler(ctx, challenger); !ok {
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

// Serve accepts incoming connections on the Listener l, creating a new
// connection goroutine for each. The connection goroutines read requests and then
// calls srv.Handler to handle sessions. Canceling ctx closes the listener and
// stops this Serve scope; other concurrent Serve calls on srv are unaffected.
// Serve returns the context cause after draining or forcibly closing the
// scope's connections. A forced shutdown after a positive graceful period also
// returns ErrGracefulShutdownTimeout.
func (srv *Server) Serve(ctx context.Context, l net.Listener) error {
	scope, err := srv.startScope(ctx, l)
	if err != nil {
		return err
	}
	defer srv.finishScope(scope)
	var tempDelay time.Duration
	for {
		conn, acceptErr := l.Accept()
		if acceptErr != nil {
			if ctx.Err() != nil {
				return scope.shutdown(ctx, scope.gracefulShutdownHandler)
			}
			if ne, ok := errors.AsType[net.Error](acceptErr); ok && ne.Temporary() {
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if v := 1 * time.Second; tempDelay > v {
					tempDelay = v
				}
				timer := time.NewTimer(tempDelay)
				select {
				case <-ctx.Done():
					if !timer.Stop() {
						<-timer.C
					}
					return scope.shutdown(ctx, scope.gracefulShutdownHandler)
				case <-timer.C:
				}
				continue
			}
			return errors.Join(acceptErr, scope.force(acceptErr))
		}
		tempDelay = 0
		if active := scope.trackConnection(conn); active != nil {
			settings := srv.connectionSettings()
			go func() {
				_ = srv.handleConn(scope.parent, conn, active, true, settings)
			}()
		}
	}
}

// HandleConn handles one connection until it finishes or ctx is canceled. It
// returns connection failures directly and does not invoke
// ConnectionFailedCallback. On cancellation, the returned error contains the
// context cause and may contain cleanup errors or ErrGracefulShutdownTimeout.
func (srv *Server) HandleConn(ctx context.Context, newConn net.Conn) error {
	scope, err := srv.startScope(ctx, nil)
	if err != nil {
		closeQuietly(newConn)
		return err
	}
	defer srv.finishScope(scope)
	active := scope.trackConnection(newConn)
	if active == nil {
		if ctx.Err() != nil {
			return scope.shutdown(ctx, scope.gracefulShutdownHandler)
		}
		return nil
	}
	settings := srv.connectionSettings()
	result := make(chan error, 1)
	go func() {
		result <- srv.handleConn(scope.parent, newConn, active, false, settings)
	}()
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		select {
		case err := <-result:
			return err
		default:
			return scope.shutdown(ctx, scope.gracefulShutdownHandler)
		}
	}
}

func (srv *Server) handleConn(parent context.Context, newConn net.Conn, active *activeConn, reportFailure bool, connectionSettings *connectionSettings) error {
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
		if reportFailure && connectionSettings.connectionFailedCallback != nil {
			connectionSettings.connectionFailedCallback(conn, err)
		}
		return err
	}
	ctx.SetValue(contextKeyServerSettings, connectionSettings)
	ctx.SetValue(contextKeyConnectionResources, active.resources)
	if !active.scope.updateCancel(active, cancelCause) {
		closeQuietly(newConn)
		return active.scope.connectionCause(active)
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
	if v := connectionSettings.proxyProtocol; v != nil {
		proxyConn, err := wrapProxyProtocolConn(newConn, *v)
		if err != nil {
			active.scope.releaseStartup(active)
			closeQuietly(newConn)
			active.scope.untrackConnection(active)
			tracked = false
			return fail(newConn, err)
		}
		newConn = proxyConn
		if !active.scope.updateConnection(active, proxyConn) {
			closeQuietly(proxyConn)
			return active.scope.connectionCause(active)
		}
	}
	_ = newConn.SetDeadline(earliestDeadline(handshakeDeadline, maxDeadline))
	if v := connectionSettings.connCallback; v != nil {
		cbConn := v(ctx, newConn)
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
	serverConfig := srv.configWithSettings(ctx, connectionSettings)
	if connectionSettings.requireClientAuth && !serverConfigHasClientAuth(serverConfig) {
		err := ErrServerClientAuthRequired
		active.scope.releaseStartup(active)
		closeQuietly(conn)
		active.scope.untrackConnection(active)
		tracked = false
		return fail(conn, err)
	}
	sshConn, chans, reqs, err := gossh.NewServerConn(conn, serverConfig)
	if err != nil {
		active.scope.releaseStartup(active)
		closeQuietly(conn)
		active.scope.untrackConnection(active)
		tracked = false
		return fail(conn, err)
	}
	active.scope.releaseStartup(active)
	ctx.SetValue(ContextKeyConn, sshConn)
	applyConnMetadata(ctx, sshConn)
	publishAuthPermissions(ctx, sshConn.Permissions)
	if connectionSettings.disconnectCallback != nil {
		defer func() {
			cancel()
			closeQuietly(sshConn)
			active.scope.untrackConnection(active)
			tracked = false
			connectionSettings.disconnectCallback(ctx, conn)
		}()
	}
	connectionLimiter := resourceLimiter{
		limit:  int64(connectionSettings.maxConnections),
		active: connectionSettings.authenticatedConnections,
	}
	if !connectionLimiter.reserve() {
		return nil
	}
	connectionReserved := true
	defer func() {
		if connectionReserved {
			connectionLimiter.release()
		}
	}()
	if handshakeTimer != nil {
		handshakeTimer.Stop()
	}
	conn.clearHandshakeDeadline()
	maxSessions := connectionSettings.maxSessionsPerConnection
	maxChannels := connectionSettings.maxChannelsPerConnection
	globalChannelLimiter := &resourceLimiter{
		limit:  int64(connectionSettings.maxChannels),
		active: connectionSettings.globalChannels,
	}
	channelLimiter := &connectionChannelLimiter{limit: int64(maxChannels), global: globalChannelLimiter}
	ctx.SetValue(contextKeyChannelLimiter, channelLimiter)
	var activeReverseForwards atomic.Int64
	forwardLimiter := &resourceLimiter{limit: int64(connectionSettings.maxReverseForwards), active: &activeReverseForwards}
	ctx.SetValue(contextKeyForwardLimiter, forwardLimiter)
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
	active.resources.closeAll()
	active.scope.untrackConnection(active)
	tracked = false
	connectionLimiter.release()
	connectionReserved = false
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
		reply := &requestReply{done: make(chan struct{})}
		ctx.SetValue(contextKeyRequestReply, reply)
		ret, payload := handler(ctx, srv, req)
		err := req.Reply(ret, payload)
		reply.complete(err)
		ctx.SetValue(contextKeyRequestReply, nil)
		if err != nil {
			return
		}
	}
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
	running := len(srv.scopes) > 0
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
