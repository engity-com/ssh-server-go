package ssh

import (
	"context"
	"errors"
	"maps"
	"net"
	"sync"
	"time"

	"github.com/echocat/slf4g"
	"github.com/echocat/slf4g/names"
	gossh "golang.org/x/crypto/ssh"
)

var (
	// ErrServerClosed is returned by [Server.Serve] and [Server.ListenAndServe]
	// after a call to [Server.Shutdown] or [Server.Close].
	ErrServerClosed = errors.New("ssh: Server closed")

	ErrServerPermissionDenied = errors.New("permission denied")
)

type SubsystemHandler func(s Session)

var DefaultSubsystemHandlers = map[string]SubsystemHandler{}

type RequestHandler func(ctx Context, srv *Server, req *gossh.Request) (ok bool, payload []byte)

var DefaultRequestHandlers = map[string]RequestHandler{}

type ChannelHandler func(srv *Server, conn *gossh.ServerConn, newChan gossh.NewChannel, ctx Context)

var DefaultChannelHandlers = map[string]ChannelHandler{
	"session": DefaultSessionHandler,
}

// Server defines parameters for running an SSH server. The zero value for
// Server is a valid configuration. When both PasswordHandler and
// PublicKeyHandler are nil, no client authentication is performed.
type Server struct {
	Logger log.Logger

	Addr                   string                 // TCP address to listen on, ":22" if empty
	Handler                Handler                // handler to invoke, ssh.DefaultHandler if nil
	HostSigners            []Signer               // private keys for the host key, must have at least one
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
	ServerConfigCallback          ServerConfigCallback          // callback for configuring detailed SSH options
	SessionRequestCallback        SessionRequestCallback        // callback for allowing or denying SSH sessions

	ConnectionFailedCallback ConnectionFailedCallback // callback to report connection failures

	HandshakeTimeout time.Duration // connection timeout until successful handshake, none if empty
	IdleTimeout      time.Duration // connection timeout when no activity, none if empty
	MaxTimeout       time.Duration // absolute connection timeout, none if empty

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

	listenerWg sync.WaitGroup
	mu         sync.RWMutex
	listeners  map[net.Listener]struct{}
	conns      map[*gossh.ServerConn]struct{}
	connWg     sync.WaitGroup
	doneChan   chan struct{}
}

func (srv *Server) ensureHostSigner() error {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	if len(srv.HostSigners) == 0 {
		signer, err := generateSigner()
		if err != nil {
			return err
		}
		srv.HostSigners = append(srv.HostSigners, signer)
	}
	return nil
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
}

func (srv *Server) config(ctx Context) *gossh.ServerConfig {
	srv.mu.RLock()
	defer srv.mu.RUnlock()

	var config *gossh.ServerConfig
	if srv.ServerConfigCallback == nil {
		config = &gossh.ServerConfig{}
	} else {
		config = srv.ServerConfigCallback(ctx)
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
	for _, signer := range srv.HostSigners {
		config.AddHostKey(signer)
	}
	if srv.PasswordHandler == nil && srv.PublicKeyHandler == nil && srv.KeyboardInteractiveHandler == nil {
		config.NoClientAuth = true
	}
	if srv.Version != "" {
		config.ServerVersion = "SSH-2.0-" + srv.Version
	}
	if srv.Banner != "" {
		config.BannerCallback = func(_ gossh.ConnMetadata) string {
			return srv.Banner
		}
	}
	if srv.BannerHandler != nil {
		config.BannerCallback = func(conn gossh.ConnMetadata) string {
			applyConnMetadata(ctx, conn)
			return srv.BannerHandler(ctx)
		}
	}
	if srv.PasswordHandler != nil {
		config.PasswordCallback = func(conn gossh.ConnMetadata, password []byte) (*gossh.Permissions, error) {
			applyConnMetadata(ctx, conn)
			if ok := srv.PasswordHandler(ctx, string(password)); !ok {
				return ctx.Permissions().Permissions, ErrServerPermissionDenied
			}
			return ctx.Permissions().Permissions, nil
		}
	}
	if srv.PublicKeyHandler != nil {
		config.PublicKeyCallback = func(conn gossh.ConnMetadata, key gossh.PublicKey) (*gossh.Permissions, error) {
			applyConnMetadata(ctx, conn)
			if ok := srv.PublicKeyHandler(ctx, key); !ok {
				return ctx.Permissions().Permissions, ErrServerPermissionDenied
			}
			ctx.SetValue(ContextKeyPublicKey, key)
			return ctx.Permissions().Permissions, nil
		}
	}
	if srv.KeyboardInteractiveHandler != nil {
		config.KeyboardInteractiveCallback = func(conn gossh.ConnMetadata, challenger gossh.KeyboardInteractiveChallenge) (*gossh.Permissions, error) {
			applyConnMetadata(ctx, conn)
			if ok := srv.KeyboardInteractiveHandler(ctx, challenger); !ok {
				return ctx.Permissions().Permissions, ErrServerPermissionDenied
			}
			return ctx.Permissions().Permissions, nil
		}
	}
	return config
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
	defer srv.mu.Unlock()

	srv.closeDoneChanLocked()
	err := srv.closeListenersLocked()
	for c := range srv.conns {
		closeQuietly(c)
		delete(srv.conns, c)
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
	err := srv.closeListenersLocked()
	srv.closeDoneChanLocked()
	srv.mu.Unlock()

	finished := make(chan struct{}, 1)
	go func() {
		srv.listenerWg.Wait()
		srv.connWg.Wait()
		finished <- struct{}{}
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-finished:
		return err
	}
}

// Serve accepts incoming connections on the Listener l, creating a new
// connection goroutine for each. The connection goroutines read requests and then
// calls srv.Handler to handle sessions.
//
// Serve always returns a non-nil error.
func (srv *Server) Serve(l net.Listener) error {
	srv.ensureHandlers()
	defer closeQuietly(l)
	if err := srv.ensureHostSigner(); err != nil {
		return err
	}
	if srv.Handler == nil {
		srv.Handler = DefaultHandler
	}
	var tempDelay time.Duration

	srv.trackListener(l, true)
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
		go srv.HandleConn(conn)
	}
}

func (srv *Server) HandleConn(newConn net.Conn) {
	ctx, cancel := newContext(srv)
	if srv.ConnCallback != nil {
		cbConn := srv.ConnCallback(ctx, newConn)
		if cbConn == nil {
			closeQuietly(newConn)
			return
		}
		newConn = cbConn
	}
	conn := &serverConn{
		Conn:          newConn,
		idleTimeout:   srv.IdleTimeout,
		closeCanceler: cancel,
	}
	if srv.MaxTimeout > 0 {
		conn.maxDeadline = time.Now().Add(srv.MaxTimeout)
	}
	if srv.HandshakeTimeout > 0 {
		conn.handshakeDeadline = time.Now().Add(srv.HandshakeTimeout)
	}
	conn.updateDeadline()
	defer closeQuietly(conn)
	sshConn, chans, reqs, err := gossh.NewServerConn(conn, srv.config(ctx))
	if err != nil {
		if srv.ConnectionFailedCallback != nil {
			srv.ConnectionFailedCallback(conn, err)
		}
		return
	}
	conn.handshakeDeadline = time.Time{}
	conn.updateDeadline()
	srv.trackConn(sshConn, true)
	defer srv.trackConn(sshConn, false)

	ctx.SetValue(ContextKeyConn, sshConn)
	applyConnMetadata(ctx, sshConn)
	//go gossh.DiscardRequests(reqs)
	go srv.handleRequests(ctx, reqs)
	for ch := range chans {
		handler := srv.ChannelHandlers[ch.ChannelType()]
		if handler == nil {
			handler = srv.ChannelHandlers["default"]
		}
		if handler == nil {
			_ = ch.Reject(gossh.UnknownChannelType, "unsupported channel type")
			continue
		}
		go handler(srv, sshConn, ch, ctx)
	}
}

func (srv *Server) handleRequests(ctx Context, in <-chan *gossh.Request) {
	for req := range in {
		handler := srv.RequestHandlers[req.Type]
		if handler == nil {
			handler = srv.RequestHandlers["default"]
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
	// NOTE: there is a potential race here for any option that doesn't call an
	// internal method. We can't actually lock here because if something calls
	// (as an example) AddHostKey, it will deadlock.

	//srv.mu.Lock()
	//defer srv.mu.Unlock()

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

func (srv *Server) closeListenersLocked() error {
	var err error
	for ln := range srv.listeners {
		if cErr := ln.Close(); cErr != nil && err == nil {
			err = cErr
		}
		delete(srv.listeners, ln)
	}
	return err
}

func (srv *Server) trackListener(ln net.Listener, add bool) {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	if srv.listeners == nil {
		srv.listeners = make(map[net.Listener]struct{})
	}
	if add {
		// If the *Server is being reused after a previous
		// Close or Shutdown, reset its doneChan:
		if len(srv.listeners) == 0 && len(srv.conns) == 0 {
			srv.doneChan = nil
		}
		srv.listeners[ln] = struct{}{}
		srv.listenerWg.Add(1)
	} else {
		delete(srv.listeners, ln)
		srv.listenerWg.Done()
	}
}

func (srv *Server) trackConn(c *gossh.ServerConn, add bool) {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	if srv.conns == nil {
		srv.conns = make(map[*gossh.ServerConn]struct{})
	}
	if add {
		srv.conns[c] = struct{}{}
		srv.connWg.Add(1)
	} else {
		delete(srv.conns, c)
		srv.connWg.Done()
	}
}

func (srv *Server) logger() log.Logger {
	if v := srv.Logger; v != nil {
		return v
	}
	return defaultServerLoggerGetter()
}

var defaultServerLoggerGetter = sync.OnceValue[log.Logger](func() log.Logger {
	return log.GetLogger(names.CurrentPackageLoggerNameGenerator(0) + ".server")
})
