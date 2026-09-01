package ssh

import (
	"context"
	"encoding/hex"
	"net"
	"sync"

	gossh "golang.org/x/crypto/ssh"
)

// contextKey is a value for use with context.WithValue. It's used as
// a pointer so it fits in an any without allocation.
type contextKey struct {
	name string
}

var (
	contextKeyChannelLimiter    = &contextKey{"channel-limiter"}
	contextKeyServerSettings    = &contextKey{"server-settings"}
	contextKeyConnectionWorkers = &contextKey{"connection-workers"}

	// ContextKeyUser is a context key for use with Contexts in this package.
	// The associated value will be of type string.
	ContextKeyUser = &contextKey{"user"}

	// ContextKeySessionID is a context key for use with Contexts in this package.
	// The associated value will be of type string.
	ContextKeySessionID = &contextKey{"session-id"}

	// ContextKeyPermissions is a context key for use with Contexts in this package.
	// The associated value will be of type *Permissions.
	ContextKeyPermissions = &contextKey{"permissions"}

	// ContextKeyClientVersion is a context key for use with Contexts in this package.
	// The associated value will be of type string.
	ContextKeyClientVersion = &contextKey{"client-version"}

	// ContextKeyServerVersion is a context key for use with Contexts in this package.
	// The associated value will be of type string.
	ContextKeyServerVersion = &contextKey{"server-version"}

	// ContextKeyLocalAddr is a context key for use with Contexts in this package.
	// The associated value will be of type net.Addr.
	ContextKeyLocalAddr = &contextKey{"local-addr"}

	// ContextKeyRemoteAddr is a context key for use with Contexts in this package.
	// The associated value will be of type net.Addr.
	ContextKeyRemoteAddr = &contextKey{"remote-addr"}

	// ContextKeyServer is a context key for use with Contexts in this package.
	// The associated value will be of type *Server.
	ContextKeyServer = &contextKey{"ssh-server"}

	// ContextKeyConn is a context key for use with Contexts in this package.
	// The associated value will be of type gossh.ServerConn.
	ContextKeyConn = &contextKey{"ssh-conn"}

	// ContextKeyPublicKey is a context key for use with Contexts in this package.
	// The associated value will be of type PublicKey.
	ContextKeyPublicKey = &contextKey{"public-key"}
)

type connectionWorkers struct {
	mu     sync.Mutex
	wg     sync.WaitGroup
	closed bool
}

func (w *connectionWorkers) goRun(fn func()) bool {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return false
	}
	w.wg.Add(1)
	w.mu.Unlock()
	go func() {
		defer w.wg.Done()
		fn()
	}()
	return true
}

func (w *connectionWorkers) closeAndWait() {
	w.mu.Lock()
	w.closed = true
	w.mu.Unlock()
	w.wg.Wait()
}

func startConnectionWorker(ctx Context, fn func()) bool {
	workers, _ := ctx.Value(contextKeyConnectionWorkers).(*connectionWorkers)
	if workers == nil {
		go fn()
		return true
	}
	return workers.goRun(fn)
}

func serverSettingsFromContext(ctx Context, srv *Server) *connectionSettings {
	settings, _ := ctx.Value(contextKeyServerSettings).(*connectionSettings)
	if settings == nil {
		settings = srv.fallbackConnectionSettings()
	}
	return settings
}

// Context is a package specific context interface. It exposes connection
// metadata and allows new values to be easily written to it. It's used in
// authentication handlers and callbacks, and its underlying context.Context is
// exposed on Session in the session Handler. A connection-scoped lock is also
// embedded in the context to make it easier to limit operations per-connection.
type Context interface {
	context.Context
	sync.Locker

	// User returns the username used when establishing the SSH connection.
	User() string

	// SessionID returns the session hash.
	SessionID() string

	// ClientVersion returns the version reported by the client.
	ClientVersion() string

	// ServerVersion returns the version reported by the server.
	ServerVersion() string

	// RemoteAddr returns the remote address for this connection.
	RemoteAddr() net.Addr

	// LocalAddr returns the local address for this connection.
	LocalAddr() net.Addr

	// Permissions returns the Permissions object used for this connection.
	Permissions() *Permissions

	// SetValue allows you to easily write new values into the underlying context.
	SetValue(key, value any)
}

type sshContext struct {
	context.Context
	*sync.Mutex

	values   map[any]any
	valuesMu sync.Mutex
}

func newContext(srv *Server) (*sshContext, context.CancelFunc) {
	innerCtx, cancel := context.WithCancel(context.Background())
	ctx := &sshContext{Context: innerCtx, Mutex: &sync.Mutex{}, values: make(map[any]any)}
	ctx.SetValue(ContextKeyServer, srv)
	perms := &Permissions{&gossh.Permissions{}}
	ctx.SetValue(ContextKeyPermissions, perms)
	return ctx, cancel
}

// this is separate from newContext because we will get ConnMetadata
// at different points so it needs to be applied separately
func applyConnMetadata(ctx Context, conn gossh.ConnMetadata) {
	// The client may change the requested user between authentication attempts.
	ctx.SetValue(ContextKeyUser, conn.User())
	if ctx.Value(ContextKeySessionID) != nil {
		return
	}
	ctx.SetValue(ContextKeySessionID, hex.EncodeToString(conn.SessionID()))
	ctx.SetValue(ContextKeyClientVersion, string(conn.ClientVersion()))
	ctx.SetValue(ContextKeyServerVersion, string(conn.ServerVersion()))
	ctx.SetValue(ContextKeyLocalAddr, conn.LocalAddr())
	ctx.SetValue(ContextKeyRemoteAddr, conn.RemoteAddr())
}

func (ctx *sshContext) Value(key any) any {
	ctx.valuesMu.Lock()
	defer ctx.valuesMu.Unlock()
	if v, ok := ctx.values[key]; ok {
		return v
	}
	return ctx.Context.Value(key)
}

func (ctx *sshContext) SetValue(key, value any) {
	ctx.valuesMu.Lock()
	defer ctx.valuesMu.Unlock()
	ctx.values[key] = value
}

func (ctx *sshContext) User() string {
	return ctx.Value(ContextKeyUser).(string)
}

func (ctx *sshContext) SessionID() string {
	return ctx.Value(ContextKeySessionID).(string)
}

func (ctx *sshContext) ClientVersion() string {
	return ctx.Value(ContextKeyClientVersion).(string)
}

func (ctx *sshContext) ServerVersion() string {
	return ctx.Value(ContextKeyServerVersion).(string)
}

func (ctx *sshContext) RemoteAddr() net.Addr {
	if addr, ok := ctx.Value(ContextKeyRemoteAddr).(net.Addr); ok {
		return addr
	}
	return nil
}

func (ctx *sshContext) LocalAddr() net.Addr {
	return ctx.Value(ContextKeyLocalAddr).(net.Addr)
}

func (ctx *sshContext) Permissions() *Permissions {
	return ctx.Value(ContextKeyPermissions).(*Permissions)
}
