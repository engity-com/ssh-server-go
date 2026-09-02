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
	contextKeyForwardLimiter    = &contextKey{"reverse-forward-limiter"}
	contextKeyServerSettings    = &contextKey{"server-settings"}
	contextKeyConnectionWorkers = &contextKey{"connection-workers"}
	contextKeyAuthConflicts     = &contextKey{"auth-callback-conflicts"}
	contextKeyRequestReply      = &contextKey{"request-reply"}

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
	// The associated value will be of type *gossh.ServerConn after the SSH
	// handshake has completed.
	ContextKeyConn = &contextKey{"ssh-conn"}

	// ContextKeyPublicKey is a context key for use with Contexts in this package.
	// The associated value will be of type PublicKey.
	ContextKeyPublicKey = &contextKey{"public-key"}
)

type requestReply struct {
	done chan struct{}
	err  error
}

func (r *requestReply) complete(err error) {
	r.err = err
	close(r.done)
}

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

// Context is a package-specific context interface. It exposes connection
// metadata and allows new values to be written to it. Metadata getters return
// zero values until metadata is available during the SSH handshake. Context is
// used in authentication handlers and callbacks and exposed by Session.Context.
// A connection-scoped lock is embedded for coordinating application state.
type Context interface {
	context.Context
	sync.Locker

	// User returns the current username, or "" before metadata is available.
	User() string

	// SessionID returns the hex-encoded session hash, or "" before it is available.
	SessionID() string

	// ClientVersion returns the version reported by the client, or "" before it is available.
	ClientVersion() string

	// ServerVersion returns the version reported by the server, or "" before it is available.
	ServerVersion() string

	// RemoteAddr returns the remote address, or nil before metadata is available.
	RemoteAddr() net.Addr

	// LocalAddr returns the local address, or nil before metadata is available.
	LocalAddr() net.Addr

	// Permissions returns the current authentication permissions. Server-created
	// contexts initialize an empty value before authentication starts.
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
	value, _ := ctx.Value(ContextKeyUser).(string)
	return value
}

func (ctx *sshContext) SessionID() string {
	value, _ := ctx.Value(ContextKeySessionID).(string)
	return value
}

func (ctx *sshContext) ClientVersion() string {
	value, _ := ctx.Value(ContextKeyClientVersion).(string)
	return value
}

func (ctx *sshContext) ServerVersion() string {
	value, _ := ctx.Value(ContextKeyServerVersion).(string)
	return value
}

func (ctx *sshContext) RemoteAddr() net.Addr {
	if addr, ok := ctx.Value(ContextKeyRemoteAddr).(net.Addr); ok {
		return addr
	}
	return nil
}

func (ctx *sshContext) LocalAddr() net.Addr {
	value, _ := ctx.Value(ContextKeyLocalAddr).(net.Addr)
	return value
}

func (ctx *sshContext) Permissions() *Permissions {
	value, _ := ctx.Value(ContextKeyPermissions).(*Permissions)
	return value
}
