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
	contextKeyChannelLimiter      = &contextKey{"channel-limiter"}
	contextKeyForwardLimiter      = &contextKey{"reverse-forward-limiter"}
	contextKeyServerSettings      = &contextKey{"server-settings"}
	contextKeyConnectionWorkers   = &contextKey{"connection-workers"}
	contextKeyConnectionResources = &contextKey{"connection-resources"}
	contextKeyAuthConflicts       = &contextKey{"auth-callback-conflicts"}
	contextKeyRequestReply        = &contextKey{"request-reply"}

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

type connectionResource struct {
	close func()
}

type connectionResources struct {
	mu                  sync.Mutex
	resources           map[*connectionResource]struct{}
	pendingAcquisitions int
	acquisitionsDrained chan struct{}
	closed              bool
	closeDone           chan struct{}
}

func (r *connectionResources) register(closeFn func()) func() {
	resource := &connectionResource{close: closeFn}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		closeFn()
		return func() {}
	}
	if r.resources == nil {
		r.resources = make(map[*connectionResource]struct{})
	}
	r.resources[resource] = struct{}{}
	r.mu.Unlock()
	return sync.OnceFunc(func() {
		r.mu.Lock()
		delete(r.resources, resource)
		r.mu.Unlock()
	})
}

func (r *connectionResources) closeAll() {
	r.mu.Lock()
	if r.closed {
		done := r.closeDone
		r.mu.Unlock()
		<-done
		return
	}
	r.closed = true
	r.closeDone = make(chan struct{})
	resources := make([]*connectionResource, 0, len(r.resources))
	for resource := range r.resources {
		resources = append(resources, resource)
	}
	clear(r.resources)
	var acquisitionsDrained <-chan struct{}
	if r.pendingAcquisitions > 0 {
		r.acquisitionsDrained = make(chan struct{})
		acquisitionsDrained = r.acquisitionsDrained
	}
	r.mu.Unlock()
	for _, resource := range resources {
		resource.close()
	}
	if acquisitionsDrained != nil {
		<-acquisitionsDrained
	}
	close(r.closeDone)
}

func registerConnectionResource(ctx Context, closeFn func()) func() {
	resources, _ := ctx.Value(contextKeyConnectionResources).(*connectionResources)
	if resources == nil {
		return func() {}
	}
	return resources.register(closeFn)
}

func beginConnectionResourceAcquisition(ctx Context) (func(func()) func(), bool) {
	resources, _ := ctx.Value(contextKeyConnectionResources).(*connectionResources)
	if resources == nil {
		return func(func()) func() { return func() {} }, true
	}
	resources.mu.Lock()
	if resources.closed {
		resources.mu.Unlock()
		return nil, false
	}
	resources.pendingAcquisitions++
	resources.mu.Unlock()
	return func(closeFn func()) func() {
		resources.mu.Lock()
		closed := resources.closed
		var unregister func()
		if !closed && closeFn != nil {
			resource := &connectionResource{close: closeFn}
			if resources.resources == nil {
				resources.resources = make(map[*connectionResource]struct{})
			}
			resources.resources[resource] = struct{}{}
			unregister = sync.OnceFunc(func() {
				resources.mu.Lock()
				delete(resources.resources, resource)
				resources.mu.Unlock()
			})
		}
		resources.mu.Unlock()
		if closed && closeFn != nil {
			closeFn()
		}
		resources.mu.Lock()
		resources.pendingAcquisitions--
		if resources.closed && resources.pendingAcquisitions == 0 && resources.acquisitionsDrained != nil {
			close(resources.acquisitionsDrained)
			resources.acquisitionsDrained = nil
		}
		resources.mu.Unlock()
		if unregister == nil {
			return func() {}
		}
		return unregister
	}, true
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
	ctx, cancelCause := newContextWithParent(context.Background(), srv)
	return ctx, func() { cancelCause(context.Canceled) }
}

func newContextWithParent(parent context.Context, srv *Server) (*sshContext, context.CancelCauseFunc) {
	innerCtx, cancel := context.WithCancelCause(context.WithoutCancel(parent))
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
