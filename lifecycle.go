package ssh

import (
	"context"
	"errors"
	"math/rand/v2"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type serveScope struct {
	srv                     *Server
	parent                  context.Context
	listener                net.Listener
	gracefulShutdownHandler GracefulShutdownHandler

	mu                 sync.Mutex
	connections        map[*activeConn]struct{}
	stopping           bool
	forced             bool
	drained            chan struct{}
	listenerCloseOnce  sync.Once
	listenerCloseError error
	stopContextWatch   func() bool
}

type activeConn struct {
	scope           *serveScope
	conn            net.Conn
	transports      []net.Conn
	cancel          context.CancelCauseFunc
	acceptedAt      time.Time
	handshaking     bool
	startupReserved bool
	closed          bool
	closeCause      error
	resources       *connectionResources
}

func newServeScope(srv *Server, parent context.Context, listener net.Listener, gracefulShutdownHandler GracefulShutdownHandler) *serveScope {
	return &serveScope{
		srv:                     srv,
		parent:                  parent,
		listener:                listener,
		gracefulShutdownHandler: gracefulShutdownHandler,
		connections:             make(map[*activeConn]struct{}),
		drained:                 make(chan struct{}),
	}
}

func (srv *Server) startScope(ctx context.Context, listener net.Listener) (*serveScope, error) {
	srv.mu.Lock()
	if srv.configuring {
		srv.mu.Unlock()
		return nil, errors.Join(ErrServerRunning, closeListener(listener))
	}
	if srv.scopes == nil {
		srv.scopes = make(map[*serveScope]struct{})
	}
	if srv.authenticatedConnections == nil {
		srv.authenticatedConnections = &atomic.Int64{}
	}
	if srv.globalChannels == nil {
		srv.globalChannels = &atomic.Int64{}
	}
	scope := newServeScope(srv, ctx, listener, srv.GracefulShutdownHandler)
	srv.scopes[scope] = struct{}{}
	srv.mu.Unlock()
	scope.stopContextWatch = context.AfterFunc(ctx, func() {
		_ = scope.stopAccepting()
	})

	srv.configMu.Lock()
	srv.ensureHandlers()
	err := srv.ensureHostSigner()
	srv.configMu.Unlock()
	if err != nil {
		closeErr := scope.stopAccepting()
		srv.finishScope(scope)
		return nil, errors.Join(err, closeErr)
	}
	return scope, nil
}

func (srv *Server) finishScope(scope *serveScope) {
	if scope.stopContextWatch != nil {
		scope.stopContextWatch()
	}
	srv.mu.Lock()
	delete(srv.scopes, scope)
	srv.mu.Unlock()
}

func (s *serveScope) closeListener() error {
	s.listenerCloseOnce.Do(func() {
		s.listenerCloseError = closeListener(s.listener)
	})
	return s.listenerCloseError
}

func closeListener(listener net.Listener) error {
	if listener == nil {
		return nil
	}
	if err := listener.Close(); err != nil && !isClosedError(err) {
		return err
	}
	return nil
}

func (s *serveScope) stopAccepting() error {
	s.mu.Lock()
	s.stopping = true
	s.maybeCloseDrainedLocked()
	s.mu.Unlock()
	return s.closeListener()
}

func (s *serveScope) trackConnection(conn net.Conn) *activeConn {
	s.mu.Lock()
	if s.stopping {
		s.mu.Unlock()
		closeQuietly(conn)
		return nil
	}

	s.srv.mu.Lock()
	maxStartups := s.srv.effectiveMaxStartups()
	dropRate := maxStartupsDropRate(s.srv.startups, maxStartups)
	if dropRate >= 100 || dropRate > 0 && int(rand.UintN(100)) < dropRate {
		s.srv.mu.Unlock()
		s.mu.Unlock()
		closeQuietly(conn)
		return nil
	}
	active := &activeConn{
		scope:           s,
		conn:            conn,
		transports:      []net.Conn{conn},
		acceptedAt:      time.Now(),
		handshaking:     true,
		startupReserved: maxStartups.Full > 0,
		resources:       &connectionResources{},
	}
	if active.startupReserved {
		s.srv.startups++
	}
	s.connections[active] = struct{}{}
	s.srv.mu.Unlock()
	s.mu.Unlock()
	return active
}

func (s *serveScope) updateConnection(active *activeConn, conn net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.connections[active]; !ok || active.closed {
		return false
	}
	active.conn = conn
	active.transports = append(active.transports, conn)
	return true
}

func (s *serveScope) updateCancel(active *activeConn, cancel context.CancelCauseFunc) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.connections[active]; !ok || active.closed {
		return false
	}
	active.cancel = cancel
	return true
}

func (s *serveScope) isHandshaking(active *activeConn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return active.handshaking
}

func (s *serveScope) releaseStartup(active *activeConn) {
	s.mu.Lock()
	active.handshaking = false
	release := active.startupReserved
	active.startupReserved = false
	s.mu.Unlock()
	if release {
		s.srv.mu.Lock()
		s.srv.startups--
		s.srv.mu.Unlock()
	}
}

func (s *serveScope) untrackConnection(active *activeConn) {
	s.releaseStartup(active)
	s.mu.Lock()
	delete(s.connections, active)
	s.maybeCloseDrainedLocked()
	s.mu.Unlock()
}

func (s *serveScope) connectionCause(active *activeConn) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return active.closeCause
}

func (s *serveScope) force(cause error) error {
	listenerErr := s.stopAccepting()
	type connectionCleanup struct {
		cancel     context.CancelCauseFunc
		transports []net.Conn
		resources  *connectionResources
	}

	s.mu.Lock()
	if s.forced {
		s.mu.Unlock()
		return listenerErr
	}
	s.forced = true
	cleanups := make([]connectionCleanup, 0, len(s.connections))
	startupReleases := 0
	for active := range s.connections {
		active.closed = true
		active.closeCause = cause
		if active.startupReserved {
			active.startupReserved = false
			startupReleases++
		}
		cleanups = append(cleanups, connectionCleanup{
			cancel:     active.cancel,
			transports: append([]net.Conn(nil), active.transports...),
			resources:  active.resources,
		})
		delete(s.connections, active)
	}
	s.maybeCloseDrainedLocked()
	s.mu.Unlock()

	if startupReleases > 0 {
		s.srv.mu.Lock()
		s.srv.startups -= startupReleases
		s.srv.mu.Unlock()
	}
	var result error
	for _, cleanup := range cleanups {
		if cleanup.cancel != nil {
			cleanup.cancel(cause)
		}
		for i := len(cleanup.transports) - 1; i >= 0; i-- {
			if err := cleanup.transports[i].Close(); err != nil && !isClosedError(err) {
				result = errors.Join(result, err)
			}
		}
		cleanup.resources.closeAll()
	}
	return errors.Join(listenerErr, result)
}

func (s *serveScope) shutdown(ctx context.Context, handler GracefulShutdownHandler) error {
	cause := context.Cause(ctx)
	if cause == nil {
		cause = context.Canceled
	}
	listenerErr := s.stopAccepting()
	period := time.Duration(0)
	if handler != nil {
		period = handler(ctx)
	}
	if period <= 0 {
		return errors.Join(cause, s.force(cause))
	}

	timer := time.NewTimer(period)
	defer timer.Stop()
	select {
	case <-s.drained:
		return errors.Join(cause, listenerErr)
	case <-timer.C:
		s.mu.Lock()
		drained := len(s.connections) == 0
		s.mu.Unlock()
		if drained {
			return errors.Join(cause, listenerErr)
		}
		forcedCause := errors.Join(cause, ErrGracefulShutdownTimeout)
		return errors.Join(forcedCause, s.force(forcedCause))
	}
}

func (s *serveScope) maybeCloseDrainedLocked() {
	if !s.stopping || len(s.connections) != 0 {
		return
	}
	select {
	case <-s.drained:
	default:
		close(s.drained)
	}
}
