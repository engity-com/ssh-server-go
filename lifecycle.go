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

type serveContext struct {
	*Server
	parent       context.Context
	listener     net.Listener
	errorHandler ErrorHandler

	mu                       sync.Mutex
	connections              map[*activeConn]struct{}
	startups                 int
	authenticatedConnections atomic.Int64
	globalChannels           atomic.Int64
	globalReverseForwards    atomic.Int64
	errorHandlerSlots        chan struct{}
	stopping                 bool
	forced                   bool
	drained                  chan struct{}
	listenerCloseOnce        sync.Once
	listenerCloseError       error
	stopContextWatch         func() bool
}

type activeConn struct {
	scope           *serveContext
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

func newServeContext(srv *Server, parent context.Context, listener net.Listener) *serveContext {
	result := &serveContext{
		Server:            srv,
		parent:            parent,
		listener:          listener,
		connections:       make(map[*activeConn]struct{}),
		errorHandlerSlots: make(chan struct{}, defaultMaxConcurrentErrorHandlers),
		drained:           make(chan struct{}),
	}
	result.errorHandler = result.limitErrorHandler(srv.ErrorHandler)
	return result
}

func (srv *Server) newServeContext(ctx context.Context, listener net.Listener) (*serveContext, error) {
	if err := srv.prepare(ctx); err != nil {
		return nil, errors.Join(err, closeListener(listener))
	}
	scope := newServeContext(srv, ctx, listener)
	scope.stopContextWatch = context.AfterFunc(ctx, func() {
		_ = scope.stopAccepting()
	})
	return scope, nil
}

func (s *serveContext) finish() {
	if s.stopContextWatch != nil {
		s.stopContextWatch()
	}
}

func (s *serveContext) closeListener() error {
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

func (s *serveContext) stopAccepting() error {
	s.mu.Lock()
	s.stopping = true
	s.maybeCloseDrainedLocked()
	s.mu.Unlock()
	return s.closeListener()
}

func (s *serveContext) trackConnection(conn net.Conn) *activeConn {
	s.mu.Lock()
	if s.stopping {
		s.mu.Unlock()
		closeQuietly(conn)
		return nil
	}

	maxStartups := s.effectiveMaxStartups()
	dropRate := maxStartupsDropRate(s.startups, maxStartups)
	// The random value only spreads load shedding; authentication and access
	// control never depend on it.
	if dropRate >= 100 || dropRate > 0 && int(rand.UintN(100)) < dropRate { // #nosec G404
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
		s.startups++
	}
	s.connections[active] = struct{}{}
	s.mu.Unlock()
	return active
}

func (s *serveContext) updateConnection(active *activeConn, conn net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.connections[active]; !ok || active.closed {
		return false
	}
	active.conn = conn
	active.transports = []net.Conn{conn}
	return true
}

func (s *serveContext) updateCancel(active *activeConn, cancel context.CancelCauseFunc) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.connections[active]; !ok || active.closed {
		return false
	}
	active.cancel = cancel
	return true
}

func (s *serveContext) isHandshaking(active *activeConn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return active.handshaking
}

func (s *serveContext) releaseStartup(active *activeConn) {
	s.mu.Lock()
	active.handshaking = false
	release := active.startupReserved
	active.startupReserved = false
	if release {
		s.startups--
	}
	s.mu.Unlock()
}

func (s *serveContext) untrackConnection(active *activeConn) {
	s.releaseStartup(active)
	s.mu.Lock()
	delete(s.connections, active)
	s.maybeCloseDrainedLocked()
	s.mu.Unlock()
}

func (s *serveContext) connectionCause(active *activeConn) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return active.closeCause
}

func (s *serveContext) force(cause error) error {
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
	s.startups -= startupReleases
	s.maybeCloseDrainedLocked()
	s.mu.Unlock()
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

func (s *serveContext) shutdown(ctx context.Context) error {
	cause := context.Cause(ctx)
	if cause == nil {
		cause = context.Canceled
	}
	listenerErr := s.stopAccepting()
	period := time.Duration(0)
	if s.GracefulShutdownHandler != nil {
		var err error
		period, err = s.GracefulShutdownHandler(ctx)
		if err != nil {
			forcedCause := errors.Join(cause, err)
			return errors.Join(forcedCause, listenerErr, s.force(forcedCause))
		}
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

func (s *serveContext) maybeCloseDrainedLocked() {
	if !s.stopping || len(s.connections) != 0 {
		return
	}
	select {
	case <-s.drained:
	default:
		close(s.drained)
	}
}

func (s *serveContext) limitErrorHandler(handler ErrorHandler) ErrorHandler {
	if handler == nil {
		return nil
	}
	return func(ctx context.Context, scope ErrorScope, operation ErrorOperation, err error, respond ErrorResponder, next ErrorHandler) (bool, error) {
		select {
		case s.errorHandlerSlots <- struct{}{}:
			defer func() { <-s.errorHandlerSlots }()
			return handler(ctx, scope, operation, err, respond, next)
		default:
			return next(ctx, scope, operation, err, respond, next)
		}
	}
}
