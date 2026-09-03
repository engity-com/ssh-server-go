package ssh

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/echocat/slf4g"
	gossh "golang.org/x/crypto/ssh"
)

var (
	// ErrErrorResponseUnsupported is returned when an error cannot be reported
	// to the client at the point where it occurred.
	ErrErrorResponseUnsupported = errors.New("ssh: error response is not supported")
	// ErrErrorResponseAlreadySent is returned when an ErrorResponder is called
	// again after a response attempt. The first response may already have changed
	// the SSH protocol state even if it returned an error.
	ErrErrorResponseAlreadySent = errors.New("ssh: error response was already sent")
	// ErrErrorResponseExpired is returned when an ErrorResponder is called after
	// its ErrorHandler has returned.
	ErrErrorResponseExpired = errors.New("ssh: error responder has expired")
	// ErrNextErrorHandlerAlreadyCalled is returned when next is called more than
	// once by the same ErrorHandler invocation.
	ErrNextErrorHandlerAlreadyCalled = errors.New("ssh: next error handler was already called")
	// ErrNextErrorHandlerExpired is returned when next is called after its
	// ErrorHandler has returned.
	ErrNextErrorHandlerExpired = errors.New("ssh: next error handler has expired")
	// ErrNextErrorHandlerIncomplete indicates that next did not complete before
	// its ErrorHandler returned.
	ErrNextErrorHandlerIncomplete = errors.New("ssh: next error handler did not complete synchronously")
)

// ErrorScope identifies the protocol resource in which an error occurred.
type ErrorScope uint8

const (
	ErrorScopeServer ErrorScope = iota
	ErrorScopeConnection
	ErrorScopeRequest
	ErrorScopeChannel
	ErrorScopeSession
	ErrorScopeForwarding
)

var errorScopeNames = map[ErrorScope]string{
	ErrorScopeServer:     "server",
	ErrorScopeConnection: "connection",
	ErrorScopeRequest:    "request",
	ErrorScopeChannel:    "channel",
	ErrorScopeSession:    "session",
	ErrorScopeForwarding: "forwarding",
}

func (v ErrorScope) Validate() error {
	_, err := v.MarshalText()
	return err
}

func (v ErrorScope) MarshalText() ([]byte, error) {
	if name, ok := errorScopeNames[v]; ok {
		return []byte(name), nil
	}
	return nil, fmt.Errorf("illegal ssh error scope: %d", v)
}

func (v ErrorScope) String() string {
	if text, err := v.MarshalText(); err == nil {
		return string(text)
	}
	return fmt.Sprintf("illegal-ssh-error-scope-%d", v)
}

func (v *ErrorScope) UnmarshalText(text []byte) error {
	for candidate, name := range errorScopeNames {
		if name == string(text) {
			*v = candidate
			return nil
		}
	}
	return fmt.Errorf("illegal ssh error scope: %q", string(text))
}

func (v *ErrorScope) Set(text string) error {
	return v.UnmarshalText([]byte(text))
}

// ErrorOperation identifies the operation which failed within an ErrorScope.
type ErrorOperation uint8

const (
	ErrorOperationAccept ErrorOperation = iota
	ErrorOperationParse
	ErrorOperationHandle
	ErrorOperationReply
	ErrorOperationHandshake
	ErrorOperationDial
	ErrorOperationListen
	ErrorOperationOpenChannel
	ErrorOperationForward
)

var errorOperationNames = map[ErrorOperation]string{
	ErrorOperationAccept:      "accept",
	ErrorOperationParse:       "parse",
	ErrorOperationHandle:      "handle",
	ErrorOperationReply:       "reply",
	ErrorOperationHandshake:   "handshake",
	ErrorOperationDial:        "dial",
	ErrorOperationListen:      "listen",
	ErrorOperationOpenChannel: "open-channel",
	ErrorOperationForward:     "forward",
}

func (v ErrorOperation) Validate() error {
	_, err := v.MarshalText()
	return err
}

func (v ErrorOperation) MarshalText() ([]byte, error) {
	if name, ok := errorOperationNames[v]; ok {
		return []byte(name), nil
	}
	return nil, fmt.Errorf("illegal ssh error operation: %d", v)
}

func (v ErrorOperation) String() string {
	if text, err := v.MarshalText(); err == nil {
		return string(text)
	}
	return fmt.Sprintf("illegal-ssh-error-operation-%d", v)
}

func (v *ErrorOperation) UnmarshalText(text []byte) error {
	for candidate, name := range errorOperationNames {
		if name == string(text) {
			*v = candidate
			return nil
		}
	}
	return fmt.Errorf("illegal ssh error operation: %q", string(text))
}

func (v *ErrorOperation) Set(text string) error {
	return v.UnmarshalText([]byte(text))
}

// ErrorResponder sends a protocol-appropriate error message to the client. For
// a session it writes to stderr, for a request it sends a negative reply, and
// for a channel it rejects the channel if it has not already been accepted or
// rejected. Other locations return ErrErrorResponseUnsupported. A responder is
// valid only for the duration of its ErrorHandler invocation and may be called
// at most once. If closeAfterResponse is true, the associated SSH connection is
// closed after the response attempt, including when sending the response fails.
// The transport can bound message size or abort a blocked response.
type ErrorResponder func(message []byte, closeAfterResponse bool) error

// ErrorHandler handles operational errors synchronously and can be invoked by
// multiple connections concurrently. Implementations must return promptly. The
// responder never exposes the underlying channel or connection. respond and
// next are valid only until the invocation returns and may each be called at
// most once. A server-accept invocation can also be abandoned when its context
// is canceled so that shutdown is not held up by a blocked handler.
// next is always non-nil and invokes the caller-specific default error action.
// It retains the original context, scope, operation, and responder; only the
// error passed to next is used. A handler may handle the error itself, pass a
// wrapped error to next, or suppress the error by returning a nil filteredErr.
//
// A non-nil filteredErr always requires the caller to stop the current
// operation immediately; canContinue is ignored in that case. Returning false,
// nil means that the error was handled but the current operation must stop.
// Returning true, nil means that the error was handled and the caller may
// continue as if it had not occurred. canContinue is permission rather than a
// guarantee: the caller may still stop if its protocol or resource state makes
// continuing impossible.
//
// For server accept errors, true permits another accept attempt. For request
// errors, true permits processing the next request, while false closes the SSH
// connection after any response. For session errors, true treats the handler as
// successful and false uses a failing exit status. Channel handlers and
// one-shot forwarding workers cannot be re-entered after returning, so true can
// only preserve their parent connection or forwarding scope. Forward-listener
// accept errors may be retried with backoff. A non-nil filteredErr causes the
// associated SSH connection to be closed where one exists, because a failure in
// error handling cannot safely be ignored. A failed session response is isolated
// to its channel when the filtered error is that same response failure.
//
// Calls can originate concurrently. To prevent a blocked handler from
// exhausting server resources, each Serve or HandleConn call bounds concurrent
// invocations and sends excess errors directly to the caller-specific next
// handler.
type ErrorHandler func(
	ctx context.Context,
	scope ErrorScope,
	operation ErrorOperation,
	err error,
	respond ErrorResponder,
	next ErrorHandler,
) (canContinue bool, filteredErr error)

type errorResponse struct {
	mu        sync.Mutex
	respond   ErrorResponder
	active    bool
	attempted bool
	complete  bool
	err       error
	close     bool
}

type nextErrorHandler struct {
	mu            sync.Mutex
	active        bool
	called        bool
	complete      bool
	canContinue   bool
	err           error
	ctx           context.Context
	scope         ErrorScope
	operation     ErrorOperation
	logger        log.Logger
	defaultAction defaultErrorAction
}

var errErrorResponseIncomplete = errors.New("ssh: error response did not complete synchronously")

type locatedError struct {
	scope     ErrorScope
	operation ErrorOperation
	err       error
}

func (e *locatedError) Error() string {
	return e.err.Error()
}

func (e *locatedError) Unwrap() error {
	return e.err
}

func locateError(scope ErrorScope, operation ErrorOperation, err error) error {
	return &locatedError{scope: scope, operation: operation, err: err}
}

func resolveErrorLocation(scope ErrorScope, operation ErrorOperation, err error) (ErrorScope, ErrorOperation) {
	var located *locatedError
	if errors.As(err, &located) {
		return located.scope, located.operation
	}
	return scope, operation
}

func isOnlyError(err, target error) bool {
	if err == nil || target == nil {
		return false
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		children := joined.Unwrap()
		if len(children) == 0 {
			return false
		}
		for _, child := range children {
			if !isOnlyError(child, target) {
				return false
			}
		}
		return true
	}
	if wrapped := errors.Unwrap(err); wrapped != nil {
		return isOnlyError(wrapped, target)
	}
	return errors.Is(err, target)
}

func newErrorResponse(respond ErrorResponder) *errorResponse {
	return &errorResponse{respond: respond, active: true}
}

func (r *errorResponse) send(message []byte, closeAfterResponse bool) error {
	r.mu.Lock()
	if !r.active {
		r.mu.Unlock()
		return ErrErrorResponseExpired
	}
	if r.attempted {
		r.mu.Unlock()
		return ErrErrorResponseAlreadySent
	}
	if r.respond == nil {
		r.attempted = true
		r.complete = true
		r.err = ErrErrorResponseUnsupported
		r.mu.Unlock()
		return ErrErrorResponseUnsupported
	}
	r.attempted = true
	r.close = closeAfterResponse
	respond := r.respond
	r.mu.Unlock()

	err := respond(message, closeAfterResponse)
	r.mu.Lock()
	r.complete = true
	r.err = err
	r.mu.Unlock()
	return err
}

func (r *errorResponse) result() (attempted bool, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.attempted && !r.complete {
		return true, errErrorResponseIncomplete
	}
	return r.attempted, r.err
}

func (r *errorResponse) closeRequested() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.close
}

func (r *errorResponse) expire() {
	r.mu.Lock()
	r.active = false
	r.respond = nil
	r.mu.Unlock()
}

func newNextErrorHandler(ctx context.Context, logger log.Logger, scope ErrorScope, operation ErrorOperation, defaultAction defaultErrorAction) *nextErrorHandler {
	return &nextErrorHandler{
		active:        true,
		ctx:           ctx,
		scope:         scope,
		operation:     operation,
		logger:        logger,
		defaultAction: defaultAction,
	}
}

func (n *nextErrorHandler) call(_ context.Context, _ ErrorScope, _ ErrorOperation, err error, _ ErrorResponder, _ ErrorHandler) (bool, error) {
	n.mu.Lock()
	if !n.active {
		n.mu.Unlock()
		return false, ErrNextErrorHandlerExpired
	}
	if n.called {
		n.mu.Unlock()
		return false, ErrNextErrorHandlerAlreadyCalled
	}
	n.called = true
	ctx := n.ctx
	scope := n.scope
	operation := n.operation
	logger := n.logger
	defaultAction := n.defaultAction
	n.mu.Unlock()
	canContinue, filteredErr := defaultAction(ctx, logger, scope, operation, err)
	n.mu.Lock()
	n.complete = true
	n.canContinue = canContinue
	n.err = filteredErr
	n.mu.Unlock()
	return canContinue, filteredErr
}

func (n *nextErrorHandler) result() (called, complete, canContinue bool, err error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.called, n.complete, n.canContinue, n.err
}

func (n *nextErrorHandler) expire() {
	n.mu.Lock()
	n.active = false
	n.ctx = nil
	n.logger = nil
	n.defaultAction = nil
	n.mu.Unlock()
}

type defaultErrorAction func(
	ctx context.Context,
	logger log.Logger,
	scope ErrorScope,
	operation ErrorOperation,
	err error,
) (canContinue bool, filtered error)

type errorHandlerResult struct {
	canContinue bool
	err         error
}

func dispatchError(
	ctx context.Context,
	logger log.Logger,
	handler ErrorHandler,
	scope ErrorScope,
	operation ErrorOperation,
	err error,
	response *errorResponse,
	defaultAction defaultErrorAction,
) (canContinue bool, filteredErr error) {
	if err == nil {
		return true, nil
	}

	scope, operation = resolveErrorLocation(scope, operation, err)
	if response == nil {
		response = newErrorResponse(func(_ []byte, closeAfterResponse bool) error {
			if closeAfterResponse {
				defer closeSSHConnection(ctx)
			}
			return ErrErrorResponseUnsupported
		})
	}
	if defaultAction == nil {
		defaultAction = defaultLogAndFailErrorAction
	}
	if handler == nil {
		canContinue, filteredErr := defaultAction(ctx, logger, scope, operation, err)
		response.expire()
		return canContinue, filteredErr
	}

	next := newNextErrorHandler(ctx, logger, scope, operation, defaultAction)
	defer next.expire()
	defer response.expire()
	if scope != ErrorScopeServer || ctx.Done() == nil {
		canContinue, filteredErr = handler(ctx, scope, operation, err, response.send, next.call)
	} else {
		result := make(chan errorHandlerResult, 1)
		go func() {
			canContinue, filteredErr := handler(ctx, scope, operation, err, response.send, next.call)
			result <- errorHandlerResult{canContinue: canContinue, err: filteredErr}
		}()
		select {
		case handled := <-result:
			canContinue, filteredErr = handled.canContinue, handled.err
		case <-ctx.Done():
			return false, context.Cause(ctx)
		}
	}
	if called, complete, _, _ := next.result(); called && !complete {
		return false, ErrNextErrorHandlerIncomplete
	}
	return canContinue, filteredErr
}

func dispatchErrorOrEscalate(
	ctx context.Context,
	logger log.Logger,
	handler ErrorHandler,
	scope ErrorScope,
	operation ErrorOperation,
	err error,
	response *errorResponse,
	defaultAction defaultErrorAction,
) (ok bool) {
	canContinue, dErr := dispatchError(ctx, logger, handler, scope, operation, err, response, defaultAction)
	if dErr != nil {
		scope, operation = resolveErrorLocation(scope, operation, err)
		logDispatchErrorEscalate(logger, scope, operation, dErr, err)
		closeSSHConnection(ctx)
		return false
	}
	return canContinue
}

func logDispatchErrorEscalate(
	logger log.Logger,
	scope ErrorScope,
	operation ErrorOperation,
	dispatchErr, originalErr error,
) {
	logger.WithError(dispatchErr).
		With("error.original", originalErr).
		With("scope", scope).
		With("operation", operation).
		Error("cannot handle error")
}

func defaultClosingConnectionErrorAction(ctx context.Context, logger log.Logger, scope ErrorScope, operation ErrorOperation, err error) (bool, error) {
	if err != nil {
		closeSSHConnection(ctx)
	}
	return err == nil, err
}

func defaultClosingConnectionAndLogErrorAction(ctx context.Context, logger log.Logger, scope ErrorScope, operation ErrorOperation, err error) (bool, error) {
	_, err = defaultClosingConnectionErrorAction(ctx, logger, scope, operation, err)
	return defaultLogAndFailErrorAction(ctx, logger, scope, operation, err)
}

func defaultLogAndFailErrorAction(_ context.Context, logger log.Logger, scope ErrorScope, operation ErrorOperation, err error) (bool, error) {
	if err != nil {
		logger.WithError(err).
			With("scope", scope.String()).
			With("operation", operation.String()).
			Error("SSH operation failed")
	}
	return err == nil, nil
}

func closeSSHConnection(ctx context.Context) {
	if ctx == nil {
		return
	}
	if closeConnection, ok := ctx.Value(contextKeyCloseConnection).(func()); ok && closeConnection != nil {
		closeConnection()
		return
	}
	if conn, ok := ctx.Value(ContextKeyConn).(*gossh.ServerConn); ok && conn != nil {
		closeQuietly(conn)
	}
}
