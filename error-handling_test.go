package ssh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/echocat/slf4g"
	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"
)

type errorHandlerTestContextKey struct{}

func TestSessionHandlerErrorCanRespondToClient(t *testing.T) {
	handlerErr := errors.New("backend unavailable")
	type reportedError struct {
		response       error
		scope          ErrorScope
		operation      ErrorOperation
		err            error
		secondResponse error
	}
	reported := make(chan reportedError, 1)
	session, _, cleanup := newTestSession(t, &Server{
		Handler: func(Session) error {
			return handlerErr
		},
		ErrorHandler: func(_ context.Context, scope ErrorScope, operation ErrorOperation, err error, respond ErrorResponder, _ ErrorHandler) (bool, error) {
			responseErr := respond([]byte("command failed\n"), false)
			reported <- reportedError{
				response:       responseErr,
				scope:          scope,
				operation:      operation,
				err:            err,
				secondResponse: respond([]byte("again"), false),
			}
			return false, nil
		},
	}, nil)
	defer cleanup()

	var stderr bytes.Buffer
	session.Stderr = &stderr
	err := session.Run("")
	var exitErr *gossh.ExitError
	require.ErrorAs(t, err, &exitErr)
	require.Equal(t, 1, exitErr.ExitStatus())
	require.Equal(t, "command failed\n", stderr.String())

	event := <-reported
	require.NoError(t, event.response)
	require.Equal(t, ErrorScopeSession, event.scope)
	require.Equal(t, ErrorOperationHandle, event.operation)
	require.ErrorIs(t, event.err, handlerErr)
	require.ErrorIs(t, event.secondResponse, ErrErrorResponseAlreadySent)
}

func TestRequestHandlerErrorCanRespondToClient(t *testing.T) {
	handlerErr := errors.New("request failed")
	reported := make(chan struct {
		scope     ErrorScope
		operation ErrorOperation
		err       error
		response  error
	}, 1)
	session, client, cleanup := newTestSession(t, &Server{
		Handler: func(Session) error { return nil },
		RequestHandlers: map[string]RequestHandler{
			"example@test": func(RequestResponseWriter, *Request) error {
				return handlerErr
			},
			"next@test": func(response RequestResponseWriter, _ *Request) error {
				return response.Accept([]byte("continued"))
			},
		},
		ErrorHandler: func(_ context.Context, scope ErrorScope, operation ErrorOperation, err error, respond ErrorResponder, _ ErrorHandler) (bool, error) {
			responseErr := respond([]byte("safe public message"), false)
			reported <- struct {
				scope     ErrorScope
				operation ErrorOperation
				err       error
				response  error
			}{scope, operation, err, responseErr}
			return true, nil
		},
	}, nil)
	defer cleanup()
	defer closeQuietly(session)

	ok, payload, err := client.SendRequest("example@test", true, nil)
	require.NoError(t, err)
	require.False(t, ok)
	require.Equal(t, []byte("safe public message"), payload)

	event := <-reported
	require.NoError(t, event.response)
	require.Equal(t, ErrorScopeRequest, event.scope)
	require.Equal(t, ErrorOperationHandle, event.operation)
	require.ErrorIs(t, event.err, handlerErr)

	ok, payload, err = client.SendRequest("next@test", true, nil)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, []byte("continued"), payload)
}

func TestSessionHandlerErrorCanContinueAsSuccess(t *testing.T) {
	session, _, cleanup := newTestSession(t, &Server{
		Handler: func(Session) error {
			return errors.New("handled")
		},
		ErrorHandler: func(context.Context, ErrorScope, ErrorOperation, error, ErrorResponder, ErrorHandler) (bool, error) {
			return true, nil
		},
	}, nil)
	defer cleanup()

	require.NoError(t, session.Run(""))
}

func TestSessionExitErrorWritesMessageAndExitCode(t *testing.T) {
	var errorHandlerCalls atomic.Int32
	session, _, cleanup := newTestSession(t, &Server{
		Handler: func(Session) error {
			return fmt.Errorf("reject command: %w", NewSessionExitError(23, "command rejected\n"))
		},
		ErrorHandler: func(context.Context, ErrorScope, ErrorOperation, error, ErrorResponder, ErrorHandler) (bool, error) {
			errorHandlerCalls.Add(1)
			return false, nil
		},
	}, nil)
	defer cleanup()
	var stderr bytes.Buffer
	session.Stderr = &stderr

	err := session.Run("")
	var exitErr *gossh.ExitError
	require.ErrorAs(t, err, &exitErr)
	require.Equal(t, 23, exitErr.ExitStatus())
	require.Equal(t, "command rejected\n", stderr.String())
	require.Zero(t, errorHandlerCalls.Load())
}

func TestSessionExitErrorDoesNotHideJoinedOperationalError(t *testing.T) {
	cleanupErr := errors.New("cleanup failed")
	reported := make(chan error, 1)
	session, _, cleanup := newTestSession(t, &Server{
		Handler: func(Session) error {
			return errors.Join(NewSessionExitError(23, "command rejected\n"), cleanupErr)
		},
		ErrorHandler: func(_ context.Context, _ ErrorScope, _ ErrorOperation, err error, _ ErrorResponder, _ ErrorHandler) (bool, error) {
			reported <- err
			return false, nil
		},
	}, nil)
	defer cleanup()

	err := session.Run("reject")
	exitErr := new(gossh.ExitError)
	require.ErrorAs(t, err, &exitErr)
	require.Equal(t, 1, exitErr.ExitStatus())
	handlerErr := <-reported
	require.ErrorIs(t, handlerErr, cleanupErr)
	var requestedExit *SessionExitError
	require.ErrorAs(t, handlerErr, &requestedExit)
}

func TestSessionExitErrorReportsProtocolFailures(t *testing.T) {
	responseErr := errors.New("response failed")
	exitErr := errors.New("exit failed")
	written := make(chan string, 1)
	channel := &failingRequestChannel{
		requestErr: exitErr,
		write: func(message []byte) (int, error) {
			written <- string(message)
			return 0, responseErr
		},
	}
	ctx, cancel := newContextWithParent(context.Background(), new(Server))
	defer cancel(context.Canceled)
	type reportedError struct {
		operation ErrorOperation
		err       error
	}
	reported := make(chan reportedError, 1)
	session := &session{
		Channel: channel,
		ctx:     ctx,
		errorHandler: func(_ context.Context, _ ErrorScope, operation ErrorOperation, err error, _ ErrorResponder, _ ErrorHandler) (bool, error) {
			reported <- reportedError{operation: operation, err: err}
			return false, nil
		},
	}

	session.startHandler(func(Session) error {
		return NewSessionExitError(7, "goodbye\n")
	})
	<-session.handlerDone
	event := <-reported
	require.Equal(t, ErrorOperationReply, event.operation)
	require.ErrorIs(t, event.err, responseErr)
	require.ErrorIs(t, event.err, exitErr)
	require.Equal(t, "goodbye\n", <-written)
	require.True(t, channel.closed)
}

func TestRequestErrorResponseCanCloseConnection(t *testing.T) {
	session, client, cleanup := newTestSession(t, &Server{
		Handler: func(Session) error { return nil },
		RequestHandlers: map[string]RequestHandler{
			"fatal@test": func(_ RequestResponseWriter, request *Request) error {
				request.Context().SetValue(ContextKeyConn, (*gossh.ServerConn)(nil))
				return errors.New("fatal request")
			},
		},
		ErrorHandler: func(_ context.Context, _ ErrorScope, _ ErrorOperation, _ error, respond ErrorResponder, _ ErrorHandler) (bool, error) {
			return false, respond([]byte("request rejected"), true)
		},
	}, nil)
	defer cleanup()
	defer closeQuietly(session)

	ok, payload, err := client.SendRequest("fatal@test", true, nil)
	require.NoError(t, err)
	require.False(t, ok)
	require.Equal(t, []byte("request rejected"), payload)
	_, err = client.NewSession()
	require.Error(t, err)
}

func TestRequestCannotContinueClosesConnection(t *testing.T) {
	session, client, cleanup := newTestSession(t, &Server{
		Handler: func(Session) error { return nil },
		RequestHandlers: map[string]RequestHandler{
			"stop@test": func(RequestResponseWriter, *Request) error {
				return errors.New("stop requests")
			},
		},
		ErrorHandler: func(_ context.Context, _ ErrorScope, _ ErrorOperation, _ error, respond ErrorResponder, _ ErrorHandler) (bool, error) {
			if err := respond([]byte("stopping"), false); err != nil {
				return false, err
			}
			return false, nil
		},
	}, nil)
	defer cleanup()
	defer closeQuietly(session)

	ok, payload, err := client.SendRequest("stop@test", true, nil)
	require.NoError(t, err)
	require.False(t, ok)
	require.Equal(t, []byte("stopping"), payload)
	_, err = client.NewSession()
	require.Error(t, err)
}

func TestNoReplyRequestDoesNotClaimErrorResponseWasSent(t *testing.T) {
	reported := make(chan error, 1)
	_, client, cleanup := newTestSession(t, &Server{
		Handler: func(Session) error { return nil },
		RequestHandlers: map[string]RequestHandler{
			"no-reply@test": func(RequestResponseWriter, *Request) error {
				return errors.New("request failed")
			},
		},
		ErrorHandler: func(_ context.Context, _ ErrorScope, _ ErrorOperation, _ error, respond ErrorResponder, _ ErrorHandler) (bool, error) {
			reported <- respond([]byte("cannot be delivered"), false)
			return true, nil
		},
	}, nil)
	defer cleanup()

	_, _, err := client.SendRequest("no-reply@test", false, nil)
	require.NoError(t, err)
	require.ErrorIs(t, <-reported, ErrErrorResponseUnsupported)
}

func TestDispatchErrorPassesWrappedErrorToNext(t *testing.T) {
	originalCtx := context.WithValue(context.Background(), errorHandlerTestContextKey{}, "original")
	originalErr := errors.New("original")
	wrappedErr := fmt.Errorf("wrapped: %w", originalErr)
	var fallbackCtx context.Context
	var fallbackScope ErrorScope
	var fallbackOperation ErrorOperation
	var fallbackErr error
	handler := func(ctx context.Context, scope ErrorScope, operation ErrorOperation, _ error, respond ErrorResponder, next ErrorHandler) (bool, error) {
		require.NotNil(t, next)
		return next(context.Background(), ErrorScopeServer, ErrorOperationAccept, wrappedErr, respond, next)
	}
	fallback := func(ctx context.Context, _ log.Logger, scope ErrorScope, operation ErrorOperation, err error) (bool, error) {
		fallbackCtx = ctx
		fallbackScope = scope
		fallbackOperation = operation
		fallbackErr = err
		return true, nil
	}

	canContinue, err := dispatchError(originalCtx, nil, handler, ErrorScopeSession, ErrorOperationHandle, originalErr, nil, fallback)
	require.NoError(t, err)
	require.True(t, canContinue)
	require.Equal(t, originalCtx, fallbackCtx)
	require.Equal(t, ErrorScopeSession, fallbackScope)
	require.Equal(t, ErrorOperationHandle, fallbackOperation)
	require.ErrorIs(t, fallbackErr, originalErr)
	require.Equal(t, wrappedErr, fallbackErr)
}

func TestErrorHandlerCallbacksExpireAndNextIsSingleUse(t *testing.T) {
	var capturedRespond ErrorResponder
	var capturedNext ErrorHandler
	var secondNextErr error
	fallbackCalls := 0
	fallback := func(context.Context, log.Logger, ErrorScope, ErrorOperation, error) (bool, error) {
		fallbackCalls++
		return true, nil
	}
	handler := func(ctx context.Context, scope ErrorScope, operation ErrorOperation, err error, respond ErrorResponder, next ErrorHandler) (bool, error) {
		capturedRespond = respond
		capturedNext = next
		canContinue, nextErr := next(ctx, scope, operation, err, respond, next)
		require.NoError(t, nextErr)
		require.True(t, canContinue)
		_, secondNextErr = next(ctx, scope, operation, err, respond, next)
		return true, nil
	}

	canContinue, err := dispatchError(context.Background(), nil, handler, ErrorScopeSession, ErrorOperationHandle, errors.New("failure"), nil, fallback)
	require.NoError(t, err)
	require.True(t, canContinue)
	require.Equal(t, 1, fallbackCalls)
	require.ErrorIs(t, secondNextErr, ErrNextErrorHandlerAlreadyCalled)
	require.ErrorIs(t, capturedRespond(nil, false), ErrErrorResponseExpired)
	_, err = capturedNext(context.Background(), ErrorScopeServer, ErrorOperationAccept, errors.New("late"), nil, capturedNext)
	require.ErrorIs(t, err, ErrNextErrorHandlerExpired)
}

func TestIsOnlyErrorRejectsJoinedIndependentError(t *testing.T) {
	target := errors.New("target")
	require.True(t, isOnlyError(fmt.Errorf("wrapped: %w", target), target))
	require.True(t, isOnlyError(errors.Join(target, target), target))
	require.False(t, isOnlyError(errors.Join(target, errors.New("independent")), target))
}

func TestErrorResponderDoesNotRetryFailedAttempt(t *testing.T) {
	responseErr := errors.New("write failed")
	var calls atomic.Int32
	response := newErrorResponse(func([]byte, bool) error {
		calls.Add(1)
		return responseErr
	})

	require.ErrorIs(t, response.send([]byte("first"), false), responseErr)
	require.ErrorIs(t, response.send([]byte("second"), false), ErrErrorResponseAlreadySent)
	require.Equal(t, int32(1), calls.Load())
	attempted, err := response.result()
	require.True(t, attempted)
	require.ErrorIs(t, err, responseErr)
}

func TestConcurrentErrorResponseHasSingleAttempt(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	response := newErrorResponse(func([]byte, bool) error {
		close(started)
		<-release
		return nil
	})
	const calls = 16
	results := make(chan error, calls)
	for range calls {
		go func() { results <- response.send(nil, false) }()
	}
	<-started
	close(release)

	succeeded := 0
	for range calls {
		err := <-results
		if err == nil {
			succeeded++
		} else {
			require.ErrorIs(t, err, ErrErrorResponseAlreadySent)
		}
	}
	require.Equal(t, 1, succeeded)
}

func TestUnsupportedErrorResponseCanStillCloseConnection(t *testing.T) {
	var closed atomic.Bool
	ctx := context.WithValue(context.Background(), contextKeyCloseConnection, func() { closed.Store(true) })
	var responseErr error
	handler := func(_ context.Context, _ ErrorScope, _ ErrorOperation, _ error, respond ErrorResponder, _ ErrorHandler) (bool, error) {
		responseErr = respond(nil, true)
		return false, nil
	}

	canContinue, err := dispatchError(ctx, nil, handler, ErrorScopeForwarding, ErrorOperationForward, errors.New("failure"), nil, nil)
	require.NoError(t, err)
	require.False(t, canContinue)
	require.ErrorIs(t, responseErr, ErrErrorResponseUnsupported)
	require.True(t, closed.Load())
}

func TestAsynchronousNextFailsDispatch(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	nextDone := make(chan struct{})
	fallback := func(context.Context, log.Logger, ErrorScope, ErrorOperation, error) (bool, error) {
		close(started)
		<-release
		return true, nil
	}
	handler := func(ctx context.Context, scope ErrorScope, operation ErrorOperation, err error, respond ErrorResponder, next ErrorHandler) (bool, error) {
		go func() {
			defer close(nextDone)
			_, _ = next(ctx, scope, operation, err, respond, next)
		}()
		<-started
		return true, nil
	}

	_, err := dispatchError(context.Background(), nil, handler, ErrorScopeSession, ErrorOperationHandle, errors.New("failure"), nil, fallback)
	require.ErrorIs(t, err, ErrNextErrorHandlerIncomplete)
	close(release)
	<-nextDone
}

func TestConcurrentErrorHandlersAreBounded(t *testing.T) {
	entered := make(chan struct{}, defaultMaxConcurrentErrorHandlers)
	release := make(chan struct{})
	var running sync.WaitGroup
	running.Add(defaultMaxConcurrentErrorHandlers)
	handler := func(context.Context, ErrorScope, ErrorOperation, error, ErrorResponder, ErrorHandler) (bool, error) {
		entered <- struct{}{}
		<-release
		return true, nil
	}
	limited := newServeContext(&Server{ErrorHandler: handler}, context.Background(), nil).errorHandler
	var defaultCalls atomic.Int32
	next := func(context.Context, ErrorScope, ErrorOperation, error, ErrorResponder, ErrorHandler) (bool, error) {
		defaultCalls.Add(1)
		return false, nil
	}

	for range defaultMaxConcurrentErrorHandlers {
		go func() {
			defer running.Done()
			_, _ = limited(context.Background(), ErrorScopeConnection, ErrorOperationHandshake, errors.New("failure"), nil, next)
		}()
	}
	for range defaultMaxConcurrentErrorHandlers {
		<-entered
	}

	canContinue, err := limited(context.Background(), ErrorScopeConnection, ErrorOperationHandshake, errors.New("overflow"), nil, next)
	require.NoError(t, err)
	require.False(t, canContinue)
	require.Equal(t, int32(1), defaultCalls.Load())

	close(release)
	running.Wait()
}

func TestServeErrorHandlerCanContinueAfterAcceptError(t *testing.T) {
	listener := &onceFailingListener{
		Listener:  newLocalListener(),
		acceptErr: temporaryError{errors.New("transient failure")},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reported := make(chan struct {
		scope     ErrorScope
		operation ErrorOperation
	}, 1)
	srv := &Server{
		Handler: func(Session) error { return nil },
		ErrorHandler: func(ctx context.Context, scope ErrorScope, operation ErrorOperation, err error, respond ErrorResponder, next ErrorHandler) (bool, error) {
			reported <- struct {
				scope     ErrorScope
				operation ErrorOperation
			}{scope, operation}
			return next(ctx, scope, operation, err, respond, next)
		},
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- srv.Serve(ctx, listener) }()
	event := <-reported
	require.Equal(t, ErrorScopeServer, event.scope)
	require.Equal(t, ErrorOperationAccept, event.operation)

	session, client, cleanup := newClientSession(t, listener.Addr().String(), nil)
	defer cleanup()
	require.NoError(t, session.Run(""))
	require.NoError(t, client.Close())
	cancel()
	require.ErrorIs(t, <-serveDone, context.Canceled)
}

func TestServeNextUsesTransformedAcceptError(t *testing.T) {
	permanentErr := errors.New("permanent failure")
	listener := &failingListener{acceptErr: temporaryError{errors.New("temporary failure")}}
	srv := &Server{
		ErrorHandler: func(ctx context.Context, scope ErrorScope, operation ErrorOperation, _ error, respond ErrorResponder, next ErrorHandler) (bool, error) {
			return next(ctx, scope, operation, permanentErr, respond, next)
		},
	}

	err := srv.Serve(context.Background(), listener)
	require.ErrorIs(t, err, permanentErr)
	require.Equal(t, int32(1), listener.closeCalls.Load())
}

func TestServeErrorHandlerCanStopWithoutError(t *testing.T) {
	listener := &failingListener{acceptErr: errors.New("accept failed")}
	srv := &Server{
		ErrorHandler: func(context.Context, ErrorScope, ErrorOperation, error, ErrorResponder, ErrorHandler) (bool, error) {
			return false, nil
		},
	}

	require.NoError(t, srv.Serve(context.Background(), listener))
	require.Equal(t, int32(1), listener.closeCalls.Load())
}

func TestServeErrorHandlerErrorOverridesCanContinue(t *testing.T) {
	handlerErr := errors.New("error handler failed")
	listener := &failingListener{acceptErr: errors.New("accept failed")}
	srv := &Server{
		ErrorHandler: func(context.Context, ErrorScope, ErrorOperation, error, ErrorResponder, ErrorHandler) (bool, error) {
			return true, handlerErr
		},
	}

	err := srv.Serve(context.Background(), listener)
	require.ErrorIs(t, err, handlerErr)
	require.Equal(t, int32(1), listener.closeCalls.Load())
}

func TestServeCancellationDoesNotWaitForBlockedErrorHandler(t *testing.T) {
	listener := &failingListener{acceptErr: errors.New("accept failed")}
	started := make(chan struct{})
	release := make(chan struct{})
	gracefulCalled := make(chan struct{})
	callbackDone := make(chan error, 1)
	srv := &Server{
		GracefulShutdownHandler: func(context.Context) (time.Duration, error) {
			close(gracefulCalled)
			return 0, nil
		},
		ErrorHandler: func(ctx context.Context, scope ErrorScope, operation ErrorOperation, err error, respond ErrorResponder, next ErrorHandler) (bool, error) {
			close(started)
			<-release
			_, callbackErr := next(ctx, scope, operation, err, respond, next)
			callbackDone <- callbackErr
			return true, nil
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- srv.Serve(ctx, listener) }()
	<-started
	cancel()

	select {
	case err := <-serveDone:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("Serve waited for a blocked ErrorHandler after cancellation")
	}
	select {
	case <-gracefulCalled:
	case <-time.After(time.Second):
		t.Fatal("Serve skipped graceful shutdown after cancellation")
	}
	close(release)
	require.ErrorIs(t, <-callbackDone, ErrNextErrorHandlerExpired)
}

type onceFailingListener struct {
	net.Listener
	acceptErr error
	failed    atomic.Bool
}

func (l *onceFailingListener) Accept() (net.Conn, error) {
	if !l.failed.Swap(true) {
		return nil, l.acceptErr
	}
	return l.Listener.Accept()
}

type temporaryError struct {
	error
}

func (temporaryError) Timeout() bool   { return false }
func (temporaryError) Temporary() bool { return true }

func TestAcceptedChannelErrorDoesNotSendSecondOpenReply(t *testing.T) {
	underlying := &recordingNewChannel{}
	channel := &trackedNewChannel{NewChannel: underlying}
	_, _, err := channel.Accept()
	require.NoError(t, err)

	response := newErrorResponse(func(message []byte, _ bool) error {
		return channel.respondToError(message)
	})
	require.ErrorIs(t, response.send([]byte("cannot be sent after accept"), false), ErrErrorResponseUnsupported)
	channel.rejectUnhandledError()
	require.Zero(t, underlying.rejections)
}

func TestChannelHandlerMustAcceptOrReject(t *testing.T) {
	reported := make(chan error, 1)
	server := &Server{
		Handler: func(Session) error { return nil },
		ChannelHandlers: map[string]ChannelHandler{
			"session": DefaultSessionHandler,
			"default": func(*Server, *gossh.ServerConn, gossh.NewChannel, Context) error {
				return nil
			},
		},
		ErrorHandler: func(_ context.Context, _ ErrorScope, _ ErrorOperation, err error, respond ErrorResponder, _ ErrorHandler) (bool, error) {
			reported <- err
			if responseErr := respond([]byte("channel handler did not answer"), false); responseErr != nil {
				return false, responseErr
			}
			return false, nil
		},
	}
	listener := newLocalListener()
	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(ctx, listener) }()
	session, client, cleanup := newClientSession(t, listener.Addr().String(), nil)
	defer func() {
		cleanup()
		cancel()
		closeQuietly(listener)
		require.ErrorIs(t, <-serveDone, context.Canceled)
	}()
	defer closeQuietly(session)

	_, _, err := client.OpenChannel("missing@test", nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "channel handler did not answer")
	require.ErrorIs(t, <-reported, ErrChannelResponseNotSent)
	connectionClosed := make(chan error, 1)
	go func() { connectionClosed <- client.Wait() }()
	select {
	case <-connectionClosed:
	case <-time.After(time.Second):
		t.Fatal("canContinue=false did not close the connection")
	}
}

func TestChannelErrorHandlerCanPreserveConnection(t *testing.T) {
	_, client, cleanup := newTestSession(t, &Server{
		Handler: func(Session) error { return nil },
		ChannelHandlers: map[string]ChannelHandler{
			"session": DefaultSessionHandler,
			"failed@test": func(_ *Server, _ *gossh.ServerConn, channel gossh.NewChannel, _ Context) error {
				if err := channel.Reject(gossh.ConnectionFailed, "failed"); err != nil {
					return err
				}
				return errors.New("channel failed")
			},
		},
		ErrorHandler: func(context.Context, ErrorScope, ErrorOperation, error, ErrorResponder, ErrorHandler) (bool, error) {
			return true, nil
		},
	}, nil)
	defer cleanup()

	_, _, err := client.OpenChannel("failed@test", nil)
	require.Error(t, err)
	session, err := client.NewSession()
	require.NoError(t, err)
	defer closeQuietly(session)
	require.NoError(t, session.Run("success"))
}

func TestChannelHandlerErrorPreservesConnectionByDefault(t *testing.T) {
	_, client, cleanup := newTestSession(t, &Server{
		Handler: func(Session) error { return nil },
		ChannelHandlers: map[string]ChannelHandler{
			"session": DefaultSessionHandler,
			"failed@test": func(_ *Server, _ *gossh.ServerConn, channel gossh.NewChannel, _ Context) error {
				if err := channel.Reject(gossh.ConnectionFailed, "failed"); err != nil {
					return err
				}
				return errors.New("channel failed")
			},
		},
	}, nil)
	defer cleanup()

	_, _, err := client.OpenChannel("failed@test", nil)
	require.Error(t, err)
	session, err := client.NewSession()
	require.NoError(t, err)
	defer closeQuietly(session)
	require.NoError(t, session.Run("success"))
}

func TestChannelAnswerErrorsRetainTheirOperation(t *testing.T) {
	acceptErr := errors.New("accept failed")
	channel := &trackedNewChannel{NewChannel: &recordingNewChannel{acceptErr: acceptErr}}
	_, _, err := channel.Accept()
	require.ErrorIs(t, err, acceptErr)
	scope, operation := resolveErrorLocation(ErrorScopeChannel, ErrorOperationHandle, err)
	require.Equal(t, ErrorScopeChannel, scope)
	require.Equal(t, ErrorOperationAccept, operation)
	_, _, err = channel.Accept()
	require.ErrorIs(t, err, ErrChannelResponseAlreadySent)

	rejectErr := errors.New("reject failed")
	channel = &trackedNewChannel{NewChannel: &recordingNewChannel{rejectErr: rejectErr}}
	err = channel.Reject(gossh.ConnectionFailed, "failed")
	require.ErrorIs(t, err, rejectErr)
	scope, operation = resolveErrorLocation(ErrorScopeChannel, ErrorOperationHandle, err)
	require.Equal(t, ErrorScopeChannel, scope)
	require.Equal(t, ErrorOperationReply, operation)
	require.ErrorIs(t, channel.Reject(gossh.ConnectionFailed, "again"), ErrChannelResponseAlreadySent)
}

func TestFailedChannelResponseIsTrackedWithoutRetry(t *testing.T) {
	rejectErr := errors.New("reject failed")
	underlying := &recordingNewChannel{rejectErr: rejectErr}
	channel := &trackedNewChannel{NewChannel: underlying}
	response := newErrorResponse(func(message []byte, _ bool) error {
		return channel.respondToError(message)
	})

	require.ErrorIs(t, response.send([]byte("failed"), false), rejectErr)
	require.ErrorIs(t, response.send([]byte("again"), false), ErrErrorResponseAlreadySent)
	attempted, err := channel.answerResult()
	require.True(t, attempted)
	require.ErrorIs(t, err, rejectErr)
	require.Equal(t, 1, underlying.rejections)
}

func TestAcceptedChannelIsClosedWhenHandlerOwnershipEnds(t *testing.T) {
	accepted := &failingRequestChannel{}
	channel := &trackedNewChannel{NewChannel: &recordingNewChannel{accepted: accepted}}

	got, _, err := channel.Accept()
	require.NoError(t, err)
	require.Same(t, accepted, got)
	channel.closeAccepted()
	require.True(t, accepted.closed)
}

func TestSessionExitClosesChannelWhenStatusReplyFails(t *testing.T) {
	replyErr := errors.New("reply failed")
	channel := &failingRequestChannel{requestErr: replyErr}
	session := &session{Channel: channel}

	err := session.Exit(1)
	require.ErrorIs(t, err, replyErr)
	require.True(t, channel.closed)
}

func TestSessionErrorResponseStopsWhenContextIsCanceled(t *testing.T) {
	closed := make(chan struct{})
	channel := &failingRequestChannel{
		closedSignal: closed,
		write: func([]byte) (int, error) {
			<-closed
			return 0, io.ErrClosedPipe
		},
	}
	ctx, cancel := newContextWithParent(context.Background(), new(Server))
	ctx.SetValue(contextKeyCloseConnection, func() { closeQuietly(channel) })
	cancel(context.Canceled)
	session := &session{Channel: channel, ctx: ctx}

	err := session.respondToError([]byte("blocked"), false)
	require.ErrorIs(t, err, context.Canceled)
	require.True(t, channel.closed)
}

func TestSessionErrorResponseTimeoutClosesConnection(t *testing.T) {
	closed := make(chan struct{})
	channel := &failingRequestChannel{
		closedSignal: closed,
		write: func([]byte) (int, error) {
			<-closed
			return 0, io.ErrClosedPipe
		},
	}
	ctx, cancel := newContextWithParent(context.Background(), new(Server))
	defer cancel(context.Canceled)
	ctx.SetValue(contextKeyCloseConnection, func() { closeQuietly(channel) })
	session := &session{Channel: channel, ctx: ctx}

	err := session.respondToErrorWithin([]byte("blocked"), false, 10*time.Millisecond)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.True(t, channel.closed)
}

func TestSessionErrorResponseOwnsMessageUntilWriteCompletes(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	written := make(chan string, 1)
	channel := &failingRequestChannel{
		write: func(message []byte) (int, error) {
			close(started)
			<-release
			written <- string(message)
			return len(message), nil
		},
	}
	ctx, cancel := newContextWithParent(context.Background(), new(Server))
	defer cancel(context.Canceled)
	ctx.SetValue(contextKeyCloseConnection, func() { closeQuietly(channel) })
	session := &session{Channel: channel, ctx: ctx}
	message := []byte("original")

	err := session.respondToErrorWithin(message, false, 10*time.Millisecond)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	<-started
	message[0] = 'X'
	close(release)
	require.Equal(t, "original", <-written)
}

func TestSessionErrorResponseIsSizeLimited(t *testing.T) {
	written := make(chan int, 1)
	channel := &failingRequestChannel{
		write: func(message []byte) (int, error) {
			written <- len(message)
			return len(message), nil
		},
	}
	ctx, cancel := newContextWithParent(context.Background(), new(Server))
	defer cancel(context.Canceled)
	session := &session{Channel: channel, ctx: ctx}

	require.NoError(t, session.respondToError(make([]byte, maxSessionErrorResponseBytes+1), false))
	require.Equal(t, maxSessionErrorResponseBytes, <-written)
}

func TestSessionResponseFailureDoesNotCloseOtherSessions(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	reported := make(chan error, 1)
	_, client, cleanup := newTestSession(t, &Server{
		Handler: func(session Session) error {
			if session.RawCommand() == "fail" {
				close(started)
				<-release
				return errors.New("session failed")
			}
			return nil
		},
		ErrorHandler: func(_ context.Context, _ ErrorScope, operation ErrorOperation, _ error, respond ErrorResponder, _ ErrorHandler) (bool, error) {
			if operation == ErrorOperationReply {
				return false, nil
			}
			err := respond([]byte("failed"), false)
			reported <- err
			return false, err
		},
	}, nil)
	defer cleanup()

	failed, err := client.NewSession()
	require.NoError(t, err)
	require.NoError(t, failed.Start("fail"))
	<-started
	require.NoError(t, failed.Close())
	close(release)
	<-reported

	unaffected, err := client.NewSession()
	require.NoError(t, err)
	require.NoError(t, unaffected.Run("success"))
}

type recordingNewChannel struct {
	rejections int
	acceptErr  error
	rejectErr  error
	accepted   gossh.Channel
}

func (c *recordingNewChannel) Accept() (gossh.Channel, <-chan *gossh.Request, error) {
	return c.accepted, nil, c.acceptErr
}

func (*recordingNewChannel) ChannelType() string {
	return "example"
}

func (*recordingNewChannel) ExtraData() []byte {
	return nil
}

func (c *recordingNewChannel) Reject(gossh.RejectionReason, string) error {
	c.rejections++
	return c.rejectErr
}

type failingRequestChannel struct {
	requestErr   error
	closed       bool
	closedOnce   sync.Once
	closedSignal chan struct{}
	write        func([]byte) (int, error)
}

func (*failingRequestChannel) Read([]byte) (int, error) {
	return 0, io.EOF
}

func (c *failingRequestChannel) Write(p []byte) (int, error) {
	if c.write != nil {
		return c.write(p)
	}
	return len(p), nil
}

func (c *failingRequestChannel) Close() error {
	c.closed = true
	if c.closedSignal != nil {
		c.closedOnce.Do(func() { close(c.closedSignal) })
	}
	return nil
}

func (*failingRequestChannel) CloseWrite() error {
	return nil
}

func (c *failingRequestChannel) SendRequest(string, bool, []byte) (bool, error) {
	return false, c.requestErr
}

func (c *failingRequestChannel) Stderr() io.ReadWriter {
	return c
}
