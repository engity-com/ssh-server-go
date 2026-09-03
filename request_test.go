package ssh

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"
)

func TestRequestResponseWriterAcceptsAndRejects(t *testing.T) {
	type observation struct {
		context  Context
		server   *Server
		typeName string
		payload  []byte
	}
	observed := make(chan observation, 2)
	server := &Server{Handler: func(Session) error { return nil }}
	server.RequestHandlers = map[string]RequestHandler{
		"accept@test": func(response RequestResponseWriter, request *Request) error {
			observed <- observation{request.Context(), request.Server(), request.Type, request.Payload}
			return response.Accept([]byte("accepted"))
		},
		"reject@test": func(response RequestResponseWriter, request *Request) error {
			observed <- observation{request.Context(), request.Server(), request.Type, request.Payload}
			return response.Reject([]byte("rejected"))
		},
	}
	session, client, cleanup := newTestSession(t, server, nil)
	defer cleanup()
	defer closeQuietly(session)

	ok, payload, err := client.SendRequest("accept@test", true, []byte("one"))
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, []byte("accepted"), payload)
	accepted := <-observed
	require.NotNil(t, accepted.context)
	require.Same(t, server, accepted.server)
	require.Equal(t, "accept@test", accepted.typeName)
	require.Equal(t, []byte("one"), accepted.payload)

	ok, payload, err = client.SendRequest("reject@test", true, []byte("two"))
	require.NoError(t, err)
	require.False(t, ok)
	require.Equal(t, []byte("rejected"), payload)
	rejected := <-observed
	require.NotNil(t, rejected.context)
	require.Same(t, server, rejected.server)
	require.Equal(t, "reject@test", rejected.typeName)
	require.Equal(t, []byte("two"), rejected.payload)
}

func TestRequestResponseWriterRecordsDecisionWithoutReply(t *testing.T) {
	reported := make(chan struct {
		wantReply bool
		err       error
	}, 1)
	_, client, cleanup := newTestSession(t, &Server{
		Handler: func(Session) error { return nil },
		RequestHandlers: map[string]RequestHandler{
			"no-reply@test": func(response RequestResponseWriter, request *Request) error {
				err := response.Accept([]byte("not transmitted"))
				reported <- struct {
					wantReply bool
					err       error
				}{request.WantReply, err}
				return err
			},
		},
	}, nil)
	defer cleanup()

	_, _, err := client.SendRequest("no-reply@test", false, nil)
	require.NoError(t, err)
	event := <-reported
	require.False(t, event.wantReply)
	require.NoError(t, event.err)
}

func TestRequestWithoutReplyNeedsNoResponse(t *testing.T) {
	handled := make(chan struct{}, 1)
	var errorHandlerCalls atomic.Int32
	_, client, cleanup := newTestSession(t, &Server{
		Handler: func(Session) error { return nil },
		RequestHandlers: map[string]RequestHandler{
			"no-reply@test": func(RequestResponseWriter, *Request) error {
				handled <- struct{}{}
				return nil
			},
		},
		ErrorHandler: func(context.Context, ErrorScope, ErrorOperation, error, ErrorResponder, ErrorHandler) (bool, error) {
			errorHandlerCalls.Add(1)
			return true, nil
		},
	}, nil)
	defer cleanup()

	_, _, err := client.SendRequest("no-reply@test", false, nil)
	require.NoError(t, err)
	<-handled
	require.Zero(t, errorHandlerCalls.Load())
}

func TestMissingRequestResponseUsesErrorHandler(t *testing.T) {
	type observation struct {
		operation ErrorOperation
		err       error
	}
	reported := make(chan observation, 1)
	_, client, cleanup := newTestSession(t, &Server{
		Handler: func(Session) error { return nil },
		RequestHandlers: map[string]RequestHandler{
			"missing@test": func(RequestResponseWriter, *Request) error { return nil },
			"next@test": func(response RequestResponseWriter, _ *Request) error {
				return response.Accept(nil)
			},
		},
		ErrorHandler: func(_ context.Context, _ ErrorScope, operation ErrorOperation, err error, respond ErrorResponder, _ ErrorHandler) (bool, error) {
			reported <- observation{operation: operation, err: err}
			if responseErr := respond([]byte("missing response"), false); responseErr != nil {
				return false, responseErr
			}
			return true, nil
		},
	}, nil)
	defer cleanup()

	ok, payload, err := client.SendRequest("missing@test", true, nil)
	require.NoError(t, err)
	require.False(t, ok)
	require.Equal(t, []byte("missing response"), payload)
	event := <-reported
	require.Equal(t, ErrorOperationReply, event.operation)
	require.ErrorIs(t, event.err, ErrRequestResponseNotSent)

	ok, _, err = client.SendRequest("next@test", true, nil)
	require.NoError(t, err)
	require.True(t, ok)
}

func TestMissingRequestResponseDefaultsToRejection(t *testing.T) {
	_, client, cleanup := newTestSession(t, &Server{
		Handler: func(Session) error { return nil },
		RequestHandlers: map[string]RequestHandler{
			"missing@test": func(RequestResponseWriter, *Request) error { return nil },
			"next@test": func(response RequestResponseWriter, _ *Request) error {
				return response.Accept(nil)
			},
		},
	}, nil)
	defer cleanup()

	ok, payload, err := client.SendRequest("missing@test", true, nil)
	require.NoError(t, err)
	require.False(t, ok)
	require.Empty(t, payload)

	ok, _, err = client.SendRequest("next@test", true, nil)
	require.NoError(t, err)
	require.True(t, ok)
}

func TestMutatingWantReplyDoesNotChangeWireContract(t *testing.T) {
	_, client, cleanup := newTestSession(t, &Server{
		Handler: func(Session) error { return nil },
		RequestHandlers: map[string]RequestHandler{
			"mutate@test": func(_ RequestResponseWriter, request *Request) error {
				request.WantReply = false
				return nil
			},
		},
		ErrorHandler: func(_ context.Context, _ ErrorScope, _ ErrorOperation, err error, respond ErrorResponder, _ ErrorHandler) (bool, error) {
			require.ErrorIs(t, err, ErrRequestResponseNotSent)
			return true, respond([]byte("still rejected"), false)
		},
	}, nil)
	defer cleanup()

	ok, payload, err := client.SendRequest("mutate@test", true, nil)
	require.NoError(t, err)
	require.False(t, ok)
	require.Equal(t, []byte("still rejected"), payload)
}

func TestExpiredRequestResponseReleasesRawRequest(t *testing.T) {
	captured := make(chan *requestResponse, 1)
	_, client, cleanup := newTestSession(t, &Server{
		Handler: func(Session) error { return nil },
		RequestHandlers: map[string]RequestHandler{
			"release@test": func(response RequestResponseWriter, _ *Request) error {
				captured <- response.(*requestResponse)
				return response.Accept(nil)
			},
		},
	}, nil)
	defer cleanup()

	ok, _, err := client.SendRequest("release@test", true, nil)
	require.NoError(t, err)
	require.True(t, ok)
	response := <-captured
	response.mu.Lock()
	raw := response.request
	response.mu.Unlock()
	require.Nil(t, raw)
	require.ErrorIs(t, response.Accept(nil), ErrRequestResponseExpired)
}

func TestRequestResponseWriterIsSingleUseAndExpires(t *testing.T) {
	request := newRequest(nil, new(Server), &gossh.Request{WantReply: false})
	require.NoError(t, request.response.Accept(nil))
	require.ErrorIs(t, request.response.Reject(nil), ErrRequestResponseAlreadySent)
	attempted, complete, accepted, err := request.response.result()
	require.True(t, attempted)
	require.True(t, complete)
	require.True(t, accepted)
	require.NoError(t, err)
	request.response.expire()
	require.ErrorIs(t, request.response.Accept(nil), ErrRequestResponseExpired)

	expired := newRequest(nil, new(Server), &gossh.Request{WantReply: false})
	expired.response.expire()
	require.ErrorIs(t, expired.response.Accept(nil), ErrRequestResponseExpired)
}

func TestConcurrentRequestResponseHasSingleWinner(t *testing.T) {
	request := newRequest(nil, new(Server), &gossh.Request{WantReply: false})
	const calls = 16
	results := make(chan error, calls)
	var started sync.WaitGroup
	started.Add(calls)
	for range calls {
		go func() {
			started.Done()
			started.Wait()
			results <- request.response.Accept(nil)
		}()
	}

	succeeded := 0
	for range calls {
		err := <-results
		if err == nil {
			succeeded++
		} else {
			require.ErrorIs(t, err, ErrRequestResponseAlreadySent)
		}
	}
	require.Equal(t, 1, succeeded)
}

func TestRequestErrorAfterResponseDoesNotSendSecondReply(t *testing.T) {
	handlerErr := errors.New("failed after response")
	reported := make(chan error, 1)
	_, client, cleanup := newTestSession(t, &Server{
		Handler: func(Session) error { return nil },
		RequestHandlers: map[string]RequestHandler{
			"responded@test": func(response RequestResponseWriter, _ *Request) error {
				require.NoError(t, response.Accept([]byte("accepted")))
				return handlerErr
			},
		},
		ErrorHandler: func(_ context.Context, _ ErrorScope, _ ErrorOperation, err error, respond ErrorResponder, _ ErrorHandler) (bool, error) {
			require.ErrorIs(t, err, handlerErr)
			reported <- respond([]byte("must not be sent"), false)
			return true, nil
		},
	}, nil)
	defer cleanup()

	ok, payload, err := client.SendRequest("responded@test", true, nil)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, []byte("accepted"), payload)
	require.ErrorIs(t, <-reported, ErrErrorResponseUnsupported)
}
