package ssh

import (
	"context"
	"errors"
	"sync"

	gossh "golang.org/x/crypto/ssh"
)

var (
	ErrRequestResponseAlreadySent = errors.New("ssh: request response was already sent")
	ErrRequestResponseExpired     = errors.New("ssh: request response is no longer valid")
	ErrRequestResponseIncomplete  = errors.New("ssh: request response did not complete synchronously")
	ErrRequestResponseNotSent     = errors.New("ssh: request handler returned without a response")
)

// Request contains one connection-level SSH request. Payload remains valid for
// the duration of the RequestHandler call and must not be retained or modified.
type Request struct {
	Type      string
	Payload   []byte
	WantReply bool

	ctx       Context
	server    *Server
	wantReply bool
	response  *requestResponse
}

// Context returns the SSH connection context associated with this request.
func (r *Request) Context() Context {
	if r == nil {
		return nil
	}
	return r.ctx
}

// Server returns the server handling this request.
func (r *Request) Server() *Server {
	if r == nil {
		return nil
	}
	return r.server
}

// RequestResponseWriter completes a request with either acceptance or
// rejection. Each writer is valid only during its RequestHandler call and may
// be completed at most once. When Request.WantReply is false, the decision is
// recorded without writing a protocol reply.
type RequestResponseWriter interface {
	Accept(payload []byte) error
	Reject(message []byte) error
}

// RequestHandler handles one connection-level SSH request. A returned error is
// passed to ErrorHandler. A request that wants a reply must be completed through
// response before the handler returns.
type RequestHandler func(response RequestResponseWriter, request *Request) error

type requestResponse struct {
	mu        sync.Mutex
	request   *gossh.Request
	active    bool
	attempted bool
	complete  bool
	accepted  bool
	err       error
	done      chan struct{}
}

func newRequest(ctx Context, server *Server, raw *gossh.Request) *Request {
	request := &Request{
		Type:      raw.Type,
		Payload:   raw.Payload,
		WantReply: raw.WantReply,
		ctx:       ctx,
		server:    server,
		wantReply: raw.WantReply,
	}
	request.response = &requestResponse{
		request: raw,
		active:  true,
		done:    make(chan struct{}),
	}
	return request
}

func (r *requestResponse) Accept(payload []byte) error {
	return r.respond(true, payload, true)
}

func (r *requestResponse) Reject(message []byte) error {
	return r.respond(false, message, true)
}

func (r *requestResponse) rejectFromErrorHandler(message []byte) error {
	err := r.respond(false, message, false)
	if errors.Is(err, ErrRequestResponseAlreadySent) {
		return ErrErrorResponseUnsupported
	}
	return err
}

func (r *requestResponse) respond(accepted bool, payload []byte, requireActive bool) error {
	r.mu.Lock()
	if requireActive && !r.active {
		r.mu.Unlock()
		return ErrRequestResponseExpired
	}
	if r.attempted || r.complete {
		r.mu.Unlock()
		return ErrRequestResponseAlreadySent
	}
	r.attempted = true
	r.accepted = accepted
	request := r.request
	r.mu.Unlock()

	var err error
	if request != nil && request.WantReply {
		err = request.Reply(accepted, payload)
		if err != nil {
			err = locateError(ErrorScopeRequest, ErrorOperationReply, err)
		}
	}

	r.mu.Lock()
	r.complete = true
	r.err = err
	close(r.done)
	r.mu.Unlock()
	return err
}

func (r *requestResponse) expire() {
	r.mu.Lock()
	r.active = false
	r.mu.Unlock()
}

func (r *requestResponse) release() {
	r.mu.Lock()
	r.active = false
	r.request = nil
	r.mu.Unlock()
}

func (r *requestResponse) completeWithoutResponse() {
	r.mu.Lock()
	if !r.attempted && !r.complete {
		r.complete = true
		close(r.done)
	}
	r.mu.Unlock()
}

func (r *requestResponse) result() (attempted, complete, accepted bool, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.attempted, r.complete, r.accepted, r.err
}

func (r *requestResponse) wait(ctx context.Context) (accepted bool, err error) {
	select {
	case <-r.done:
		_, complete, accepted, err := r.result()
		if !complete {
			return false, ErrRequestResponseIncomplete
		}
		return accepted, err
	case <-ctx.Done():
		return false, context.Cause(ctx)
	}
}
