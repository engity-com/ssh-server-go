package ssh

import (
	"context"
	"io"
	"sync"
	"time"
)

type closeWriter interface {
	CloseWrite() error
}

// FullDuplexCopyOpts defines optional callbacks for observing a bidirectional copy.
type FullDuplexCopyOpts struct {
	OnStart       func()
	OnEnd         func(l2r, r2l int64, duration time.Duration, err error, wasInL2r *bool)
	OnStreamStart func(isL2r bool)
	OnStreamEnd   func(isL2r bool, err error)
}

// FullDuplexCopy copies data in both directions until both streams finish.
// It half-closes completed streams and closes both sides on cancellation or error.
func FullDuplexCopy(ctx context.Context, left io.ReadWriteCloser, right io.ReadWriteCloser, opts *FullDuplexCopyOpts) (rErr error) {
	type done struct {
		wasL2r  bool
		written int64
		error   error
	}
	dones := make(chan done, 2)
	var errWasInL2r *bool
	var l2r, r2l int64
	started := time.Now()
	defer func() {
		if opts != nil {
			if f := opts.OnEnd; f != nil {
				f(l2r, r2l, time.Since(started), rErr, errWasInL2r)
			}
		}
	}()

	copyFull := func(from io.Reader, to io.Writer, isL2r bool) {
		if opts != nil {
			if f := opts.OnStreamStart; f != nil {
				f(isL2r)
			}
		}

		var err error
		n, err := io.Copy(to, from)
		if !isRelevantIoError(err) {
			err = nil
		}

		if err == nil {
			if cw, ok := to.(closeWriter); ok {
				err = cw.CloseWrite()
				if !isRelevantIoError(err) {
					err = nil
				}
			}
		}

		if opts != nil {
			if f := opts.OnStreamEnd; f != nil {
				f(isL2r, err)
			}
		}
		dones <- done{wasL2r: isL2r, written: n, error: err}
	}
	go copyFull(right, left, false)
	go copyFull(left, right, true)

	if opts != nil {
		if f := opts.OnStart; f != nil {
			f()
		}
	}

	closeStreams := sync.OnceFunc(func() {
		closeQuietly(left)
		closeQuietly(right)
	})
	ctxDone := ctx.Done()
	for completed := 0; completed < 2; {
		select {
		case <-ctxDone:
			ctxDone = nil
			closeStreams()
		case v := <-dones:
			completed++
			if v.wasL2r {
				l2r = v.written
			} else {
				r2l = v.written
			}
			if v.error != nil && rErr == nil {
				errWasInL2r = &v.wasL2r
				rErr = v.error
				closeStreams()
			}
		}
	}
	return rErr
}
