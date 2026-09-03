package ssh

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"
)

type closeWriter interface {
	CloseWrite() error
}

// FullDuplexCopyOpts defines optional callbacks for observing a bidirectional
// copy. Callbacks are invoked asynchronously in event order on one observer
// goroutine and cannot delay FullDuplexCopy. They must still return promptly to
// avoid retaining that observer goroutine.
type FullDuplexCopyOpts struct {
	OnStart       func()
	OnEnd         func(l2r, r2l int64, duration time.Duration, err error, wasInL2r *bool)
	OnStreamStart func(isL2r bool)
	OnStreamEnd   func(isL2r bool, err error)
}

// FullDuplexCopy copies data in both directions until both streams finish. It
// half-closes completed streams and closes both sides on cancellation or error.
// To guarantee cancellation, Close on each side must unblock concurrent Read and
// Write calls; implementations that do not honor that contract can prevent this
// function from returning. A nil context is treated as context.Background.
func FullDuplexCopy(ctx context.Context, left io.ReadWriteCloser, right io.ReadWriteCloser, opts *FullDuplexCopyOpts) (rErr error) {
	if left == nil || right == nil {
		return errors.New("ssh: FullDuplexCopy requires two non-nil streams")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	type done struct {
		wasL2r  bool
		written int64
		error   error
	}
	dones := make(chan done, 2)
	var errWasInL2r *bool
	var l2r, r2l int64
	started := time.Now()
	observer := make(chan func(), 6)
	go func() {
		for callback := range observer {
			func() {
				defer func() { _ = recover() }()
				callback()
			}()
		}
	}()
	observe := func(callback func()) {
		if callback != nil {
			observer <- callback
		}
	}
	defer close(observer)
	defer func() {
		if opts != nil {
			if f := opts.OnEnd; f != nil {
				l2rFinal, r2lFinal := l2r, r2l
				duration, errFinal, directionFinal := time.Since(started), rErr, errWasInL2r
				observe(func() { f(l2rFinal, r2lFinal, duration, errFinal, directionFinal) })
			}
		}
	}()

	closeStreams := sync.OnceFunc(func() {
		closeQuietly(left)
		closeQuietly(right)
	})
	copyFull := func(from io.Reader, to io.Writer, isL2r bool) {
		if opts != nil {
			if f := opts.OnStreamStart; f != nil {
				observe(func() { f(isL2r) })
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
			} else {
				closeStreams()
			}
		}

		if opts != nil {
			if f := opts.OnStreamEnd; f != nil {
				observe(func() { f(isL2r, err) })
			}
		}
		dones <- done{wasL2r: isL2r, written: n, error: err}
	}
	if opts != nil {
		if f := opts.OnStart; f != nil {
			observe(f)
		}
	}
	go copyFull(right, left, false)
	go copyFull(left, right, true)

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
