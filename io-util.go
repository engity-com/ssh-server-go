package ssh

import (
	"errors"
	"io"
	"net"
	"syscall"
)

func isClosedError(err error) bool {
	if err == nil {
		return false
	}

	if errors.Is(err, io.ErrClosedPipe) || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return true
	}

	if _isClosedError(err) {
		return true
	}

	if noe, ok := errors.AsType[*net.OpError](err); ok && noe.Err != nil {
		switch noe.Err.Error() {
		case "use of closed network connection":
			return true
		}
	}

	return false
}

func isRelevantIoError(err error) bool {
	return err != nil && !errors.Is(err, syscall.EIO) && !isClosedError(err)
}

func closeQuietly(c io.Closer) {
	if c == nil {
		return
	}
	_ = c.Close()
}
