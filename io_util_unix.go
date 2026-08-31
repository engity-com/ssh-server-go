//go:build unix

package ssh

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func _isClosedError(err error) bool {
	var sce = &os.SyscallError{}
	if errors.As(err, &sce) && sce.Err != nil {
		switch sce.Err {
		case unix.EPIPE:
			return true
		}
	}
	return false
}
