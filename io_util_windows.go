//go:build windows

package ssh

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

func _isClosedError(err error) bool {
	var sce = &os.SyscallError{}
	if errors.As(err, &sce) && sce.Err != nil {
		switch //goland:noinspection GoDirectComparisonOfErrors
		sce.Err {
		case windows.WSAECONNRESET, windows.WSAECONNABORTED:
			return true
		}
	}

	return false

}
