//go:build !unix && !windows

package ssh

func _isClosedError(err error) bool {
	return false
}
