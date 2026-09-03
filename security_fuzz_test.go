package ssh

import (
	"errors"
	"fmt"
	"testing"
)

func FuzzErrorTreeClassification(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0})
	f.Add([]byte{1, 0, 1})
	f.Add([]byte{2})
	f.Add([]byte{0, 1, 2, 0})

	f.Fuzz(func(t *testing.T, operations []byte) {
		if len(operations) > 64 {
			t.Skip()
		}
		target := errors.New("target")
		other := errors.New("other")
		tree := error(target)
		onlyTarget := true
		for _, operation := range operations {
			switch operation % 4 {
			case 0:
				tree = fmt.Errorf("wrapped: %w", tree)
			case 1:
				tree = errors.Join(tree, target)
			case 2:
				tree = errors.Join(tree, other)
				onlyTarget = false
			case 3:
				tree = errors.Join(fmt.Errorf("wrapped: %w", target), tree)
			}
		}
		if got := isOnlyError(tree, target); got != onlyTarget {
			t.Fatalf("isOnlyError() = %v, want %v for operations %v", got, onlyTarget, operations)
		}
	})
}
