//go:build !windows

package flowseg

import "testing"

// sparse is a no-op: a write past the end leaves a hole on these systems'
// file systems (see sparse_windows_test.go).
func sparse(*testing.T, segFile) {}
