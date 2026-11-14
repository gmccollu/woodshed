//go:build windows

package main

import (
	"io/fs"
	"strings"
	"testing"
)

func ownerOf(fs.FileInfo) string { return "" }

func TestAccessDeniedMessageWindows(t *testing.T) {
	dir := t.TempDir()
	msg := accessDenied(dir, "woodshed search link")
	if !strings.HasPrefix(msg, "Can't read "+dir) || !strings.HasSuffix(msg, ". Run it in an administrator prompt.") ||
		!strings.Contains(msg, "(owner ") {
		t.Fatalf("%q", msg)
	}
}
