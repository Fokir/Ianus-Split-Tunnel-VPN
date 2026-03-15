//go:build windows

package main

import (
	"os"

	"golang.org/x/sys/windows"
)

// redirectStderr redirects the OS-level stderr (fd 2) to the given file.
// This ensures that Go runtime panic stack traces (which bypass the log
// package and write directly to fd 2) are captured in the log file.
func redirectStderr(f *os.File) error {
	return windows.SetStdHandle(windows.STD_ERROR_HANDLE, windows.Handle(f.Fd()))
}
