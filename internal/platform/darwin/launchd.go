//go:build darwin

package darwin

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// InheritLaunchdSocket retrieves inherited file descriptors passed by launchd
// via the LAUNCH_DAEMON_SOCKET_FDS / __LAUNCHD_FD environment mechanism.
//
// launchd sets the environment variable LAUNCH_DAEMON_SOCKET_FDS (or passes
// fds starting from fd 3) when socket activation is configured in the plist.
// We use the pure-Go approach: check for the env var set by
// launch_activate_socket's contract — launchd passes fd 3 when a single
// socket is configured.
func InheritLaunchdSocket() (net.Listener, error) {
	// Method 1: Check LAUNCHD_SOCKET_FDS env var (set by some wrappers).
	if fdsStr := os.Getenv("LAUNCHD_SOCKET_FDS"); fdsStr != "" {
		parts := strings.Split(fdsStr, ":")
		if len(parts) > 0 {
			fd, err := strconv.Atoi(parts[0])
			if err == nil {
				return listenerFromFD(fd)
			}
		}
	}

	// Method 2: Standard launchd fd inheritance — fd 3.
	// launchd passes the socket as fd 3 when a single Sockets entry is configured.
	// We verify by checking if fd 3 is a valid socket.
	const launchdFD = 3
	if isSocket(launchdFD) {
		return listenerFromFD(launchdFD)
	}

	return nil, fmt.Errorf("no launchd socket found")
}

// isSocket checks if the given file descriptor is a socket.
func isSocket(fd int) bool {
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil {
		return false
	}
	return stat.Mode&syscall.S_IFMT == syscall.S_IFSOCK
}

// listenerFromFD creates a net.Listener from a raw file descriptor.
func listenerFromFD(fd int) (net.Listener, error) {
	// Ensure the FD is set to close-on-exec.
	syscall.CloseOnExec(fd)

	f := os.NewFile(uintptr(fd), "launchd-socket")
	if f == nil {
		return nil, fmt.Errorf("invalid fd %d", fd)
	}

	ln, err := net.FileListener(f)
	f.Close() // FileListener dups the fd, so we close the original.
	if err != nil {
		return nil, fmt.Errorf("fd %d → listener: %w", fd, err)
	}
	return ln, nil
}
