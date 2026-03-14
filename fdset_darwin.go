//go:build darwin

package main

import "golang.org/x/sys/unix"

// fdSet sets the bit for fd in fds.
// On macOS, FdSet.Bits is [32]int32 — one bit per fd, 32 fds per element.
func fdSet(fds *unix.FdSet, fd int) {
	fds.Bits[fd>>5] |= int32(1) << (uint(fd) & 31)
}
