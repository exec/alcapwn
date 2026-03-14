//go:build linux

package main

import "golang.org/x/sys/unix"

// fdSet sets the bit for fd in fds.
// On Linux, FdSet.Bits is [16]int64 — one bit per fd, 64 fds per element.
func fdSet(fds *unix.FdSet, fd int) {
	fds.Bits[fd>>6] |= int64(1) << (uint(fd) & 63)
}
