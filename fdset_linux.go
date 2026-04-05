//go:build linux

package main

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

// fdSet sets the bit for fd in fds.
// On 64-bit Linux FdSet.Bits is [16]int64; on 32-bit it is [32]int32.
// Using the element's own bit width makes this portable across GOARCH.
func fdSet(fds *unix.FdSet, fd int) {
	const bitsPerWord = 8 * int(unsafe.Sizeof(fds.Bits[0]))
	fds.Bits[fd/bitsPerWord] |= 1 << (uint(fd) % uint(bitsPerWord))
}
