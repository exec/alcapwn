//go:build linux

package main

import "golang.org/x/sys/unix"

// makeInputRaw transitions fd to "input-raw" mode: character-by-character
// reads, echo off, ISIG off — but output post-processing (OPOST/ONLCR) is
// intentionally left enabled so \n still produces CRLF.
//
// term.MakeRaw also clears OPOST, which breaks every goroutine that writes a
// bare \n (spinner, consolePrinter.Notify, etc.) because those \n bytes are
// no longer translated to \r\n by the kernel, causing lines to stack up at
// their starting column instead of returning to column 0.
func makeInputRaw(fd int) (restore func(), err error) {
	termios, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return func() {}, err
	}
	saved := *termios

	termios.Iflag &^= unix.IGNBRK | unix.BRKINT | unix.PARMRK | unix.ISTRIP |
		unix.INLCR | unix.IGNCR | unix.ICRNL | unix.IXON
	// Oflag: intentionally unchanged — keep OPOST + ONLCR.
	termios.Lflag &^= unix.ECHO | unix.ECHONL | unix.ICANON | unix.ISIG | unix.IEXTEN
	termios.Cflag &^= unix.CSIZE | unix.PARENB
	termios.Cflag |= unix.CS8
	termios.Cc[unix.VMIN] = 1
	termios.Cc[unix.VTIME] = 0

	if err := unix.IoctlSetTermios(fd, unix.TCSETS, termios); err != nil {
		return func() {}, err
	}
	return func() {
		unix.IoctlSetTermios(fd, unix.TCSETS, &saved) //nolint:errcheck
	}, nil
}
