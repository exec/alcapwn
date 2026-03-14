//go:build darwin

package main

import "golang.org/x/sys/unix"

// makeInputRaw is the macOS implementation. Identical logic to the Linux
// version but uses TIOCGETA/TIOCSETA instead of TCGETS/TCSETS.
func makeInputRaw(fd int) (restore func(), err error) {
	termios, err := unix.IoctlGetTermios(fd, unix.TIOCGETA)
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

	if err := unix.IoctlSetTermios(fd, unix.TIOCSETA, termios); err != nil {
		return func() {}, err
	}
	return func() {
		unix.IoctlSetTermios(fd, unix.TIOCSETA, &saved) //nolint:errcheck
	}, nil
}
