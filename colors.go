package main

import "fmt"

// ANSI color codes.
// Applied only to alcapwn's own output — never to remote-derived strings
// (those go through stripDangerousAnsi before display).
const (
	ansiReset  = "\x1b[0m"
	ansiBold   = "\x1b[1m"
	ansiDim    = "\x1b[2m"
	ansiRed    = "\x1b[31m"
	ansiGreen  = "\x1b[32m"
	ansiYellow = "\x1b[33m"
	ansiCyan   = "\x1b[36m"
	ansiGrey   = "\x1b[90m"

	ansiBoldRed    = "\x1b[1;31m"
	ansiBoldGreen  = "\x1b[1;32m"
	ansiBoldYellow = "\x1b[1;33m"
	ansiBoldCyan   = "\x1b[1;36m"
)

// colorizePrefixed colors the leading [+]/[!]/[*]/[-]/[i] bracket of a
// message, leaving the rest of the string unchanged.
//
//	[+] → green   (success / session opened / root achieved)
//	[!] → red     (error / warning)
//	[*] → cyan    (status / progress)
//	[-] → yellow  (negative result, not an error)
//	[i] → grey    (advisory tip)
func colorizePrefixed(s string) string {
	if len(s) < 3 {
		return s
	}
	var code string
	switch s[:3] {
	case "[+]":
		code = ansiGreen
	case "[!]":
		code = ansiRed
	case "[*]":
		code = ansiCyan
	case "[-]":
		code = ansiYellow
	case "[i]":
		code = ansiGrey
	default:
		return s
	}
	return code + s[:3] + ansiReset + s[3:]
}

// cprintf formats a message, applies prefix colorization, and prints with a
// trailing newline.  Only call from the main command goroutine — background
// goroutines must use printer.Notify which holds the consolePrinter mutex.
func cprintf(format string, args ...interface{}) {
	fmt.Println(colorizePrefixed(fmt.Sprintf(format, args...)))
}
