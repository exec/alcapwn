package main

import (
	"fmt"
	"sync"
	"time"
)

type taskStatus int

const (
	taskPending  taskStatus = iota
	taskRunning             // spinning, white
	taskRetrying            // spinning, yellow
	taskDone                // static ✓, green
	taskFailed              // static ✗, red
)

var spinFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠣", "⠏"}

type statusLine struct {
	label  string
	status taskStatus
	detail string // shown after label, e.g. "█████░░░░░  6/13  CRON JOBS"
}

type statusDisplay struct {
	mu       sync.Mutex
	lines    []statusLine
	rendered int    // lines written in last render pass
	frame    int    // current spinner frame index
	stopCh   chan struct{}
	doneCh   chan struct{}
	stopOnce sync.Once
}

func newStatusDisplay() *statusDisplay {
	d := &statusDisplay{
		stopCh: make(chan struct{}),
		doneCh: make(chan struct{}),
	}
	go d.spinLoop()
	return d
}

// spinLoop ticks the spinner frame and re-renders every 80 ms.
func (d *statusDisplay) spinLoop() {
	defer close(d.doneCh)
	ticker := time.NewTicker(80 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-d.stopCh:
			return
		case <-ticker.C:
			d.mu.Lock()
			d.frame = (d.frame + 1) % len(spinFrames)
			d.renderLocked()
			d.mu.Unlock()
		}
	}
}

// stop halts the spinner goroutine and waits for it to exit.
// Call this before clear() or before printing any output. Safe to call multiple times.
func (d *statusDisplay) stop() {
	d.stopOnce.Do(func() {
		close(d.stopCh)
		<-d.doneCh
	})
}

// addTask appends a pending task, renders immediately, and returns its index.
func (d *statusDisplay) addTask(label string) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	idx := len(d.lines)
	d.lines = append(d.lines, statusLine{label: label})
	d.renderLocked()
	return idx
}

// set updates a task's status and detail text, then re-renders.
func (d *statusDisplay) set(idx int, s taskStatus, detail string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if idx >= 0 && idx < len(d.lines) {
		d.lines[idx].status = s
		d.lines[idx].detail = detail
		d.renderLocked()
	}
}

// clear erases all rendered task lines. Call after stop().
func (d *statusDisplay) clear() {
	d.mu.Lock()
	defer d.mu.Unlock()
	for i := 0; i < d.rendered; i++ {
		fmt.Print("\x1b[1A\x1b[2K")
	}
	if d.rendered > 0 {
		fmt.Print("\r")
	}
	d.rendered = 0
}

func (d *statusDisplay) renderLocked() {
	// Move cursor up to overwrite previous render.
	if d.rendered > 0 {
		fmt.Printf("\x1b[%dA", d.rendered)
	}
	for _, l := range d.lines {
		var sym, clr string
		switch l.status {
		case taskPending:
			sym = "·"
			clr = "\033[90m" // dark grey
		case taskRunning:
			sym = spinFrames[d.frame]
			clr = "\033[97m" // bright white
		case taskRetrying:
			sym = spinFrames[d.frame]
			clr = "\033[33m" // yellow
		case taskDone:
			sym = "✓"
			clr = "\033[32m" // green
		case taskFailed:
			sym = "✗"
			clr = "\033[31m" // red
		}
		detail := ""
		if l.detail != "" {
			detail = "  " + l.detail
		}
		// %-18s left-pads label to fixed width so detail always starts in the same column.
		// \x1b[K clears the rest of the line so leftover chars from longer previous renders vanish.
		fmt.Printf("  %s%s\033[0m  %-18s\033[90m%s\033[0m\x1b[K\n", clr, sym, l.label, detail)
	}
	d.rendered = len(d.lines)
}
