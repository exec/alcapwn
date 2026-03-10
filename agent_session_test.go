package main

import (
	"encoding/json"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"alcapwn/proto"
)

// ── agentTaskID ───────────────────────────────────────────────────────────────

func TestAgentTaskID_nonEmpty(t *testing.T) {
	id := agentTaskID("ex", "id")
	if id == "" {
		t.Fatal("agentTaskID returned empty string")
	}
}

func TestAgentTaskID_prefixPresent(t *testing.T) {
	id := agentTaskID("dl", "/etc/passwd")
	if !strings.HasPrefix(id, "dl") {
		t.Fatalf("expected id to start with prefix %q, got %q", "dl", id)
	}
}

func TestAgentTaskID_differentContent(t *testing.T) {
	id1 := agentTaskID("ex", "id")
	id2 := agentTaskID("ex", "whoami")
	// Different content should produce different IDs (different len portion).
	// Note: same content can collide within same nanosecond in theory, but
	// different length content guarantees different hex suffix.
	if id1 == id2 {
		t.Fatalf("expected different IDs for different content lengths, got %q and %q", id1, id2)
	}
}

func TestAgentTaskID_differentPrefixes(t *testing.T) {
	id1 := agentTaskID("ex", "cmd")
	id2 := agentTaskID("dl", "cmd")
	if id1 == id2 {
		t.Fatalf("expected different IDs for different prefixes, got both %q", id1)
	}
}

// ── agentDispatch: nil channel ────────────────────────────────────────────────

func TestAgentDispatch_nilChannel(t *testing.T) {
	reg := NewRegistry()
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	sess := reg.Allocate(c1, false)
	if sess == nil {
		t.Fatal("Allocate returned nil")
	}
	// agentTaskCh is nil by default → dispatch should return an error immediately.
	_, err := agentDispatch(sess, proto.Task{
		ID:      agentTaskID("ex", "id"),
		Kind:    proto.TaskExec,
		Command: "id",
	}, 2*time.Second)
	if err == nil {
		t.Fatal("expected error for nil agentTaskCh")
	}
	if !strings.Contains(err.Error(), "not initialised") {
		t.Fatalf("expected 'not initialised' error, got: %v", err)
	}
}

// ── newTestPrinter ────────────────────────────────────────────────────────────

// newTestPrinter creates a consolePrinter backed by a minimal Console.
// Notify() will write to stdout (harmless in tests).
func newTestPrinter() *consolePrinter {
	c := &Console{
		registry:          NewRegistry(),
		listeners:         newListenerRegistry(),
		pendingTLSUpgrade: make(map[string]chan net.Conn),
		editor:            newLineEditor(int(os.Stdin.Fd())),
		persist:           NewPersistenceStore(),
		config:            &Config{AutoOpenListeners: true},
		firewalls:         NewFirewallStore(),
	}
	return &consolePrinter{console: c}
}

// ── handleAgentSession integration test ──────────────────────────────────────

// mockAgent simulates an agent on one end of a net.Pipe():
//  1. Sends Hello.
//  2. Reads Welcome and verifies session ID.
//  3. Reads Task and sends Result.
//
// Any protocol error causes the conn to be closed with t.Error logged.
func runMockAgent(t *testing.T, conn net.Conn, expectedSessionID int, wantCommand string, resultOutput []byte) {
	t.Helper()
	defer conn.Close()

	hello := proto.Hello{
		Version:   "1.0",
		MachineID: "aabbccdd11223344",
		Hostname:  "test-host",
		OS:        "linux",
		Arch:      "amd64",
		User:      "root",
		UID:       "0",
	}
	if err := proto.WriteMsg(conn, proto.MsgHello, hello); err != nil {
		t.Errorf("mock agent: WriteMsg Hello: %v", err)
		return
	}

	env, err := proto.ReadMsg(conn)
	if err != nil {
		t.Errorf("mock agent: ReadMsg Welcome: %v", err)
		return
	}
	if env.Type != proto.MsgWelcome {
		t.Errorf("mock agent: expected welcome, got %q", env.Type)
		return
	}
	var welcome proto.Welcome
	if err := json.Unmarshal(env.Data, &welcome); err != nil {
		t.Errorf("mock agent: unmarshal Welcome: %v", err)
		return
	}
	if welcome.SessionID != expectedSessionID {
		t.Errorf("mock agent: welcome session_id: want %d got %d", expectedSessionID, welcome.SessionID)
	}

	// Read Task.
	env, err = proto.ReadMsg(conn)
	if err != nil {
		t.Errorf("mock agent: ReadMsg Task: %v", err)
		return
	}
	if env.Type != proto.MsgTask {
		t.Errorf("mock agent: expected task, got %q", env.Type)
		return
	}
	var task proto.Task
	if err := json.Unmarshal(env.Data, &task); err != nil {
		t.Errorf("mock agent: unmarshal Task: %v", err)
		return
	}
	if task.Command != wantCommand {
		t.Errorf("mock agent: task command: want %q got %q", wantCommand, task.Command)
	}

	// Send Result.
	result := proto.Result{
		TaskID: task.ID,
		Output: resultOutput,
		Exit:   0,
	}
	if err := proto.WriteMsg(conn, proto.MsgResult, result); err != nil {
		t.Errorf("mock agent: WriteMsg Result: %v", err)
	}
}

func TestHandleAgentSession_execRoundTrip(t *testing.T) {
	// server ↔ agent pipe
	serverConn, agentConn := net.Pipe()

	reg := NewRegistry()
	sess := reg.Allocate(serverConn, false)
	if sess == nil {
		t.Fatal("Allocate returned nil")
	}

	printer := newTestPrinter()
	opts := sessionOpts{
		printer:  printer,
		registry: reg,
	}

	const command = "id"
	wantOutput := []byte("uid=0(root) gid=0(root) groups=0(root)")

	// Start mock agent goroutine.
	agentDone := make(chan struct{})
	go func() {
		defer close(agentDone)
		runMockAgent(t, agentConn, sess.ID, command, wantOutput)
	}()

	// Start handleAgentSession in its own goroutine (matches acceptLoop usage).
	go handleAgentSession(sess, opts)

	// Wait briefly for session setup (Hello/Welcome exchange + agentTaskCh init).
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		sess.mu.Lock()
		ready := sess.IsAgent && sess.agentTaskCh != nil
		sess.mu.Unlock()
		if ready {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	sess.mu.Lock()
	ready := sess.IsAgent && sess.agentTaskCh != nil
	sess.mu.Unlock()
	if !ready {
		t.Fatal("timed out waiting for agent session to become ready")
	}

	// Issue exec via agentExec.
	res, err := agentExec(sess, command, 5*time.Second)
	if err != nil {
		t.Fatalf("agentExec: %v", err)
	}
	if string(res.Output) != string(wantOutput) {
		t.Fatalf("result output: want %q got %q", string(wantOutput), string(res.Output))
	}
	if res.Exit != 0 {
		t.Fatalf("result exit: want 0 got %d", res.Exit)
	}

	// Wait for mock agent to finish.
	select {
	case <-agentDone:
	case <-time.After(5 * time.Second):
		t.Error("mock agent goroutine did not complete in time")
	}
}

// TestHandleAgentSession_disconnect verifies that when the agent closes the
// connection, any pending task receives an "agent disconnected" error result.
func TestHandleAgentSession_disconnect(t *testing.T) {
	serverConn, agentConn := net.Pipe()

	reg := NewRegistry()
	sess := reg.Allocate(serverConn, false)
	if sess == nil {
		t.Fatal("Allocate returned nil")
	}

	printer := newTestPrinter()
	opts := sessionOpts{
		printer:  printer,
		registry: reg,
	}

	// Minimal agent: send Hello, read Welcome, then close without sending Result.
	agentDone := make(chan struct{})
	go func() {
		defer close(agentDone)
		defer agentConn.Close()

		hello := proto.Hello{Version: "1.0", Hostname: "dc-test"}
		if err := proto.WriteMsg(agentConn, proto.MsgHello, hello); err != nil {
			return
		}
		env, err := proto.ReadMsg(agentConn)
		if err != nil || env.Type != proto.MsgWelcome {
			return
		}
		// Read the task so the write loop doesn't block.
		proto.ReadMsg(agentConn) //nolint:errcheck
		// Disconnect immediately after receiving task (simulate crash).
	}()

	go handleAgentSession(sess, opts)

	// Wait for session ready.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		sess.mu.Lock()
		ready := sess.IsAgent && sess.agentTaskCh != nil
		sess.mu.Unlock()
		if ready {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	sess.mu.Lock()
	ready := sess.IsAgent && sess.agentTaskCh != nil
	sess.mu.Unlock()
	if !ready {
		t.Fatal("timed out waiting for agent session to become ready")
	}

	// Send a task; the agent will disconnect, so the result should carry an error.
	res, err := agentExec(sess, "id", 5*time.Second)
	if err != nil {
		// A timeout error is also acceptable — the agent disconnected.
		t.Logf("agentExec returned error (expected): %v", err)
		return
	}
	if res.Error == "" {
		t.Fatalf("expected non-empty error in Result after agent disconnect, got output=%q", string(res.Output))
	}

	select {
	case <-agentDone:
	case <-time.After(5 * time.Second):
		t.Error("mock agent goroutine did not complete in time")
	}
}

// TestHandleAgentSession_badHello verifies that a connection sending a non-Hello
// first message is rejected and the session is removed from the registry.
func TestHandleAgentSession_badHello(t *testing.T) {
	serverConn, agentConn := net.Pipe()

	reg := NewRegistry()
	sess := reg.Allocate(serverConn, false)
	if sess == nil {
		t.Fatal("Allocate returned nil")
	}

	printer := newTestPrinter()
	opts := sessionOpts{
		printer:  printer,
		registry: reg,
	}

	go func() {
		defer agentConn.Close()
		// Send a Ping instead of Hello — should be rejected.
		proto.WriteMsg(agentConn, proto.MsgPing, struct{}{}) //nolint:errcheck
	}()

	done := make(chan struct{})
	go func() {
		defer close(done)
		handleAgentSession(sess, opts)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handleAgentSession did not return after bad Hello")
	}

	// Session should have been removed from the registry.
	if reg.Get(sess.ID) != nil {
		t.Error("session was not removed from registry after bad Hello")
	}
}
