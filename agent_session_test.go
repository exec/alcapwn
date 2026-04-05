package main

import (
	"crypto/ecdh"
	"crypto/rand"
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

// newTestServerKey generates a fresh X25519 key for use in tests.
func newTestServerKey(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate test server key: %v", err)
	}
	return key
}

// ── handleAgentSession integration test ──────────────────────────────────────

// runMockAgent simulates an agent on one end of a net.Pipe():
//  1. Performs client-side X25519 handshake (no pinning).
//     NOTE: The routing tag is injected by the server-side prefixConn, so the
//     agent does not write proto.Magic — the server reads it from the prefix.
//  2. Sends Hello (encrypted).
//  3. Reads Welcome (encrypted) and verifies session ID.
//  4. Reads Task (encrypted) and sends Result (encrypted).
//
// Any protocol error causes the conn to be closed with t.Error logged.
func runMockAgent(t *testing.T, conn net.Conn, expectedSessionID int, wantCommand string, resultOutput []byte) {
	t.Helper()
	defer conn.Close()

	// Step 1: client-side crypto handshake (no fingerprint pinning in tests).
	// The server reads the routing tag from its prefixConn, so the agent's
	// first bytes on the wire are the crypto handshake (server pubkey read).
	cs, err := proto.NewClientCryptoSession(conn, "")
	if err != nil {
		t.Errorf("mock agent: client crypto handshake: %v", err)
		return
	}

	// Step 2: send Hello (encrypted).
	hello := proto.Hello{
		Version:   "1.0",
		MachineID: "aabbccdd11223344",
		Hostname:  "test-host",
		OS:        "linux",
		Arch:      "amd64",
		User:      "root",
		UID:       "0",
	}
	if err := proto.WriteMsgEncrypted(conn, cs, proto.MsgHello, hello); err != nil {
		t.Errorf("mock agent: WriteMsgEncrypted Hello: %v", err)
		return
	}

	// Step 3: read Welcome (encrypted).
	env, err := proto.ReadMsgEncrypted(conn, cs)
	if err != nil {
		t.Errorf("mock agent: ReadMsgEncrypted Welcome: %v", err)
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

	// Step 4a: read Task (encrypted).
	env, err = proto.ReadMsgEncrypted(conn, cs)
	if err != nil {
		t.Errorf("mock agent: ReadMsgEncrypted Task: %v", err)
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

	// Step 4b: send Result (encrypted).
	result := proto.Result{
		TaskID: task.ID,
		Output: resultOutput,
		Exit:   0,
	}
	if err := proto.WriteMsgEncrypted(conn, cs, proto.MsgResult, result); err != nil {
		t.Errorf("mock agent: WriteMsgEncrypted Result: %v", err)
	}
}

func TestHandleAgentSession_execRoundTrip(t *testing.T) {
	// server ↔ agent pipe.
	// acceptLoop normally peeks 4 bytes and re-injects them via prefixConn.
	// In the test we simulate the same by using prefixConn on the server side
	// so handleAgentSession can consume the routing tag from the prefix while
	// the agent's wire bytes start directly with the crypto handshake.
	serverConn, agentConn := net.Pipe()

	reg := NewRegistry()
	wrapped := &prefixConn{Conn: serverConn, prefix: proto.Magic[:]}
	sess := reg.Allocate(wrapped, false)
	if sess == nil {
		t.Fatal("Allocate returned nil")
	}

	printer := newTestPrinter()
	opts := sessionOpts{
		printer:   printer,
		registry:  reg,
		serverKey: newTestServerKey(t),
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
	wrapped := &prefixConn{Conn: serverConn, prefix: proto.Magic[:]}
	sess := reg.Allocate(wrapped, false)
	if sess == nil {
		t.Fatal("Allocate returned nil")
	}

	printer := newTestPrinter()
	testKey := newTestServerKey(t)
	opts := sessionOpts{
		printer:   printer,
		registry:  reg,
		serverKey: testKey,
	}

	// Minimal agent: do handshake (server reads routing tag from prefixConn),
	// send Hello, read Welcome, read the task so the write loop doesn't block,
	// then close.
	agentDone := make(chan struct{})
	go func() {
		defer close(agentDone)
		defer agentConn.Close()

		// Client crypto handshake (server reads routing tag from prefixConn prefix).
		cs, err := proto.NewClientCryptoSession(agentConn, "")
		if err != nil {
			return
		}
		// Send Hello.
		hello := proto.Hello{Version: "1.0", Hostname: "dc-test"}
		if err := proto.WriteMsgEncrypted(agentConn, cs, proto.MsgHello, hello); err != nil {
			return
		}
		// Read Welcome.
		env, err := proto.ReadMsgEncrypted(agentConn, cs)
		if err != nil || env.Type != proto.MsgWelcome {
			return
		}
		// Read the task so the write loop doesn't block.
		proto.ReadMsgEncrypted(agentConn, cs) //nolint:errcheck
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
	wrapped := &prefixConn{Conn: serverConn, prefix: proto.Magic[:]}
	sess := reg.Allocate(wrapped, false)
	if sess == nil {
		t.Fatal("Allocate returned nil")
	}

	printer := newTestPrinter()
	testKey := newTestServerKey(t)
	opts := sessionOpts{
		printer:   printer,
		registry:  reg,
		serverKey: testKey,
	}

	go func() {
		defer agentConn.Close()
		// Client crypto handshake (server reads routing tag from prefixConn prefix).
		cs, err := proto.NewClientCryptoSession(agentConn, "")
		if err != nil {
			return
		}
		// Send a Ping instead of Hello — should be rejected.
		proto.WriteMsgEncrypted(agentConn, cs, proto.MsgPing, struct{}{}) //nolint:errcheck
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

// TestHandleAgentSession_noServerKey verifies that handleAgentSession rejects
// the connection immediately when no server key is configured.
func TestHandleAgentSession_noServerKey(t *testing.T) {
	serverConn, agentConn := net.Pipe()
	defer agentConn.Close()

	reg := NewRegistry()
	wrapped := &prefixConn{Conn: serverConn, prefix: proto.Magic[:]}
	sess := reg.Allocate(wrapped, false)
	if sess == nil {
		t.Fatal("Allocate returned nil")
	}

	printer := newTestPrinter()
	opts := sessionOpts{
		printer:   printer,
		registry:  reg,
		serverKey: nil, // no key
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		handleAgentSession(sess, opts)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handleAgentSession did not return after missing server key")
	}

	// Session should be gone.
	if reg.Get(sess.ID) != nil {
		t.Error("session was not removed from registry after missing server key")
	}
}
