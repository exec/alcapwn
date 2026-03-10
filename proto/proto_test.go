package proto

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

// ── IsAgentHandshake ──────────────────────────────────────────────────────────

func TestIsAgentHandshake_nil(t *testing.T) {
	if IsAgentHandshake(nil) {
		t.Fatal("expected false for nil slice")
	}
}

func TestIsAgentHandshake_empty(t *testing.T) {
	if IsAgentHandshake([]byte{}) {
		t.Fatal("expected false for empty slice")
	}
}

func TestIsAgentHandshake_short(t *testing.T) {
	if IsAgentHandshake([]byte{'A', 'L', 'C'}) {
		t.Fatal("expected false for 3-byte slice")
	}
}

func TestIsAgentHandshake_exact(t *testing.T) {
	if !IsAgentHandshake([]byte{'A', 'L', 'C', 'A'}) {
		t.Fatal("expected true for exact magic bytes")
	}
}

func TestIsAgentHandshake_longer(t *testing.T) {
	buf := []byte{'A', 'L', 'C', 'A', 0x00, 0x00, 0x00, 0x05}
	if !IsAgentHandshake(buf) {
		t.Fatal("expected true for buffer longer than 4 bytes with magic")
	}
}

func TestIsAgentHandshake_wrong(t *testing.T) {
	cases := [][]byte{
		{'a', 'l', 'c', 'a'}, // lowercase
		{'A', 'L', 'C', 'B'}, // last byte wrong
		{'X', 'L', 'C', 'A'}, // first byte wrong
		{0x00, 0x00, 0x00, 0x00},
	}
	for _, c := range cases {
		if IsAgentHandshake(c) {
			t.Fatalf("expected false for %v", c)
		}
	}
}

// ── WriteMsg ──────────────────────────────────────────────────────────────────

func TestWriteMsg_frameLayout(t *testing.T) {
	var buf bytes.Buffer
	payload := Hello{Version: "1.0", Hostname: "testhost"}
	if err := WriteMsg(&buf, MsgHello, payload); err != nil {
		t.Fatalf("WriteMsg returned error: %v", err)
	}
	b := buf.Bytes()
	if len(b) < 8 {
		t.Fatalf("frame too short: %d bytes", len(b))
	}
	// Check magic
	if [4]byte(b[0:4]) != Magic {
		t.Fatalf("magic mismatch: got %x", b[0:4])
	}
	// Check length field matches actual body length
	bodyLen := binary.BigEndian.Uint32(b[4:8])
	if int(bodyLen) != len(b)-8 {
		t.Fatalf("length field %d does not match body length %d", bodyLen, len(b)-8)
	}
}

func TestWriteMsg_envelopeType(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteMsg(&buf, MsgPing, struct{}{}); err != nil {
		t.Fatalf("WriteMsg error: %v", err)
	}
	body := buf.Bytes()[8:]
	var env Envelope
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	if env.Type != MsgPing {
		t.Fatalf("expected type %q, got %q", MsgPing, env.Type)
	}
}

func TestWriteMsg_writerError(t *testing.T) {
	err := WriteMsg(errWriter{}, MsgPing, struct{}{})
	if err == nil {
		t.Fatal("expected error from failing writer")
	}
}

// errWriter is an io.Writer that always returns an error.
type errWriter struct{}

func (errWriter) Write(_ []byte) (int, error) {
	return 0, io.ErrClosedPipe
}

// ── ReadMsg ───────────────────────────────────────────────────────────────────

func TestReadMsg_badMagic(t *testing.T) {
	// Write a frame with wrong magic.
	var buf bytes.Buffer
	body := []byte(`{"type":"ping","data":{}}`)
	buf.Write([]byte{'X', 'X', 'X', 'X'})
	var lenBytes [4]byte
	binary.BigEndian.PutUint32(lenBytes[:], uint32(len(body)))
	buf.Write(lenBytes[:])
	buf.Write(body)

	_, err := ReadMsg(&buf)
	if err == nil {
		t.Fatal("expected error for bad magic")
	}
	if !strings.Contains(err.Error(), "bad magic") {
		t.Fatalf("expected 'bad magic' error, got: %v", err)
	}
}

func TestReadMsg_bodyTooLarge(t *testing.T) {
	var buf bytes.Buffer
	buf.Write(Magic[:])
	var lenBytes [4]byte
	binary.BigEndian.PutUint32(lenBytes[:], MaxBodySize+1)
	buf.Write(lenBytes[:])

	_, err := ReadMsg(&buf)
	if err == nil {
		t.Fatal("expected error for body too large")
	}
	if !strings.Contains(err.Error(), "too large") {
		t.Fatalf("expected 'too large' error, got: %v", err)
	}
}

func TestReadMsg_truncatedBody(t *testing.T) {
	var buf bytes.Buffer
	buf.Write(Magic[:])
	var lenBytes [4]byte
	binary.BigEndian.PutUint32(lenBytes[:], 100) // promise 100 bytes
	buf.Write(lenBytes[:])
	buf.Write([]byte("short")) // only write 5 bytes

	_, err := ReadMsg(&buf)
	if err == nil {
		t.Fatal("expected error for truncated body")
	}
}

func TestReadMsg_truncatedHeader(t *testing.T) {
	var buf bytes.Buffer
	buf.Write([]byte{'A', 'L'}) // only 2 bytes instead of 8

	_, err := ReadMsg(&buf)
	if err == nil {
		t.Fatal("expected error for truncated header")
	}
}

func TestReadMsg_invalidJSON(t *testing.T) {
	var buf bytes.Buffer
	body := []byte(`not valid json`)
	buf.Write(Magic[:])
	var lenBytes [4]byte
	binary.BigEndian.PutUint32(lenBytes[:], uint32(len(body)))
	buf.Write(lenBytes[:])
	buf.Write(body)

	_, err := ReadMsg(&buf)
	if err == nil {
		t.Fatal("expected JSON parse error")
	}
}

// ── Round-trip ────────────────────────────────────────────────────────────────

func TestRoundTrip_Hello(t *testing.T) {
	original := Hello{
		Version:   "2.0",
		MachineID: "deadbeefcafe1234",
		Hostname:  "victim.local",
		OS:        "linux",
		Arch:      "amd64",
		User:      "root",
		UID:       "0",
	}

	var buf bytes.Buffer
	if err := WriteMsg(&buf, MsgHello, original); err != nil {
		t.Fatalf("WriteMsg: %v", err)
	}

	env, err := ReadMsg(&buf)
	if err != nil {
		t.Fatalf("ReadMsg: %v", err)
	}
	if env.Type != MsgHello {
		t.Fatalf("type: want %q got %q", MsgHello, env.Type)
	}

	var decoded Hello
	if err := json.Unmarshal(env.Data, &decoded); err != nil {
		t.Fatalf("unmarshal Hello: %v", err)
	}
	if decoded != original {
		t.Fatalf("round-trip mismatch:\n  want %+v\n  got  %+v", original, decoded)
	}
}

func TestRoundTrip_Welcome(t *testing.T) {
	original := Welcome{SessionID: 42, Interval: 60, Jitter: 20}

	var buf bytes.Buffer
	if err := WriteMsg(&buf, MsgWelcome, original); err != nil {
		t.Fatalf("WriteMsg: %v", err)
	}
	env, err := ReadMsg(&buf)
	if err != nil {
		t.Fatalf("ReadMsg: %v", err)
	}
	var decoded Welcome
	if err := json.Unmarshal(env.Data, &decoded); err != nil {
		t.Fatalf("unmarshal Welcome: %v", err)
	}
	if decoded != original {
		t.Fatalf("round-trip mismatch: want %+v got %+v", original, decoded)
	}
}

func TestRoundTrip_Task(t *testing.T) {
	original := Task{
		ID:      "ex123abc",
		Kind:    TaskExec,
		Command: "id",
	}

	var buf bytes.Buffer
	if err := WriteMsg(&buf, MsgTask, original); err != nil {
		t.Fatalf("WriteMsg: %v", err)
	}
	env, err := ReadMsg(&buf)
	if err != nil {
		t.Fatalf("ReadMsg: %v", err)
	}
	var decoded Task
	if err := json.Unmarshal(env.Data, &decoded); err != nil {
		t.Fatalf("unmarshal Task: %v", err)
	}
	if decoded.ID != original.ID || decoded.Kind != original.Kind || decoded.Command != original.Command {
		t.Fatalf("round-trip mismatch: want %+v got %+v", original, decoded)
	}
}

func TestRoundTrip_Result(t *testing.T) {
	original := Result{
		TaskID: "ex123abc",
		Output: []byte("uid=0(root) gid=0(root)"),
		Exit:   0,
	}

	var buf bytes.Buffer
	if err := WriteMsg(&buf, MsgResult, original); err != nil {
		t.Fatalf("WriteMsg: %v", err)
	}
	env, err := ReadMsg(&buf)
	if err != nil {
		t.Fatalf("ReadMsg: %v", err)
	}
	var decoded Result
	if err := json.Unmarshal(env.Data, &decoded); err != nil {
		t.Fatalf("unmarshal Result: %v", err)
	}
	if decoded.TaskID != original.TaskID || string(decoded.Output) != string(original.Output) || decoded.Exit != original.Exit {
		t.Fatalf("round-trip mismatch: want %+v got %+v", original, decoded)
	}
}

func TestRoundTrip_MultipleMessages(t *testing.T) {
	var buf bytes.Buffer

	// Write two messages back to back.
	if err := WriteMsg(&buf, MsgPing, struct{}{}); err != nil {
		t.Fatalf("WriteMsg ping: %v", err)
	}
	if err := WriteMsg(&buf, MsgPong, struct{}{}); err != nil {
		t.Fatalf("WriteMsg pong: %v", err)
	}

	env1, err := ReadMsg(&buf)
	if err != nil {
		t.Fatalf("ReadMsg 1: %v", err)
	}
	if env1.Type != MsgPing {
		t.Fatalf("expected ping, got %q", env1.Type)
	}

	env2, err := ReadMsg(&buf)
	if err != nil {
		t.Fatalf("ReadMsg 2: %v", err)
	}
	if env2.Type != MsgPong {
		t.Fatalf("expected pong, got %q", env2.Type)
	}
}

// ── MsgType constants ─────────────────────────────────────────────────────────

func TestMsgTypeConstants(t *testing.T) {
	if MsgHello != "hello" {
		t.Errorf("MsgHello = %q, want %q", MsgHello, "hello")
	}
	if MsgWelcome != "welcome" {
		t.Errorf("MsgWelcome = %q, want %q", MsgWelcome, "welcome")
	}
	if MsgTask != "task" {
		t.Errorf("MsgTask = %q, want %q", MsgTask, "task")
	}
	if MsgResult != "result" {
		t.Errorf("MsgResult = %q, want %q", MsgResult, "result")
	}
	if MsgPing != "ping" {
		t.Errorf("MsgPing = %q, want %q", MsgPing, "ping")
	}
	if MsgPong != "pong" {
		t.Errorf("MsgPong = %q, want %q", MsgPong, "pong")
	}
}
