package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"alcapwn/proto"
)

// mockC2 simulates the server-side HTTP C2 for testing the real HTTPTransport.
// It performs the actual X25519 key exchange so the agent can successfully
// establish a CryptoSession.
type mockC2 struct {
	t         *testing.T
	mu        sync.Mutex
	serverKey *ecdh.PrivateKey
	cs        *proto.CryptoSession
	token     string
	tasks     []proto.Task
	results   []proto.Result
	failReg   bool
}

func newMockC2(t *testing.T) *mockC2 {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &mockC2{
		t:         t,
		serverKey: key,
		token:     "test-token-abc123",
	}
}

func (m *mockC2) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/register" && r.Method == http.MethodPost:
		m.handleRegister(w, r)
	case r.URL.Path == "/beacon/"+m.token && r.Method == http.MethodGet:
		m.handlePoll(w, r)
	case r.URL.Path == "/beacon/"+m.token && r.Method == http.MethodPost:
		m.handleResult(w, r)
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

func (m *mockC2) handleRegister(w http.ResponseWriter, r *http.Request) {
	if m.failReg {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 32+4096))
	if err != nil || len(body) < 32 {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	agentPubBytes := body[:32]

	cs, serverPubBytes, err := proto.NewServerCryptoSessionHTTP(m.serverKey, agentPubBytes)
	if err != nil {
		http.Error(w, "handshake failed", http.StatusInternalServerError)
		return
	}

	m.mu.Lock()
	m.cs = cs
	m.mu.Unlock()

	welcome := proto.Welcome{
		SessionID: 42,
		Interval:  1,
		Jitter:    15,
		Token:     m.token,
	}

	var buf bytes.Buffer
	buf.Write(serverPubBytes)
	if err := proto.WriteMsgEncrypted(&buf, cs, proto.MsgWelcome, welcome); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	w.Write(buf.Bytes())
}

func (m *mockC2) handlePoll(w http.ResponseWriter, _ *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.tasks) == 0 || m.cs == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	task := m.tasks[0]
	m.tasks = m.tasks[1:]

	var buf bytes.Buffer
	if err := proto.WriteMsgEncrypted(&buf, m.cs, proto.MsgTask, task); err != nil {
		http.Error(w, "encryption error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	w.Write(buf.Bytes())
}

func (m *mockC2) handleResult(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	cs := m.cs
	m.mu.Unlock()

	if cs == nil {
		http.Error(w, "no session", http.StatusBadRequest)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, int64(proto.MaxBodySize)+4))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}

	env, err := proto.ReadMsgEncrypted(bytes.NewReader(body), cs)
	if err != nil {
		http.Error(w, "decryption error", http.StatusBadRequest)
		return
	}
	if env.Type != proto.MsgResult {
		http.Error(w, "expected result", http.StatusBadRequest)
		return
	}

	var res proto.Result
	if err := json.Unmarshal(env.Data, &res); err != nil {
		http.Error(w, "bad result", http.StatusBadRequest)
		return
	}

	m.mu.Lock()
	m.results = append(m.results, res)
	m.mu.Unlock()

	w.WriteHeader(http.StatusOK)
}

// --- Tests that exercise the REAL HTTPTransport methods ---

func TestHTTPTransport_Connect(t *testing.T) {
	mock := newMockC2(t)
	srv := httptest.NewServer(mock)
	defer srv.Close()

	ht := &HTTPTransport{
		baseURL:   srv.URL,
		userAgent: "test-agent",
		client:    srv.Client(),
		ivSec:     1,
		jitPct:    0,
	}

	hello := proto.Hello{
		Version:  "v3",
		Hostname: "testhost",
		OS:       "linux",
		Arch:     "amd64",
	}

	err := ht.Connect(hello)
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}

	if ht.token != mock.token {
		t.Fatalf("want token %q, got %q", mock.token, ht.token)
	}
	if ht.cs == nil {
		t.Fatal("CryptoSession should be set after Connect")
	}
}

func TestHTTPTransport_PollTask(t *testing.T) {
	mock := newMockC2(t)
	mock.tasks = []proto.Task{
		{ID: "task-1", Kind: proto.TaskExec, Command: "id"},
	}
	srv := httptest.NewServer(mock)
	defer srv.Close()

	ht := &HTTPTransport{
		baseURL:   srv.URL,
		userAgent: "test-agent",
		client:    srv.Client(),
		ivSec:     1,
		jitPct:    0,
	}
	hello := proto.Hello{Version: "v3", Hostname: "testhost"}
	if err := ht.Connect(hello); err != nil {
		t.Fatalf("Connect: %v", err)
	}

	task, err := ht.PollTask()
	if err != nil {
		t.Fatalf("PollTask: %v", err)
	}
	if task == nil {
		t.Fatal("want non-nil task")
	}
	if task.ID != "task-1" {
		t.Fatalf("want task ID 'task-1', got %q", task.ID)
	}
	if task.Kind != proto.TaskExec {
		t.Fatalf("want kind exec, got %q", task.Kind)
	}
	if task.Command != "id" {
		t.Fatalf("want command 'id', got %q", task.Command)
	}
}

func TestHTTPTransport_PollTask_NoContentThenTask(t *testing.T) {
	mock := newMockC2(t)
	// No tasks initially — first poll returns 204.
	srv := httptest.NewServer(mock)
	defer srv.Close()

	ht := &HTTPTransport{
		baseURL:   srv.URL,
		userAgent: "test-agent",
		client:    srv.Client(),
		ivSec:     0, // zero sleep for test speed
		jitPct:    0,
	}
	hello := proto.Hello{Version: "v3", Hostname: "testhost"}
	if err := ht.Connect(hello); err != nil {
		t.Fatalf("Connect: %v", err)
	}

	// Enqueue a task after Connect so the first poll hits 204 and the next
	// poll finds the task.
	go func() {
		mock.mu.Lock()
		mock.tasks = []proto.Task{
			{ID: "delayed-task", Kind: proto.TaskExec, Command: "whoami"},
		}
		mock.mu.Unlock()
	}()

	task, err := ht.PollTask()
	if err != nil {
		t.Fatalf("PollTask: %v", err)
	}
	if task.ID != "delayed-task" {
		t.Fatalf("want task ID 'delayed-task', got %q", task.ID)
	}
}

func TestHTTPTransport_SendResult(t *testing.T) {
	mock := newMockC2(t)
	mock.tasks = []proto.Task{
		{ID: "task-r1", Kind: proto.TaskExec, Command: "echo hi"},
	}
	srv := httptest.NewServer(mock)
	defer srv.Close()

	ht := &HTTPTransport{
		baseURL:   srv.URL,
		userAgent: "test-agent",
		client:    srv.Client(),
		ivSec:     1,
		jitPct:    0,
	}
	hello := proto.Hello{Version: "v3", Hostname: "testhost"}
	if err := ht.Connect(hello); err != nil {
		t.Fatalf("Connect: %v", err)
	}

	task, err := ht.PollTask()
	if err != nil {
		t.Fatalf("PollTask: %v", err)
	}

	result := proto.Result{
		TaskID: task.ID,
		Output: []byte("hi\n"),
	}
	if err := ht.SendResult(result); err != nil {
		t.Fatalf("SendResult: %v", err)
	}

	mock.mu.Lock()
	defer mock.mu.Unlock()
	if len(mock.results) != 1 {
		t.Fatalf("want 1 result on server, got %d", len(mock.results))
	}
	if mock.results[0].TaskID != "task-r1" {
		t.Fatalf("want task ID 'task-r1', got %q", mock.results[0].TaskID)
	}
	if string(mock.results[0].Output) != "hi\n" {
		t.Fatalf("want output 'hi\\n', got %q", mock.results[0].Output)
	}
}

func TestHTTPTransport_ConnectFailure_ServerError(t *testing.T) {
	mock := newMockC2(t)
	mock.failReg = true
	srv := httptest.NewServer(mock)
	defer srv.Close()

	ht := &HTTPTransport{
		baseURL:   srv.URL,
		userAgent: "test-agent",
		client:    srv.Client(),
		ivSec:     1,
		jitPct:    0,
	}
	hello := proto.Hello{Version: "v3", Hostname: "testhost"}
	err := ht.Connect(hello)
	if err == nil {
		t.Fatal("expected error from Connect when server returns 500")
	}
}

func TestHTTPTransport_ConnectFailure_BadURL(t *testing.T) {
	ht := &HTTPTransport{
		baseURL:   "http://127.0.0.1:1", // almost certainly refused
		userAgent: "test-agent",
		client:    &http.Client{},
		ivSec:     1,
		jitPct:    0,
	}
	hello := proto.Hello{Version: "v3", Hostname: "testhost"}
	err := ht.Connect(hello)
	if err == nil {
		t.Fatal("expected error from Connect when server is unreachable")
	}
}

func TestHTTPTransport_JitterZeroIgnored(t *testing.T) {
	key, _ := ecdh.X25519().GenerateKey(rand.Reader)
	srvCustom := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/register" || r.Method != http.MethodPost {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		body, _ := io.ReadAll(io.LimitReader(r.Body, 32+4096))
		if len(body) < 32 {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		cs, serverPubBytes, err := proto.NewServerCryptoSessionHTTP(key, body[:32])
		if err != nil {
			http.Error(w, "handshake failed", http.StatusInternalServerError)
			return
		}
		welcome := proto.Welcome{
			SessionID: 1,
			Interval:  60,
			Jitter:    0,
			Token:     "tok-zero-jitter",
		}
		var buf bytes.Buffer
		buf.Write(serverPubBytes)
		proto.WriteMsgEncrypted(&buf, cs, proto.MsgWelcome, welcome)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		w.Write(buf.Bytes())
	}))
	defer srvCustom.Close()

	ht := &HTTPTransport{
		baseURL:   srvCustom.URL,
		userAgent: "test-agent",
		client:    srvCustom.Client(),
		ivSec:     1,
		jitPct:    30,
	}
	hello := proto.Hello{Version: "v3", Hostname: "testhost"}
	if err := ht.Connect(hello); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if ht.jitPct != 30 {
		t.Fatalf("jitter=0 from server should not override default 30; got %d", ht.jitPct)
	}
}

func TestHTTPTransport_JitterPositiveApplied(t *testing.T) {
	mock := newMockC2(t)
	srv := httptest.NewServer(mock)
	defer srv.Close()

	ht := &HTTPTransport{
		baseURL:   srv.URL,
		userAgent: "test-agent",
		client:    srv.Client(),
		ivSec:     1,
		jitPct:    5,
	}
	hello := proto.Hello{Version: "v3", Hostname: "testhost"}
	if err := ht.Connect(hello); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	// Mock server sends Jitter=15.
	if ht.jitPct != 15 {
		t.Fatalf("positive jitter should be applied; want 15, got %d", ht.jitPct)
	}
}

func TestHTTPTransport_NewRequest_Headers(t *testing.T) {
	ht := &HTTPTransport{userAgent: "Custom-UA/1.0"}
	req, err := ht.newRequest(http.MethodGet, "http://example.com/test", nil)
	if err != nil {
		t.Fatal(err)
	}
	if req.Header.Get("User-Agent") != "Custom-UA/1.0" {
		t.Fatalf("want User-Agent 'Custom-UA/1.0', got %q", req.Header.Get("User-Agent"))
	}
	if req.Header.Get("Accept-Language") != "en-US,en;q=0.9" {
		t.Fatal("missing Accept-Language header")
	}
	if req.Header.Get("Cache-Control") != "no-cache" {
		t.Fatal("missing Cache-Control header")
	}
	if req.Header.Get("Content-Type") != "" {
		t.Fatalf("Content-Type should not be set for nil body, got %q", req.Header.Get("Content-Type"))
	}
}

func TestHTTPTransport_NewRequest_WithBody(t *testing.T) {
	ht := &HTTPTransport{userAgent: "Custom-UA/1.0"}
	body := bytes.NewReader([]byte("test-body"))
	req, err := ht.newRequest(http.MethodPost, "http://example.com/test", body)
	if err != nil {
		t.Fatal(err)
	}
	if req.Header.Get("Content-Type") != "application/octet-stream" {
		t.Fatalf("want Content-Type 'application/octet-stream', got %q", req.Header.Get("Content-Type"))
	}
}

func TestHTTPTransport_Close_Noop(t *testing.T) {
	ht := &HTTPTransport{}
	ht.Close()
	ht.Close() // double close must not panic
}

func TestHTTPTransport_IntervalOverride(t *testing.T) {
	mock := newMockC2(t)
	srv := httptest.NewServer(mock)
	defer srv.Close()

	ht := &HTTPTransport{
		baseURL:   srv.URL,
		userAgent: "test-agent",
		client:    srv.Client(),
		ivSec:     99,
		jitPct:    0,
	}
	hello := proto.Hello{Version: "v3", Hostname: "testhost"}
	if err := ht.Connect(hello); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	// Mock server sends Interval=1.
	if ht.ivSec != 1 {
		t.Fatalf("interval from server should override default; want 1, got %d", ht.ivSec)
	}
}

func TestHTTPTransport_URLConstruction(t *testing.T) {
	mock := newMockC2(t)
	srv := httptest.NewServer(mock)
	defer srv.Close()

	ht := &HTTPTransport{
		baseURL:   srv.URL,
		userAgent: "test-agent",
		client:    srv.Client(),
		ivSec:     1,
		jitPct:    0,
	}
	hello := proto.Hello{Version: "v3", Hostname: "testhost"}
	if err := ht.Connect(hello); err != nil {
		t.Fatalf("Connect: %v", err)
	}

	wantRegister := srv.URL + "/register"
	if ht.registerURL != wantRegister {
		t.Fatalf("registerURL: want %q, got %q", wantRegister, ht.registerURL)
	}
	wantBeacon := srv.URL + "/beacon/"
	if ht.beaconBase != wantBeacon {
		t.Fatalf("beaconBase: want %q, got %q", wantBeacon, ht.beaconBase)
	}
}
