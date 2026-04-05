package main

// listener_http_test.go — integration tests for the HTTP beacon C2 listener.
//
// Tests use net/http/httptest to call handlers directly without binding a real
// TCP port.  The Console is constructed the same way newTestPrinter does it so
// the lineEditor reference is valid.

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"alcapwn/proto"
)

// ── helpers ───────────────────────────────────────────────────────────────────

// newTestConsoleHTTP returns a Console wired up for HTTP handler tests.
// It mirrors the pattern used by newTestPrinter() in agent_session_test.go.
func newTestConsoleHTTP(t *testing.T, serverKey *ecdh.PrivateKey) *Console {
	t.Helper()
	reg := NewRegistry()
	c := &Console{
		registry:          reg,
		listeners:         newListenerRegistry(),
		httpListeners:     newHTTPListenerRegistry(),
		pendingTLSUpgrade: make(map[string]chan net.Conn),
		editor:            newLineEditor(int(os.Stdin.Fd())),
		persist:           NewPersistenceStore(),
		config:            &Config{AutoOpenListeners: true},
		firewalls:         NewFirewallStore(),
		opts:              sessionOpts{serverKey: serverKey},
	}
	c.printer = &consolePrinter{console: c}
	c.opts.printer = c.printer
	return c
}

// registerAgent performs a POST /register against the given Console and returns
// the token, agent CryptoSession, and parsed Welcome — or calls t.Fatal on any
// error.  agentPriv is the caller's ephemeral key.
func registerAgent(t *testing.T, c *Console, agentPriv *ecdh.PrivateKey, hello proto.Hello) (string, *proto.CryptoSession, proto.Welcome) {
	t.Helper()

	helloJSON, err := json.Marshal(hello)
	if err != nil {
		t.Fatalf("registerAgent: marshal Hello: %v", err)
	}
	body := append(agentPriv.PublicKey().Bytes(), helloJSON...)

	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body))
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()
	c.handleHTTPRegister(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("registerAgent: POST /register returned %d: %s", w.Code, w.Body.String())
	}

	respBody := w.Body.Bytes()
	if len(respBody) < 32 {
		t.Fatalf("registerAgent: response too short (%d bytes)", len(respBody))
	}
	serverPubBytes := respBody[:32]
	welcomeFrame := respBody[32:]

	cs, err := proto.NewClientCryptoSessionHTTP(agentPriv, serverPubBytes, "")
	if err != nil {
		t.Fatalf("registerAgent: NewClientCryptoSessionHTTP: %v", err)
	}

	env, err := proto.ReadMsgEncrypted(bytes.NewReader(welcomeFrame), cs)
	if err != nil {
		t.Fatalf("registerAgent: ReadMsgEncrypted Welcome: %v", err)
	}
	if env.Type != proto.MsgWelcome {
		t.Fatalf("registerAgent: expected welcome, got %q", env.Type)
	}

	var welcome proto.Welcome
	if err := json.Unmarshal(env.Data, &welcome); err != nil {
		t.Fatalf("registerAgent: unmarshal Welcome: %v", err)
	}
	return welcome.Token, cs, welcome
}

// ── TestHTTPRegister_success ──────────────────────────────────────────────────

func TestHTTPRegister_success(t *testing.T) {
	serverKey := newTestServerKey(t)
	c := newTestConsoleHTTP(t, serverKey)

	agentPriv, err := ecdh.X25519().GenerateKey(crand.Reader)
	if err != nil {
		t.Fatalf("generate agent key: %v", err)
	}
	hello := proto.Hello{Version: "v3", Hostname: "test-host", OS: "linux", Arch: "amd64", UID: "0"}

	token, _, welcome := registerAgent(t, c, agentPriv, hello)

	if token == "" {
		t.Fatal("token is empty")
	}
	if welcome.Token != token {
		t.Fatalf("welcome.Token %q != token %q", welcome.Token, token)
	}
	if welcome.SessionID == 0 {
		t.Fatal("welcome.SessionID is 0")
	}

	// Session must be in the registry and be an agent.
	sess := c.registry.LookupHTTPToken(token)
	if sess == nil {
		t.Fatal("session not found by token after register")
	}
	if !sess.IsAgent {
		t.Fatal("sess.IsAgent is false")
	}
	if sess.AgentMeta == nil {
		t.Fatal("sess.AgentMeta is nil")
	}
	if sess.AgentMeta.Hostname != hello.Hostname {
		t.Fatalf("hostname: want %q got %q", hello.Hostname, sess.AgentMeta.Hostname)
	}
}

// ── TestHTTPRegister_noServerKey ─────────────────────────────────────────────

func TestHTTPRegister_noServerKey(t *testing.T) {
	c := newTestConsoleHTTP(t, nil) // no server key

	agentPriv, _ := ecdh.X25519().GenerateKey(crand.Reader)
	helloJSON, _ := json.Marshal(proto.Hello{Version: "v3"})
	body := append(agentPriv.PublicKey().Bytes(), helloJSON...)

	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body))
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()
	c.handleHTTPRegister(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", w.Code)
	}
}

// ── TestHTTPRegister_badBody ──────────────────────────────────────────────────

func TestHTTPRegister_badBody(t *testing.T) {
	serverKey := newTestServerKey(t)
	c := newTestConsoleHTTP(t, serverKey)

	// Body shorter than 32 bytes — handler must return 400.
	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader([]byte("short")))
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()
	c.handleHTTPRegister(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

// ── TestHTTPRegister_badHello ─────────────────────────────────────────────────

func TestHTTPRegister_badHello(t *testing.T) {
	serverKey := newTestServerKey(t)
	c := newTestConsoleHTTP(t, serverKey)

	agentPriv, _ := ecdh.X25519().GenerateKey(crand.Reader)
	// 32-byte pubkey followed by invalid JSON.
	body := append(agentPriv.PublicKey().Bytes(), []byte("not json {{{{")...)

	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body))
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()
	c.handleHTTPRegister(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

// ── TestHTTPRegister_wrongMethod ──────────────────────────────────────────────

func TestHTTPRegister_wrongMethod(t *testing.T) {
	serverKey := newTestServerKey(t)
	c := newTestConsoleHTTP(t, serverKey)

	req := httptest.NewRequest(http.MethodGet, "/register", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()
	c.handleHTTPRegister(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

// ── TestHTTPBeacon_unknownToken ───────────────────────────────────────────────

func TestHTTPBeacon_unknownToken(t *testing.T) {
	serverKey := newTestServerKey(t)
	c := newTestConsoleHTTP(t, serverKey)

	req := httptest.NewRequest(http.MethodGet, "/beacon/nosuchtoken", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()
	c.handleHTTPBeacon(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

// ── TestHTTPBeacon_badMethod ──────────────────────────────────────────────────

func TestHTTPBeacon_badMethod(t *testing.T) {
	serverKey := newTestServerKey(t)
	c := newTestConsoleHTTP(t, serverKey)

	agentPriv, _ := ecdh.X25519().GenerateKey(crand.Reader)
	token, _, _ := registerAgent(t, c, agentPriv, proto.Hello{Version: "v3", Hostname: "x"})

	req := httptest.NewRequest(http.MethodPut, "/beacon/"+token, nil)
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()
	c.handleHTTPBeacon(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

// ── TestHTTPBeacon_pollNoTask ─────────────────────────────────────────────────

func TestHTTPBeacon_pollNoTask(t *testing.T) {
	serverKey := newTestServerKey(t)
	c := newTestConsoleHTTP(t, serverKey)

	agentPriv, _ := ecdh.X25519().GenerateKey(crand.Reader)
	token, _, _ := registerAgent(t, c, agentPriv, proto.Hello{Version: "v3", Hostname: "idle"})

	// GET /beacon/{token} with no pending task → 204 No Content.
	req := httptest.NewRequest(http.MethodGet, "/beacon/"+token, nil)
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()
	c.handleHTTPBeacon(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", w.Code)
	}
}

// ── TestHTTPBeacon_pollAndResult ──────────────────────────────────────────────
//
// Full round-trip:
//  1. Register session
//  2. Operator issues agentExec in a goroutine (blocks waiting for result)
//  3. Agent: GET /beacon/{token} → receives encrypted task (200)
//  4. Agent: POST /beacon/{token} with encrypted result
//  5. agentExec goroutine unblocks, result verified

func TestHTTPBeacon_pollAndResult(t *testing.T) {
	serverKey := newTestServerKey(t)
	c := newTestConsoleHTTP(t, serverKey)

	agentPriv, err := ecdh.X25519().GenerateKey(crand.Reader)
	if err != nil {
		t.Fatalf("generate agent key: %v", err)
	}
	token, agentCS, _ := registerAgent(t, c, agentPriv, proto.Hello{
		Version: "v3", Hostname: "target", OS: "linux", Arch: "amd64", UID: "1000",
	})

	sess := c.registry.LookupHTTPToken(token)
	if sess == nil {
		t.Fatal("session not found after register")
	}

	const command = "id"
	wantOutput := []byte("uid=1000(user) gid=1000(user) groups=1000(user)")

	// Step 2: operator issues exec in background.
	type execResult struct {
		res proto.Result
		err error
	}
	execDone := make(chan execResult, 1)
	go func() {
		res, err := agentExec(sess, command, 5*time.Second)
		execDone <- execResult{res, err}
	}()

	// Give agentExec a moment to enqueue the task so the channel is ready.
	// We poll briefly rather than using a fixed sleep.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		sess.mu.Lock()
		n := len(sess.agentTaskCh)
		sess.mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	// Step 3: agent GETs /beacon/{token} — should receive encrypted task.
	getReq := httptest.NewRequest(http.MethodGet, "/beacon/"+token, nil)
	getReq.RemoteAddr = "127.0.0.1:12345"
	getW := httptest.NewRecorder()
	c.handleHTTPBeacon(getW, getReq)

	if getW.Code != http.StatusOK {
		t.Fatalf("GET /beacon: expected 200, got %d — %s", getW.Code, getW.Body.String())
	}

	// Decrypt the task on the agent side.
	taskFrame := getW.Body.Bytes()
	taskEnv, err := proto.ReadMsgEncrypted(bytes.NewReader(taskFrame), agentCS)
	if err != nil {
		t.Fatalf("agent: ReadMsgEncrypted task: %v", err)
	}
	if taskEnv.Type != proto.MsgTask {
		t.Fatalf("agent: expected task envelope, got %q", taskEnv.Type)
	}
	var task proto.Task
	if err := json.Unmarshal(taskEnv.Data, &task); err != nil {
		t.Fatalf("agent: unmarshal Task: %v", err)
	}
	if task.Command != command {
		t.Fatalf("agent: task command: want %q got %q", command, task.Command)
	}

	// Step 4: agent POSTs encrypted result.
	result := proto.Result{TaskID: task.ID, Output: wantOutput, Exit: 0}
	var resultBuf bytes.Buffer
	if err := proto.WriteMsgEncrypted(&resultBuf, agentCS, proto.MsgResult, result); err != nil {
		t.Fatalf("agent: WriteMsgEncrypted result: %v", err)
	}

	postReq := httptest.NewRequest(http.MethodPost, "/beacon/"+token, &resultBuf)
	postReq.RemoteAddr = "127.0.0.1:12345"
	postW := httptest.NewRecorder()
	c.handleHTTPBeacon(postW, postReq)

	if postW.Code != http.StatusOK {
		t.Fatalf("POST /beacon: expected 200, got %d — %s", postW.Code, postW.Body.String())
	}

	// Step 5: verify agentExec received the correct result.
	select {
	case er := <-execDone:
		if er.err != nil {
			t.Fatalf("agentExec returned error: %v", er.err)
		}
		if string(er.res.Output) != string(wantOutput) {
			t.Fatalf("result output: want %q got %q", string(wantOutput), string(er.res.Output))
		}
		if er.res.Exit != 0 {
			t.Fatalf("result exit: want 0 got %d", er.res.Exit)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for agentExec to return")
	}
}

// ── TLS listener tests ────────────────────────────────────────────────────────

// makeSelfSignedCert generates a throw-away ECDSA P-256 self-signed cert and
// returns the *tls.Config (for the server), the SHA-256 hex fingerprint, and
// the raw DER bytes (for pin construction).
func makeSelfSignedCert(t *testing.T) (*tls.Config, string, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	serial, _ := crand.Int(crand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certDER, err := x509.CreateCertificate(crand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("x509.CreateCertificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}
	cert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	fp := fmt.Sprintf("%x", sha256.Sum256(certDER))
	return cfg, fp, certDER
}

// tlsPinClient builds an *http.Client that pins a specific SHA-256 hex fingerprint.
func tlsPinClient(fpHex string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
					if len(rawCerts) == 0 {
						return errors.New("tls: no certificate presented")
					}
					got := fmt.Sprintf("%x", sha256.Sum256(rawCerts[0]))
					if got != fpHex {
						return fmt.Errorf("tls: cert fingerprint mismatch: got %s want %s", got, fpHex)
					}
					return nil
				},
			},
		},
		Timeout: 5 * time.Second,
	}
}

// tlsListenerAddr starts a TLS HTTP listener on a random port and returns its
// real bound address.  Polls up to 200ms for the goroutine to register.
func tlsListenerAddr(t *testing.T, c *Console, tlsCfg *tls.Config) string {
	t.Helper()
	if err := c.StartHTTPListener("127.0.0.1:0", "", "", "", tlsCfg); err != nil {
		t.Fatalf("StartHTTPListener TLS: %v", err)
	}
	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) {
		c.httpListeners.mu.Lock()
		var found string
		for _, e := range c.httpListeners.listeners {
			found = e.addr
			break
		}
		c.httpListeners.mu.Unlock()
		if found != "127.0.0.1:0" && found != "" {
			return found
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("timed out waiting for TLS listener to bind")
	return ""
}

// newServerKey generates a fresh ECDH X25519 private key for test consoles.
func newServerKey(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(crand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return key
}

func TestHTTPListenerTLS_PlainHTTPRegression(t *testing.T) {
	// nil tlsCfg → plain HTTP; must still work exactly as before.
	c := newTestConsoleHTTP(t, newServerKey(t))
	if err := c.StartHTTPListener("127.0.0.1:0", "", "", "", nil); err != nil {
		t.Fatalf("StartHTTPListener plain: %v", err)
	}
	t.Cleanup(func() { _ = c.StopHTTPListener("127.0.0.1:0") })
	// Verify the entry was registered.
	c.httpListeners.mu.Lock()
	var entry *httpListenerEntry
	for _, e := range c.httpListeners.listeners {
		entry = e
	}
	c.httpListeners.mu.Unlock()
	if entry == nil {
		t.Fatal("no listener registered")
	}
	if entry.useTLS {
		t.Error("useTLS should be false for plain listener")
	}
}

func TestHTTPListenerTLS_CorrectFingerprint(t *testing.T) {
	tlsCfg, fp, _ := makeSelfSignedCert(t)
	c := newTestConsoleHTTP(t, newServerKey(t))
	addr := tlsListenerAddr(t, c, tlsCfg)
	t.Cleanup(func() { _ = c.StopHTTPListener(addr) })

	// Verify the registry entry has useTLS == true.
	c.httpListeners.mu.Lock()
	entry := c.httpListeners.listeners[addr]
	c.httpListeners.mu.Unlock()
	if entry == nil {
		t.Fatalf("no listener registered at %s", addr)
	}
	if !entry.useTLS {
		t.Errorf("useTLS should be true for TLS listener")
	}

	client := tlsPinClient(fp)
	resp, err := client.Get("https://" + addr + "/")
	if err != nil {
		t.Fatalf("GET with correct fingerprint failed: %v", err)
	}
	resp.Body.Close()
	// Any HTTP response (even 404) means the TLS handshake succeeded.
}

func TestHTTPListenerTLS_WrongFingerprint(t *testing.T) {
	tlsCfg, _, _ := makeSelfSignedCert(t)
	c := newTestConsoleHTTP(t, newServerKey(t))
	addr := tlsListenerAddr(t, c, tlsCfg)
	t.Cleanup(func() { _ = c.StopHTTPListener(addr) })

	wrongFP := strings.Repeat("aa", 32) // valid hex length but wrong value
	client := tlsPinClient(wrongFP)
	_, err := client.Get("https://" + addr + "/")
	if err == nil {
		t.Fatal("expected TLS handshake error with wrong fingerprint, got nil")
	}
}

func TestHTTPListenerTLS_PlainClientRejected(t *testing.T) {
	tlsCfg, _, _ := makeSelfSignedCert(t)
	c := newTestConsoleHTTP(t, newServerKey(t))
	addr := tlsListenerAddr(t, c, tlsCfg)
	t.Cleanup(func() { _ = c.StopHTTPListener(addr) })

	// Plain http.Client against TLS listener — the server rejects the plain
	// HTTP request.  Go's TLS stack sends back an HTTP/1.0 400 Bad Request,
	// so the transport-level error may be nil.  We accept either a non-nil
	// error OR a 4xx/5xx response status as proof of rejection.
	plainClient := &http.Client{Timeout: 2 * time.Second}
	resp, err := plainClient.Get("http://" + addr + "/")
	if err != nil {
		// Transport-level error is fine — request was rejected.
		return
	}
	resp.Body.Close()
	if resp.StatusCode < 400 {
		t.Fatalf("expected rejection (4xx/5xx or error), got status %d", resp.StatusCode)
	}
}

// ── TestHTTPRegister_concurrent ─────────────────────────────────────────────
//
// Register 5 agents in parallel. Verify all get unique tokens and session IDs.

func TestHTTPRegister_concurrent(t *testing.T) {
	serverKey := newTestServerKey(t)
	c := newTestConsoleHTTP(t, serverKey)

	const N = 5
	type regResult struct {
		token     string
		sessionID int
		err       error
	}
	results := make([]regResult, N)
	var wg sync.WaitGroup
	wg.Add(N)

	for i := 0; i < N; i++ {
		go func(idx int) {
			defer wg.Done()
			agentPriv, err := ecdh.X25519().GenerateKey(crand.Reader)
			if err != nil {
				results[idx] = regResult{err: err}
				return
			}
			hello := proto.Hello{
				Version:  "v3",
				Hostname: fmt.Sprintf("host-%d", idx),
				OS:       "linux",
				Arch:     "amd64",
				UID:      fmt.Sprintf("%d", 1000+idx),
			}
			token, _, welcome := registerAgent(t, c, agentPriv, hello)
			results[idx] = regResult{token: token, sessionID: welcome.SessionID}
		}(i)
	}
	wg.Wait()

	tokens := make(map[string]struct{}, N)
	sessionIDs := make(map[int]struct{}, N)
	for i, r := range results {
		if r.err != nil {
			t.Fatalf("agent %d registration error: %v", i, r.err)
		}
		if r.token == "" {
			t.Fatalf("agent %d got empty token", i)
		}
		if r.sessionID == 0 {
			t.Fatalf("agent %d got session ID 0", i)
		}
		if _, dup := tokens[r.token]; dup {
			t.Fatalf("agent %d has duplicate token %q", i, r.token)
		}
		tokens[r.token] = struct{}{}
		if _, dup := sessionIDs[r.sessionID]; dup {
			t.Fatalf("agent %d has duplicate session ID %d", i, r.sessionID)
		}
		sessionIDs[r.sessionID] = struct{}{}
	}
}

// ── TestHTTPBeacon_concurrentPoll ────────────────────────────────────────────
//
// Register an agent, dispatch 3 tasks, have 3 goroutines poll simultaneously.
// Verify each gets a different task (tests the map-based httpInFlight).

func TestHTTPBeacon_concurrentPoll(t *testing.T) {
	serverKey := newTestServerKey(t)
	c := newTestConsoleHTTP(t, serverKey)

	agentPriv, err := ecdh.X25519().GenerateKey(crand.Reader)
	if err != nil {
		t.Fatalf("generate agent key: %v", err)
	}
	token, _, _ := registerAgent(t, c, agentPriv, proto.Hello{
		Version: "v3", Hostname: "concurrent-poll", OS: "linux", Arch: "amd64",
	})

	sess := c.registry.LookupHTTPToken(token)
	if sess == nil {
		t.Fatal("session not found after register")
	}

	// Dispatch 3 tasks into the session task channel.
	const numTasks = 3
	for i := 0; i < numTasks; i++ {
		task := proto.Task{
			ID:      agentTaskID("cp"),
			Kind:    proto.TaskExec,
			Command: fmt.Sprintf("cmd-%d", i),
		}
		resultCh := make(chan proto.Result, 1)
		sess.agentTaskCh <- agentTaskReq{task: task, resultCh: resultCh}
	}

	// Wait briefly for all tasks to be enqueued.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		sess.mu.Lock()
		n := len(sess.agentTaskCh)
		sess.mu.Unlock()
		if n >= numTasks {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	// 3 goroutines poll simultaneously.
	type pollResult struct {
		code   int
		taskID string
	}
	pollResults := make([]pollResult, numTasks)
	var wg sync.WaitGroup
	wg.Add(numTasks)

	for i := 0; i < numTasks; i++ {
		go func(idx int) {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodGet, "/beacon/"+token, nil)
			req.RemoteAddr = "127.0.0.1:12345"
			w := httptest.NewRecorder()
			c.handleHTTPBeacon(w, req)
			pollResults[idx].code = w.Code

			if w.Code == http.StatusOK {
				// We cannot decrypt without the agent CS, but we can verify
				// the task was stored in httpInFlight by checking the map.
				// Instead, just record that we got a 200.
				pollResults[idx].taskID = fmt.Sprintf("task-%d", idx) // placeholder
			}
		}(i)
	}
	wg.Wait()

	// All 3 polls should have returned 200 (each dequeued one task).
	okCount := 0
	for _, pr := range pollResults {
		if pr.code == http.StatusOK {
			okCount++
		}
	}
	if okCount != numTasks {
		t.Fatalf("expected %d polls with status 200, got %d", numTasks, okCount)
	}

	// httpInFlight should have exactly 3 entries (one per task).
	sess.httpInflightMu.Lock()
	inflightCount := len(sess.httpInFlight)
	sess.httpInflightMu.Unlock()
	if inflightCount != numTasks {
		t.Fatalf("expected %d in-flight tasks, got %d", numTasks, inflightCount)
	}
}

// ── TestHTTPBeacon_resultUnknownTaskID ───────────────────────────────────────
//
// Register, poll a task, then submit a result with a wrong task ID.
// The production code returns 200 OK (the unknown result is silently dropped).
// This test documents that behavior. If future code changes to return 400,
// update this test accordingly.

func TestHTTPBeacon_resultUnknownTaskID(t *testing.T) {
	serverKey := newTestServerKey(t)
	c := newTestConsoleHTTP(t, serverKey)

	agentPriv, err := ecdh.X25519().GenerateKey(crand.Reader)
	if err != nil {
		t.Fatalf("generate agent key: %v", err)
	}
	token, agentCS, _ := registerAgent(t, c, agentPriv, proto.Hello{
		Version: "v3", Hostname: "unknown-task", OS: "linux", Arch: "amd64", UID: "0",
	})

	sess := c.registry.LookupHTTPToken(token)
	if sess == nil {
		t.Fatal("session not found")
	}

	// Dispatch a task and poll it so there is something in httpInFlight.
	task := proto.Task{ID: agentTaskID("ut"), Kind: proto.TaskExec, Command: "id"}
	resultCh := make(chan proto.Result, 1)
	sess.agentTaskCh <- agentTaskReq{task: task, resultCh: resultCh}

	// Wait for task to be in channel.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		sess.mu.Lock()
		n := len(sess.agentTaskCh)
		sess.mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	// Poll to dequeue the task into httpInFlight.
	getReq := httptest.NewRequest(http.MethodGet, "/beacon/"+token, nil)
	getReq.RemoteAddr = "127.0.0.1:12345"
	getW := httptest.NewRecorder()
	c.handleHTTPBeacon(getW, getReq)
	if getW.Code != http.StatusOK {
		t.Fatalf("poll: expected 200, got %d", getW.Code)
	}

	// Submit a result with a WRONG task ID.
	wrongResult := proto.Result{TaskID: "nonexistent-task-id", Output: []byte("pwned"), Exit: 0}
	var resultBuf bytes.Buffer
	if err := proto.WriteMsgEncrypted(&resultBuf, agentCS, proto.MsgResult, wrongResult); err != nil {
		t.Fatalf("WriteMsgEncrypted: %v", err)
	}

	postReq := httptest.NewRequest(http.MethodPost, "/beacon/"+token, &resultBuf)
	postReq.RemoteAddr = "127.0.0.1:12345"
	postW := httptest.NewRecorder()
	c.handleHTTPBeacon(postW, postReq)

	// Current production behavior: unknown task ID → 200 OK (result silently dropped).
	if postW.Code != http.StatusOK {
		t.Fatalf("expected 200 for unknown task ID, got %d", postW.Code)
	}

	// The original in-flight task should still be pending (not resolved).
	sess.httpInflightMu.Lock()
	_, stillInflight := sess.httpInFlight[task.ID]
	sess.httpInflightMu.Unlock()
	if !stillInflight {
		t.Fatal("original task was incorrectly removed from in-flight map")
	}
}

// ── TestHTTPRegister_oversizedBody ──────────────────────────────────────────
//
// Send a registration body larger than 32 + 4096 bytes. The io.LimitReader
// in handleHTTPRegister truncates the body, causing JSON parse failure → 400.

func TestHTTPRegister_oversizedBody(t *testing.T) {
	serverKey := newTestServerKey(t)
	c := newTestConsoleHTTP(t, serverKey)

	agentPriv, err := ecdh.X25519().GenerateKey(crand.Reader)
	if err != nil {
		t.Fatalf("generate agent key: %v", err)
	}

	// Build a body that exceeds the 32 + 4096 limit.
	// 32 bytes pubkey + 8192 bytes of valid-looking but oversized JSON.
	bigJSON := `{"version":"v3","hostname":"` + strings.Repeat("A", 8000) + `"}`
	body := append(agentPriv.PublicKey().Bytes(), []byte(bigJSON)...)

	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body))
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()
	c.handleHTTPRegister(w, req)

	// The LimitReader truncates at 32+4096=4128 bytes. The JSON is cut mid-string,
	// causing json.Unmarshal to fail → 400 "bad hello".
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for oversized body, got %d: %s", w.Code, w.Body.String())
	}
}

// ── TestHTTPDownload ────────────────────────────────────────────────────────
//
// Tests for the download handler: valid download, invalid token, path traversal,
// and unregistered file.
//
// For non-TLS listeners with port :0, the production code does not re-key the
// registry entry to the real bound address (only the TLS path does). To work
// around this without modifying production code, we allocate a free port first
// and then start the listener on that exact port.

// freePort returns a free TCP port on localhost by binding and immediately closing.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("freePort: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}

func TestHTTPDownload_validFile(t *testing.T) {
	serverKey := newTestServerKey(t)
	c := newTestConsoleHTTP(t, serverKey)

	// Create a temp directory with a test file.
	tmpDir := t.TempDir()
	testContent := []byte("this is the agent binary")
	testFile := "agent.exe"
	if err := os.WriteFile(filepath.Join(tmpDir, testFile), testContent, 0644); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	// Start listener with download dir on a known port.
	port := freePort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	if err := c.StartHTTPListener(addr, "", "", tmpDir, nil); err != nil {
		t.Fatalf("StartHTTPListener: %v", err)
	}
	t.Cleanup(func() { _ = c.StopHTTPListener(addr) })

	// Wait briefly for the goroutine to start serving.
	time.Sleep(50 * time.Millisecond)

	// Look up the download token from the registry.
	c.httpListeners.mu.Lock()
	entry := c.httpListeners.listeners[addr]
	c.httpListeners.mu.Unlock()
	if entry == nil {
		t.Fatal("listener entry not found")
	}
	downloadToken := entry.downloadToken

	// Register the file in the whitelist.
	if err := c.RegisterDownload(addr, testFile); err != nil {
		t.Fatalf("RegisterDownload: %v", err)
	}

	// Request with valid token and registered filename → 200.
	client := &http.Client{Timeout: 5 * time.Second}
	url := fmt.Sprintf("http://%s/download/%s/%s", addr, downloadToken, testFile)
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET download: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestHTTPDownload_invalidToken(t *testing.T) {
	serverKey := newTestServerKey(t)
	c := newTestConsoleHTTP(t, serverKey)

	tmpDir := t.TempDir()
	port := freePort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	if err := c.StartHTTPListener(addr, "", "", tmpDir, nil); err != nil {
		t.Fatalf("StartHTTPListener: %v", err)
	}
	t.Cleanup(func() { _ = c.StopHTTPListener(addr) })
	time.Sleep(50 * time.Millisecond)

	// Request with a wrong token. Since the mux is registered with the real
	// download path, a request to /download/WRONG/file won't even match
	// the handler and gets a 404 from the default mux.
	client := &http.Client{Timeout: 5 * time.Second}
	url := fmt.Sprintf("http://%s/download/badtoken/agent.exe", addr)
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET download: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 for invalid token, got %d", resp.StatusCode)
	}
}

func TestHTTPDownload_pathTraversal(t *testing.T) {
	serverKey := newTestServerKey(t)
	c := newTestConsoleHTTP(t, serverKey)

	tmpDir := t.TempDir()
	port := freePort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	if err := c.StartHTTPListener(addr, "", "", tmpDir, nil); err != nil {
		t.Fatalf("StartHTTPListener: %v", err)
	}
	t.Cleanup(func() { _ = c.StopHTTPListener(addr) })
	time.Sleep(50 * time.Millisecond)

	c.httpListeners.mu.Lock()
	entry := c.httpListeners.listeners[addr]
	c.httpListeners.mu.Unlock()
	downloadToken := entry.downloadToken

	// Path traversal attempt: ../etc/passwd
	// The handler calls filepath.Base() which strips the path traversal to "passwd".
	// Then allowedFiles check rejects it → 403.
	client := &http.Client{Timeout: 5 * time.Second}
	url := fmt.Sprintf("http://%s/download/%s/../etc/passwd", addr, downloadToken)
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET download traversal: %v", err)
	}
	resp.Body.Close()
	// filepath.Base("../etc/passwd") = "passwd", which is not in the whitelist → 403.
	// Note: net/http may also clean the URL path before it reaches the handler.
	// Accept 400, 403, or 404 as evidence that the traversal was blocked.
	if resp.StatusCode == http.StatusOK {
		t.Fatal("path traversal attempt returned 200 OK — security issue")
	}
}

func TestHTTPDownload_unregisteredFile(t *testing.T) {
	serverKey := newTestServerKey(t)
	c := newTestConsoleHTTP(t, serverKey)

	tmpDir := t.TempDir()
	// Create the file on disk but do NOT register it in the whitelist.
	if err := os.WriteFile(filepath.Join(tmpDir, "secret.txt"), []byte("secret"), 0644); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	port := freePort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	if err := c.StartHTTPListener(addr, "", "", tmpDir, nil); err != nil {
		t.Fatalf("StartHTTPListener: %v", err)
	}
	t.Cleanup(func() { _ = c.StopHTTPListener(addr) })
	time.Sleep(50 * time.Millisecond)

	c.httpListeners.mu.Lock()
	entry := c.httpListeners.listeners[addr]
	c.httpListeners.mu.Unlock()
	downloadToken := entry.downloadToken

	// File exists on disk but is not whitelisted → 403.
	client := &http.Client{Timeout: 5 * time.Second}
	url := fmt.Sprintf("http://%s/download/%s/secret.txt", addr, downloadToken)
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET download: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for unregistered file, got %d", resp.StatusCode)
	}
}

// ── TestStopHTTPListener ────────────────────────────────────────────────────
//
// Start a listener, stop it, verify the port is freed (can re-bind).

func TestStopHTTPListener(t *testing.T) {
	serverKey := newTestServerKey(t)
	c := newTestConsoleHTTP(t, serverKey)

	port := freePort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	if err := c.StartHTTPListener(addr, "", "", "", nil); err != nil {
		t.Fatalf("StartHTTPListener: %v", err)
	}

	// Wait for the server goroutine to start.
	time.Sleep(50 * time.Millisecond)

	// Verify the port is occupied: try to listen on it directly.
	ln, err := net.Listen("tcp", addr)
	if err == nil {
		ln.Close()
		t.Fatal("expected port to be occupied, but net.Listen succeeded")
	}

	// Stop the listener.
	if err := c.StopHTTPListener(addr); err != nil {
		t.Fatalf("StopHTTPListener: %v", err)
	}

	// Give the OS a moment to release the port.
	time.Sleep(50 * time.Millisecond)

	// Now the port should be free.
	ln, err = net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("expected port to be free after stop, but net.Listen failed: %v", err)
	}
	ln.Close()

	// Registry should no longer contain the listener.
	c.httpListeners.mu.Lock()
	_, stillRegistered := c.httpListeners.listeners[addr]
	c.httpListeners.mu.Unlock()
	if stillRegistered {
		t.Fatal("listener still in registry after StopHTTPListener")
	}
}

// ── TestStopHTTPListener_notFound ───────────────────────────────────────────

func TestStopHTTPListener_notFound(t *testing.T) {
	serverKey := newTestServerKey(t)
	c := newTestConsoleHTTP(t, serverKey)

	err := c.StopHTTPListener("127.0.0.1:99999")
	if err == nil {
		t.Fatal("expected error for non-existent listener")
	}
}
