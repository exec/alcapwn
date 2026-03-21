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
	"strings"
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
