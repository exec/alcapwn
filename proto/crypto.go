// Package proto — crypto.go
//
// Session encryption for alcapwn agent↔server communication.
//
// Protocol:
//  1. acceptLoop detects agent by ALCA magic (unchanged from Phase 1).
//  2. handleAgentSession reads/discards the 4-byte routing tag, then calls
//     NewServerCryptoSession which sends the server's 32-byte X25519 public
//     key and reads the agent's ephemeral 32-byte public key.
//  3. Both sides compute ECDH(ownPriv, peerPub) → shared secret.
//  4. HKDF-SHA256 derives two independent 32-byte AES-256-GCM keys:
//       key₁  = HKDF(shared, serverPub‖agentPub, "alcapwn v3 server-to-client")
//       key₂  = HKDF(shared, serverPub‖agentPub, "alcapwn v3 client-to-server")
//  5. All subsequent messages use WriteMsgEncrypted / ReadMsgEncrypted.
//     Wire format per message:  [4-byte ciphertext length][AES-256-GCM ciphertext]
//     Nonces are 12-byte monotonic counters (separate send/recv), never reused.
//
// Phase 2 / Phase 3 compatibility:
//   - CryptoSession is transport-agnostic: it only needs io.ReadWriter.
//   - Phase 2 (HTTP/S) will call the same functions over HTTP body streams.
//   - Phase 3 (generate) embeds serverFingerprint via -ldflags like LHOST/LPORT.
package proto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// CryptoSession holds AES-256-GCM ciphers and monotonic nonce counters for one
// agent↔server connection.
//   - writeMu serialises concurrent callers of WriteMsgEncrypted (the write
//     loop and the Pong responder both write on the same connection).
//   - recv* fields are touched only by the single reader goroutine — no lock needed.
type CryptoSession struct {
	writeMu    sync.Mutex  // guards sendCipher + sendNonce across goroutines
	sendCipher cipher.AEAD
	recvCipher cipher.AEAD
	sendNonce  [12]byte // big-endian 96-bit counter, incremented after each seal
	recvNonce  [12]byte // big-endian 96-bit counter, incremented after each open
}

// NewServerCryptoSession performs the server-side X25519 handshake over rw:
//
//  1. Sends the server's 32-byte long-term public key.
//  2. Reads the agent's 32-byte ephemeral public key.
//  3. Computes the shared secret and derives two session keys.
//
// Must be called after the 4-byte ALCA routing tag has been consumed.
func NewServerCryptoSession(rw io.ReadWriter, serverPriv *ecdh.PrivateKey) (*CryptoSession, error) {
	serverPub := serverPriv.PublicKey().Bytes() // 32 bytes
	if _, err := rw.Write(serverPub); err != nil {
		return nil, fmt.Errorf("crypto: send server pubkey: %w", err)
	}

	agentPubBytes := make([]byte, 32)
	if _, err := io.ReadFull(rw, agentPubBytes); err != nil {
		return nil, fmt.Errorf("crypto: read agent pubkey: %w", err)
	}
	agentPub, err := ecdh.X25519().NewPublicKey(agentPubBytes)
	if err != nil {
		return nil, fmt.Errorf("crypto: parse agent pubkey: %w", err)
	}

	shared, err := serverPriv.ECDH(agentPub)
	if err != nil {
		return nil, fmt.Errorf("crypto: ECDH: %w", err)
	}

	// server sends on key₁, receives on key₂
	sendKey, recvKey, err := deriveKeys(shared, serverPub, agentPubBytes)
	if err != nil {
		return nil, err
	}
	return newCryptoSession(sendKey, recvKey)
}

// NewClientCryptoSession performs the agent-side X25519 handshake over rw:
//
//  1. Reads the server's 32-byte public key.
//  2. Verifies it against pinnedFingerprint (SHA-256 hex) if non-empty.
//  3. Sends the agent's ephemeral 32-byte public key.
//  4. Computes the shared secret and derives two session keys.
//
// pinnedFingerprint is the lowercase hex SHA-256 of the server's public key,
// obtained from the server's startup banner and embedded via -ldflags at
// agent build time.  Pass "" to skip verification (insecure).
func NewClientCryptoSession(rw io.ReadWriter, pinnedFingerprint string) (*CryptoSession, error) {
	serverPubBytes := make([]byte, 32)
	if _, err := io.ReadFull(rw, serverPubBytes); err != nil {
		return nil, fmt.Errorf("crypto: read server pubkey: %w", err)
	}

	if pinnedFingerprint != "" {
		got := fmt.Sprintf("%x", sha256.Sum256(serverPubBytes))
		if got != pinnedFingerprint {
			return nil, fmt.Errorf("crypto: fingerprint mismatch\n  want: %s\n   got: %s",
				pinnedFingerprint, got)
		}
	}

	agentPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("crypto: generate ephemeral key: %w", err)
	}
	agentPubBytes := agentPriv.PublicKey().Bytes()
	if _, err := rw.Write(agentPubBytes); err != nil {
		return nil, fmt.Errorf("crypto: send agent pubkey: %w", err)
	}

	serverPub, err := ecdh.X25519().NewPublicKey(serverPubBytes)
	if err != nil {
		return nil, fmt.Errorf("crypto: parse server pubkey: %w", err)
	}
	shared, err := agentPriv.ECDH(serverPub)
	if err != nil {
		return nil, fmt.Errorf("crypto: ECDH: %w", err)
	}

	// agent receives on key₁ (server-to-client), sends on key₂ (client-to-server)
	recvKey, sendKey, err := deriveKeys(shared, serverPubBytes, agentPubBytes)
	if err != nil {
		return nil, err
	}
	return newCryptoSession(sendKey, recvKey)
}

// ── HTTP transport variants ───────────────────────────────────────────────────
//
// For the HTTP beacon transport the agent sends its ephemeral public key in the
// POST /register request body (agent-first), whereas the TCP transport has the
// server send its key first.  The derived key material is identical; only the
// call sequence differs.

// NewServerCryptoSessionHTTP creates a CryptoSession for an HTTP-registered
// agent.  agentPubBytes is taken from the POST /register request body.
// Returns the CryptoSession and the server's raw public key bytes, which must
// be sent back to the agent in the registration response so it can complete the
// key exchange.
func NewServerCryptoSessionHTTP(serverPriv *ecdh.PrivateKey, agentPubBytes []byte) (*CryptoSession, []byte, error) {
	agentPub, err := ecdh.X25519().NewPublicKey(agentPubBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: parse agent pubkey: %w", err)
	}
	serverPub := serverPriv.PublicKey().Bytes()
	shared, err := serverPriv.ECDH(agentPub)
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: ECDH: %w", err)
	}
	// server sends on key₁, receives on key₂ — same direction mapping as TCP
	sendKey, recvKey, err := deriveKeys(shared, serverPub, agentPubBytes)
	if err != nil {
		return nil, nil, err
	}
	cs, err := newCryptoSession(sendKey, recvKey)
	if err != nil {
		return nil, nil, err
	}
	return cs, serverPub, nil
}

// NewClientCryptoSessionHTTP creates the agent-side CryptoSession after
// receiving the server's public key from the POST /register response body.
// agentPriv is the ephemeral key the agent generated for this session.
// pinnedFingerprint is the optional SHA-256 hex of the server's long-term key
// (embedded via -ldflags at build time); pass "" to skip verification.
func NewClientCryptoSessionHTTP(agentPriv *ecdh.PrivateKey, serverPubBytes []byte, pinnedFingerprint string) (*CryptoSession, error) {
	if pinnedFingerprint != "" {
		got := fmt.Sprintf("%x", sha256.Sum256(serverPubBytes))
		if got != pinnedFingerprint {
			return nil, fmt.Errorf("crypto: fingerprint mismatch\n  want: %s\n   got: %s",
				pinnedFingerprint, got)
		}
	}
	serverPub, err := ecdh.X25519().NewPublicKey(serverPubBytes)
	if err != nil {
		return nil, fmt.Errorf("crypto: parse server pubkey: %w", err)
	}
	shared, err := agentPriv.ECDH(serverPub)
	if err != nil {
		return nil, fmt.Errorf("crypto: ECDH: %w", err)
	}
	agentPubBytes := agentPriv.PublicKey().Bytes()
	// agent receives on key₁ (server→client), sends on key₂ (client→server)
	recvKey, sendKey, err := deriveKeys(shared, serverPubBytes, agentPubBytes)
	if err != nil {
		return nil, err
	}
	return newCryptoSession(sendKey, recvKey)
}

// WriteMsgEncrypted marshals data as a proto Envelope of type t, encrypts it
// with AES-256-GCM, and writes [4-byte ciphertext length][ciphertext] to w.
// Safe for concurrent callers (serialised via cs.writeMu).
func WriteMsgEncrypted(w io.Writer, cs *CryptoSession, t MsgType, data any) error {
	plaintext, err := marshalEnvelope(t, data)
	if err != nil {
		return err
	}
	cs.writeMu.Lock()
	defer cs.writeMu.Unlock()
	ciphertext := cs.sendCipher.Seal(nil, cs.sendNonce[:], plaintext, nil)
	incrementNonce(&cs.sendNonce)

	frame := make([]byte, 4+len(ciphertext))
	binary.BigEndian.PutUint32(frame[0:4], uint32(len(ciphertext)))
	copy(frame[4:], ciphertext)
	_, err = w.Write(frame)
	return err
}

// ReadMsgEncrypted reads one encrypted frame from r, decrypts it with
// AES-256-GCM, and returns the decoded Envelope.
func ReadMsgEncrypted(r io.Reader, cs *CryptoSession) (*Envelope, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	ciphertextLen := binary.BigEndian.Uint32(lenBuf[:])
	// Minimum valid ciphertext = GCM tag only (16 bytes); maximum = body + tag.
	const gcmOverhead = 16
	if ciphertextLen < gcmOverhead || ciphertextLen > uint32(MaxBodySize)+gcmOverhead {
		return nil, fmt.Errorf("crypto: encrypted frame length %d out of range", ciphertextLen)
	}

	ciphertext := make([]byte, ciphertextLen)
	if _, err := io.ReadFull(r, ciphertext); err != nil {
		return nil, err
	}

	plaintext, err := cs.recvCipher.Open(nil, cs.recvNonce[:], ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("crypto: decrypt failed: %w", err)
	}
	incrementNonce(&cs.recvNonce)

	var env Envelope
	if err := json.Unmarshal(plaintext, &env); err != nil {
		return nil, err
	}
	return &env, nil
}

// FingerprintKey returns the lowercase hex SHA-256 of a 32-byte X25519 public key.
// This is the value the operator embeds into the agent via -ldflags.
func FingerprintKey(pubBytes []byte) string {
	sum := sha256.Sum256(pubBytes)
	return fmt.Sprintf("%x", sum[:])
}

// LoadOrCreateServerKey loads the server's long-term X25519 private key from
// path, or generates and persists a new one if the file does not exist.
// Returns the private key and its public-key fingerprint (lowercase hex SHA-256).
func LoadOrCreateServerKey(path string) (*ecdh.PrivateKey, string, error) {
	if data, err := os.ReadFile(path); err == nil && len(data) == 32 {
		if priv, err := ecdh.X25519().NewPrivateKey(data); err == nil {
			fp := FingerprintKey(priv.PublicKey().Bytes())
			return priv, fp, nil
		}
	}

	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", fmt.Errorf("crypto: generate server key: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0700); err == nil {
		_ = os.WriteFile(path, priv.Bytes(), 0600)
	}

	fp := FingerprintKey(priv.PublicKey().Bytes())
	return priv, fp, nil
}

// ── internal helpers ─────────────────────────────────────────────────────────

// deriveKeys derives two independent AES-256-GCM keys from the ECDH shared
// secret using HKDF-SHA256.  Returns (serverToClient, clientToServer).
func deriveKeys(shared, serverPub, agentPub []byte) (key1, key2 [32]byte, err error) {
	salt := make([]byte, len(serverPub)+len(agentPub))
	copy(salt, serverPub)
	copy(salt[len(serverPub):], agentPub)

	prk := hkdfExtract(salt, shared)
	copy(key1[:], hkdfExpand(prk, []byte("alcapwn v3 server-to-client")))
	copy(key2[:], hkdfExpand(prk, []byte("alcapwn v3 client-to-server")))
	return
}

// hkdfExtract implements HKDF-Extract(salt, ikm) → PRK (RFC 5869 §2.2).
func hkdfExtract(salt, ikm []byte) []byte {
	mac := hmac.New(sha256.New, salt)
	mac.Write(ikm)
	return mac.Sum(nil)
}

// hkdfExpand implements one 32-byte block of HKDF-Expand(prk, info, 32) (RFC 5869 §2.3).
func hkdfExpand(prk, info []byte) []byte {
	mac := hmac.New(sha256.New, prk)
	mac.Write(info)
	mac.Write([]byte{0x01})
	return mac.Sum(nil)
}

func newCryptoSession(sendKey, recvKey [32]byte) (*CryptoSession, error) {
	sb, err := aes.NewCipher(sendKey[:])
	if err != nil {
		return nil, fmt.Errorf("crypto: AES send: %w", err)
	}
	send, err := cipher.NewGCM(sb)
	if err != nil {
		return nil, fmt.Errorf("crypto: GCM send: %w", err)
	}
	rb, err := aes.NewCipher(recvKey[:])
	if err != nil {
		return nil, fmt.Errorf("crypto: AES recv: %w", err)
	}
	recv, err := cipher.NewGCM(rb)
	if err != nil {
		return nil, fmt.Errorf("crypto: GCM recv: %w", err)
	}
	return &CryptoSession{sendCipher: send, recvCipher: recv}, nil
}

func incrementNonce(n *[12]byte) {
	for i := 11; i >= 0; i-- {
		n[i]++
		if n[i] != 0 {
			break
		}
	}
}

// marshalEnvelope serialises data into a typed Envelope and returns the JSON bytes.
// Shared by WriteMsg and WriteMsgEncrypted.
// paddedEnvelope is the on-wire JSON struct for encrypted messages.
// The _p field carries random padding so each ciphertext is a different length,
// making traffic-analysis fingerprinting by size significantly harder.
// Receivers unmarshal into the plain Envelope struct, which ignores _p.
type paddedEnvelope struct {
	Type MsgType         `json:"type"`
	Data json.RawMessage `json:"data"`
	Pad  string          `json:"_p,omitempty"` // random hex, stripped on decode
}

func marshalEnvelope(t MsgType, data any) ([]byte, error) {
	payload, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	// Random 0–63 padding bytes expressed as hex.  The exact length is chosen
	// uniformly at random so ciphertext sizes are not message-type predictable.
	var padBuf [63]byte
	var padLen [1]byte
	if _, err := rand.Read(padLen[:]); err == nil {
		n := int(padLen[0]) & 0x3f // 0–63
		rand.Read(padBuf[:n])      //nolint:errcheck
		env := paddedEnvelope{
			Type: t,
			Data: json.RawMessage(payload),
			Pad:  fmt.Sprintf("%x", padBuf[:n]),
		}
		return json.Marshal(env)
	}
	// Fallback (rand unavailable): marshal without padding.
	return json.Marshal(paddedEnvelope{Type: t, Data: json.RawMessage(payload)})
}
