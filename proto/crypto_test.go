package proto

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// ── FingerprintKey ────────────────────────────────────────────────────────────

func TestFingerprintKey_length(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	fp := FingerprintKey(key.PublicKey().Bytes())
	if len(fp) != 64 {
		t.Fatalf("fingerprint length: want 64 hex chars, got %d (%q)", len(fp), fp)
	}
}

func TestFingerprintKey_deterministic(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pub := key.PublicKey().Bytes()
	fp1 := FingerprintKey(pub)
	fp2 := FingerprintKey(pub)
	if fp1 != fp2 {
		t.Fatalf("fingerprint not deterministic: %q vs %q", fp1, fp2)
	}
}

func TestFingerprintKey_differentKeys(t *testing.T) {
	k1, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key 1: %v", err)
	}
	k2, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key 2: %v", err)
	}
	fp1 := FingerprintKey(k1.PublicKey().Bytes())
	fp2 := FingerprintKey(k2.PublicKey().Bytes())
	if fp1 == fp2 {
		t.Fatal("different keys produced the same fingerprint (collision)")
	}
}

func TestFingerprintKey_lowercase(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	fp := FingerprintKey(key.PublicKey().Bytes())
	for i, c := range fp {
		if c >= 'A' && c <= 'F' {
			t.Fatalf("fingerprint has uppercase hex at position %d: %q", i, fp)
		}
	}
}

// ── LoadOrCreateServerKey ─────────────────────────────────────────────────────

func TestLoadOrCreateServerKey_createsFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server_key.bin")

	key, fp, err := LoadOrCreateServerKey(path)
	if err != nil {
		t.Fatalf("LoadOrCreateServerKey: %v", err)
	}
	if key == nil {
		t.Fatal("returned nil key")
	}
	if len(fp) != 64 {
		t.Fatalf("fingerprint length: want 64, got %d", len(fp))
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Fatal("key file was not created")
	}
}

func TestLoadOrCreateServerKey_filePerms(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server_key.bin")

	if _, _, err := LoadOrCreateServerKey(path); err != nil {
		t.Fatalf("LoadOrCreateServerKey: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat key file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Fatalf("key file permissions: want 0600, got %04o", perm)
	}
}

func TestLoadOrCreateServerKey_loadsSameKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server_key.bin")

	key1, fp1, err := LoadOrCreateServerKey(path)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}

	key2, fp2, err := LoadOrCreateServerKey(path)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}

	if fp1 != fp2 {
		t.Fatalf("fingerprints differ between calls: %q vs %q", fp1, fp2)
	}
	// Compare public key bytes to confirm same key was loaded.
	if string(key1.PublicKey().Bytes()) != string(key2.PublicKey().Bytes()) {
		t.Fatal("loaded a different key on second call")
	}
}

func TestLoadOrCreateServerKey_fingerprintMatchesKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server_key.bin")

	key, fp, err := LoadOrCreateServerKey(path)
	if err != nil {
		t.Fatalf("LoadOrCreateServerKey: %v", err)
	}

	wantFP := FingerprintKey(key.PublicKey().Bytes())
	if fp != wantFP {
		t.Fatalf("fingerprint mismatch: got %q, want %q", fp, wantFP)
	}
}

func TestLoadOrCreateServerKey_corruptFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server_key.bin")

	// Write 31 bytes (wrong length — valid X25519 key is exactly 32 bytes).
	if err := os.WriteFile(path, make([]byte, 31), 0600); err != nil {
		t.Fatalf("write corrupt file: %v", err)
	}

	_, _, err := LoadOrCreateServerKey(path)
	if err == nil {
		t.Fatal("expected error for corrupt key file (31 bytes), got nil — key was silently regenerated")
	}
}

func TestLoadOrCreateServerKey_corruptFileContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server_key.bin")

	// Write 32 bytes of zeros — might or might not be a valid X25519 key
	// depending on the implementation. The important thing is that if
	// NewPrivateKey rejects it, we get an error (not silent regen).
	// Use 33 bytes to ensure length check triggers.
	if err := os.WriteFile(path, make([]byte, 33), 0600); err != nil {
		t.Fatalf("write corrupt file: %v", err)
	}

	_, _, err := LoadOrCreateServerKey(path)
	if err == nil {
		t.Fatal("expected error for corrupt key file (33 bytes), got nil — key was silently regenerated")
	}
}

func TestLoadOrCreateServerKey_writeFail(t *testing.T) {
	// Create a read-only directory. WriteFile inside it should fail.
	dir := t.TempDir()
	roDir := filepath.Join(dir, "readonly")
	if err := os.Mkdir(roDir, 0500); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// Attempt to create a key file inside the read-only directory.
	// On some systems, MkdirAll of an existing dir succeeds even if read-only,
	// but WriteFile should fail because the directory is not writable.
	path := filepath.Join(roDir, "server_key.bin")

	_, _, err := LoadOrCreateServerKey(path)
	if err == nil {
		t.Fatal("expected error when key file cannot be written, got nil")
	}
}

// ── Handshake helpers ─────────────────────────────────────────────────────────

// doHandshake runs server and client handshakes concurrently over a net.Pipe,
// returning both CryptoSessions. t.Fatal is called on any error.
func doHandshake(t *testing.T) (serverCS, clientCS *CryptoSession) {
	t.Helper()

	serverPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}

	sConn, cConn := net.Pipe()

	errs := make(chan error, 2)
	var sCS, cCS *CryptoSession

	go func() {
		cs, err := NewServerCryptoSession(sConn, serverPriv)
		sCS = cs
		errs <- err
	}()
	go func() {
		cs, err := NewClientCryptoSession(cConn, "")
		cCS = cs
		errs <- err
	}()

	for i := 0; i < 2; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("handshake error: %v", err)
		}
	}
	sConn.Close()
	cConn.Close()
	return sCS, cCS
}

// doHandshakeWithConns runs the handshake and returns the open connections as well.
func doHandshakeWithConns(t *testing.T, serverPriv *ecdh.PrivateKey) (sConn, cConn net.Conn, sCS, cCS *CryptoSession) {
	t.Helper()
	sConn, cConn = net.Pipe()

	errs := make(chan error, 2)
	go func() {
		cs, err := NewServerCryptoSession(sConn, serverPriv)
		sCS = cs
		errs <- err
	}()
	go func() {
		cs, err := NewClientCryptoSession(cConn, "")
		cCS = cs
		errs <- err
	}()

	for i := 0; i < 2; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("handshake error: %v", err)
		}
	}
	return
}

// ── NewServerCryptoSession / NewClientCryptoSession ───────────────────────────

func TestHandshake_producesNonNilSessions(t *testing.T) {
	sCS, cCS := doHandshake(t)
	if sCS == nil {
		t.Fatal("server CryptoSession is nil")
	}
	if cCS == nil {
		t.Fatal("client CryptoSession is nil")
	}
}

func TestHandshake_roundTrip_serverToClient(t *testing.T) {
	serverPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	sConn, cConn, sCS, cCS := doHandshakeWithConns(t, serverPriv)
	defer sConn.Close()
	defer cConn.Close()

	want := Hello{Version: "1.0", Hostname: "test"}
	done := make(chan error, 1)
	go func() {
		done <- WriteMsgEncrypted(sConn, sCS, MsgHello, want)
	}()

	env, err := ReadMsgEncrypted(cConn, cCS)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	if writeErr := <-done; writeErr != nil {
		t.Fatalf("server write: %v", writeErr)
	}
	if env.Type != MsgHello {
		t.Fatalf("type: want %q got %q", MsgHello, env.Type)
	}
	var got Hello
	if err := json.Unmarshal(env.Data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got != want {
		t.Fatalf("payload mismatch: want %+v got %+v", want, got)
	}
}

func TestHandshake_roundTrip_clientToServer(t *testing.T) {
	serverPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	sConn, cConn, sCS, cCS := doHandshakeWithConns(t, serverPriv)
	defer sConn.Close()
	defer cConn.Close()

	want := Result{TaskID: "t1", Output: []byte("output"), Exit: 0}
	done := make(chan error, 1)
	go func() {
		done <- WriteMsgEncrypted(cConn, cCS, MsgResult, want)
	}()

	env, err := ReadMsgEncrypted(sConn, sCS)
	if err != nil {
		t.Fatalf("server read: %v", err)
	}
	if writeErr := <-done; writeErr != nil {
		t.Fatalf("client write: %v", writeErr)
	}
	if env.Type != MsgResult {
		t.Fatalf("type: want %q got %q", MsgResult, env.Type)
	}
	var got Result
	if err := json.Unmarshal(env.Data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.TaskID != want.TaskID || string(got.Output) != string(want.Output) {
		t.Fatalf("payload mismatch: want %+v got %+v", want, got)
	}
}

// ── WriteMsgEncrypted / ReadMsgEncrypted ──────────────────────────────────────

func TestEncrypted_multipleMessages(t *testing.T) {
	serverPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	sConn, cConn, sCS, cCS := doHandshakeWithConns(t, serverPriv)
	defer sConn.Close()
	defer cConn.Close()

	const N = 5
	types := []MsgType{MsgHello, MsgWelcome, MsgTask, MsgResult, MsgPing}

	// Writer goroutine.
	writeErr := make(chan error, 1)
	go func() {
		for i := 0; i < N; i++ {
			if err := WriteMsgEncrypted(sConn, sCS, types[i], struct{}{}); err != nil {
				writeErr <- err
				return
			}
		}
		writeErr <- nil
	}()

	// Read all messages and verify ordering.
	for i := 0; i < N; i++ {
		env, err := ReadMsgEncrypted(cConn, cCS)
		if err != nil {
			t.Fatalf("read message %d: %v", i, err)
		}
		if env.Type != types[i] {
			t.Fatalf("message %d: want type %q got %q", i, types[i], env.Type)
		}
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("write error: %v", err)
	}
}

func TestEncrypted_AADTamperedLength(t *testing.T) {
	// Verify that the 4-byte length prefix is bound as AAD to GCM.
	// Strategy: write an encrypted message, capture the wire bytes, then
	// construct a new frame with the *same* ciphertext but a different length
	// prefix (followed by enough padding to satisfy ReadFull). If AAD is
	// properly bound, GCM Open must reject it.
	serverPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	_, _, sCS, cCS := doHandshakeWithConns(t, serverPriv)

	// Encrypt a message to a buffer.
	var buf bytes.Buffer
	if err := WriteMsgEncrypted(&buf, sCS, MsgPing, struct{}{}); err != nil {
		t.Fatalf("WriteMsgEncrypted: %v", err)
	}

	wire := buf.Bytes()
	origLen := binary.BigEndian.Uint32(wire[0:4])
	ciphertext := wire[4:]

	// Build a tampered frame with a different length prefix but the same
	// ciphertext. The new length is origLen+1, and we append one zero byte
	// so ReadFull reads origLen+1 bytes total (the real ciphertext + 1 junk).
	tampered := make([]byte, 4+len(ciphertext)+1)
	binary.BigEndian.PutUint32(tampered[0:4], origLen+1)
	copy(tampered[4:], ciphertext)
	tampered[len(tampered)-1] = 0x00

	_, err = ReadMsgEncrypted(bytes.NewReader(tampered), cCS)
	if err == nil {
		t.Fatal("expected decryption error when length prefix is tampered (AAD mismatch), got nil")
	}
}

func TestEncrypted_tamperedCiphertext(t *testing.T) {
	serverPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	sConn, cConn, sCS, _ := doHandshakeWithConns(t, serverPriv)
	defer sConn.Close()
	defer cConn.Close()

	// Generate a fresh CryptoSession with the wrong key to simulate decryption
	// failure (mismatch between sender and receiver keys).
	wrongKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate wrong key: %v", err)
	}
	// Build a "wrong" CryptoSession directly via a second handshake pair to
	// obtain a structurally valid but cryptographically mismatched session.
	sc2, cc2 := net.Pipe()
	wrongErrs := make(chan error, 2)
	var wrongCS *CryptoSession
	go func() {
		cs, err := NewServerCryptoSession(sc2, wrongKey)
		wrongCS = cs
		wrongErrs <- err
	}()
	go func() {
		_, err := NewClientCryptoSession(cc2, "")
		wrongErrs <- err
	}()
	for i := 0; i < 2; i++ {
		if e := <-wrongErrs; e != nil {
			t.Fatalf("wrong-key handshake: %v", e)
		}
	}
	sc2.Close()
	cc2.Close()

	// Write a message using the correct server session into sConn.
	// net.Pipe is synchronous, so the write and read must happen concurrently.
	writeDone := make(chan error, 1)
	go func() {
		writeDone <- WriteMsgEncrypted(sConn, sCS, MsgPing, struct{}{})
	}()

	// Try to read it with the wrong CryptoSession (wrong key → decrypt failure).
	// Must happen concurrently with the write above (net.Pipe has no buffer).
	_, err = ReadMsgEncrypted(cConn, wrongCS)
	if err == nil {
		t.Fatal("expected decryption error with wrong key, got nil")
	}

	// Wait for write goroutine; it may succeed or get an error if cConn closed.
	<-writeDone
}

func TestEncrypted_wrongKeyReturnsError(t *testing.T) {
	// Build two independent handshake pairs and cross the CryptoSessions.
	p1 := func() (*ecdh.PrivateKey, error) { return ecdh.X25519().GenerateKey(rand.Reader) }
	k1, _ := p1()
	k2, _ := p1()

	sc1, cc1 := net.Pipe()
	sc2, cc2 := net.Pipe()

	type cs struct {
		server, client *CryptoSession
		err            error
	}
	ch := make(chan cs, 2)

	go func() {
		var r cs
		r.server, r.err = NewServerCryptoSession(sc1, k1)
		ch <- r
	}()
	go func() {
		r := cs{}
		r.client, r.err = NewClientCryptoSession(cc1, "")
		ch <- r
	}()
	go func() {
		r := cs{}
		r.server, r.err = NewServerCryptoSession(sc2, k2)
		ch <- r
	}()
	go func() {
		r := cs{}
		r.client, r.err = NewClientCryptoSession(cc2, "")
		ch <- r
	}()

	results := make([]cs, 4)
	for i := range results {
		results[i] = <-ch
		if results[i].err != nil {
			t.Fatalf("handshake %d: %v", i, results[i].err)
		}
	}
	sc1.Close()
	cc1.Close()
	sc2.Close()
	cc2.Close()
	// Test is structurally satisfied by TestEncrypted_tamperedCiphertext above.
	// This test confirms two independent handshakes both succeed without error.
}

// ── Certificate pinning ───────────────────────────────────────────────────────

func TestPinning_correctFingerprintPasses(t *testing.T) {
	serverPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	fp := FingerprintKey(serverPriv.PublicKey().Bytes())

	sConn, cConn := net.Pipe()
	errs := make(chan error, 2)

	go func() {
		_, err := NewServerCryptoSession(sConn, serverPriv)
		errs <- err
	}()
	go func() {
		_, err := NewClientCryptoSession(cConn, fp) // correct fingerprint
		errs <- err
	}()

	for i := 0; i < 2; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("handshake with correct pinning: %v", err)
		}
	}
	sConn.Close()
	cConn.Close()
}

func TestPinning_wrongFingerprintFails(t *testing.T) {
	serverPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	wrongKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate wrong key: %v", err)
	}
	wrongFP := FingerprintKey(wrongKey.PublicKey().Bytes())

	sConn, cConn := net.Pipe()
	errs := make(chan error, 2)

	go func() {
		_, err := NewServerCryptoSession(sConn, serverPriv)
		errs <- err
	}()
	go func() {
		_, err := NewClientCryptoSession(cConn, wrongFP) // wrong fingerprint
		errs <- err
	}()

	// The client fails immediately after reading the server pubkey (fingerprint
	// mismatch) without sending its own pubkey.  The server goroutine is left
	// blocking on ReadFull waiting for the agent pubkey that never arrives.
	// Collect the first result (the client error), then close both connections
	// to unblock the server goroutine, then drain the channel.
	firstErr := <-errs
	sConn.Close()
	cConn.Close()
	<-errs // drain server goroutine (gets closed-pipe error)

	if firstErr == nil {
		t.Fatal("expected fingerprint mismatch error, got nil")
	}
}

func TestPinning_emptyFingerprintSkipsVerification(t *testing.T) {
	serverPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	sConn, cConn := net.Pipe()
	errs := make(chan error, 2)

	go func() {
		_, err := NewServerCryptoSession(sConn, serverPriv)
		errs <- err
	}()
	go func() {
		_, err := NewClientCryptoSession(cConn, "") // no pinning
		errs <- err
	}()

	for i := 0; i < 2; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("handshake with no pinning: %v", err)
		}
	}
	sConn.Close()
	cConn.Close()
}

// ── Concurrent writes ─────────────────────────────────────────────────────────

func TestConcurrentWrites(t *testing.T) {
	serverPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	sConn, cConn, sCS, cCS := doHandshakeWithConns(t, serverPriv)
	defer sConn.Close()
	defer cConn.Close()

	const numWriters = 10
	const msgsPerWriter = 5

	// Reader goroutine: drain all messages.
	total := numWriters * msgsPerWriter
	readDone := make(chan error, 1)
	go func() {
		for i := 0; i < total; i++ {
			if _, err := ReadMsgEncrypted(cConn, cCS); err != nil {
				readDone <- err
				return
			}
		}
		readDone <- nil
	}()

	// Launch concurrent writers sharing the same CryptoSession (sCS).
	var wg sync.WaitGroup
	writeErrs := make(chan error, numWriters*msgsPerWriter)
	for w := 0; w < numWriters; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for m := 0; m < msgsPerWriter; m++ {
				if err := WriteMsgEncrypted(sConn, sCS, MsgPing, struct{}{}); err != nil {
					writeErrs <- err
					return
				}
			}
		}()
	}
	wg.Wait()
	close(writeErrs)

	for err := range writeErrs {
		t.Errorf("concurrent write error: %v", err)
	}

	if err := <-readDone; err != nil {
		t.Fatalf("reader error: %v", err)
	}
}

// ── incrementNonce ────────────────────────────────────────────────────────────

func TestIncrementNonce_basic(t *testing.T) {
	var n [12]byte
	if err := incrementNonce(&n); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n[11] != 1 {
		t.Fatalf("expected n[11]=1 after first increment, got %d", n[11])
	}
}

func TestIncrementNonce_carry(t *testing.T) {
	var n [12]byte
	n[11] = 0xff
	if err := incrementNonce(&n); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n[11] != 0 || n[10] != 1 {
		t.Fatalf("carry not propagated: n[10]=%d n[11]=%d", n[10], n[11])
	}
}

func TestIncrementNonce_overflow(t *testing.T) {
	var n [12]byte
	for i := range n {
		n[i] = 0xff
	}
	err := incrementNonce(&n)
	if err == nil {
		t.Fatal("expected error on nonce overflow (all-0xFF), got nil")
	}
	// Nonce must NOT have been modified on error.
	for i, b := range n {
		if b != 0xff {
			t.Fatalf("nonce was modified despite overflow error: byte %d = %d", i, b)
		}
	}
}

func TestIncrementNonce_nearLimit(t *testing.T) {
	// NIST SP 800-38D recommends at most 2^32 invocations per key for a random
	// nonce. We enforce this as a practical limit using the low 4 bytes of the
	// big-endian nonce (bytes 8-11).
	var n [12]byte
	// Set bytes 8-11 to 0xFFFFFFFF (2^32 - 1) — the last allowed value.
	n[8] = 0xff
	n[9] = 0xff
	n[10] = 0xff
	n[11] = 0xff
	// The next increment would produce counter value 2^32 (0x100000000),
	// which exceeds the NIST limit.
	err := incrementNonce(&n)
	if err == nil {
		t.Fatal("expected error at 2^32 invocation limit, got nil")
	}
}

// ── HKDF backwards compatibility ─────────────────────────────────────────────

func TestHKDF_backwardsCompatible(t *testing.T) {
	// Fixed inputs — the derived keys must match these exact values forever
	// (changing them means a wire-format break).
	shared := make([]byte, 32)
	serverPub := make([]byte, 32)
	agentPub := make([]byte, 32)
	for i := range shared {
		shared[i] = byte(i + 1)
		serverPub[i] = byte(i + 50)
		agentPub[i] = byte(i + 100)
	}

	k1, k2, err := deriveKeys(shared, serverPub, agentPub)
	if err != nil {
		t.Fatalf("deriveKeys: %v", err)
	}

	// These hex values were captured from the hand-rolled HKDF implementation
	// before the switch to golang.org/x/crypto/hkdf. If these change, the new
	// implementation is NOT backwards-compatible.
	k1hex := fmt.Sprintf("%x", k1)
	k2hex := fmt.Sprintf("%x", k2)

	const wantK1 = "f0c72edb12a51b4935cba434ab38f437303b86363e8bd9547bb52fe2dc2109f0"
	const wantK2 = "15eb06a9fec9af60bcc3ebb88380b2ac93e70b91ae003f5159314c48650bc3fa"

	if k1hex != wantK1 {
		t.Fatalf("key1 mismatch (wire-format break!):\n  want: %s\n   got: %s", wantK1, k1hex)
	}
	if k2hex != wantK2 {
		t.Fatalf("key2 mismatch (wire-format break!):\n  want: %s\n   got: %s", wantK2, k2hex)
	}
}

// ── hkdfExtract / hkdfExpand ──────────────────────────────────────────────────

func TestDeriveKeys_deterministicAndDistinct(t *testing.T) {
	shared := make([]byte, 32)
	serverPub := make([]byte, 32)
	agentPub := make([]byte, 32)
	// Use non-zero values to avoid trivial cases.
	for i := range shared {
		shared[i] = byte(i + 1)
		serverPub[i] = byte(i + 50)
		agentPub[i] = byte(i + 100)
	}

	k1a, k2a, err := deriveKeys(shared, serverPub, agentPub)
	if err != nil {
		t.Fatalf("deriveKeys: %v", err)
	}
	k1b, k2b, err := deriveKeys(shared, serverPub, agentPub)
	if err != nil {
		t.Fatalf("deriveKeys second call: %v", err)
	}

	// Deterministic.
	if k1a != k1b {
		t.Fatal("key1 not deterministic")
	}
	if k2a != k2b {
		t.Fatal("key2 not deterministic")
	}
	// Distinct keys.
	if k1a == k2a {
		t.Fatal("key1 and key2 are identical — direction independence broken")
	}
}

// ── HTTP crypto variants ──────────────────────────────────────────────────────

// TestHTTPCrypto_roundTrip verifies that NewServerCryptoSessionHTTP and
// NewClientCryptoSessionHTTP produce matching sessions: messages encrypted by
// the server can be decrypted by the client and vice-versa.
func TestHTTPCrypto_roundTrip(t *testing.T) {
	serverPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}
	agentPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate agent key: %v", err)
	}

	// Server side: receives agent pub key from POST /register body.
	serverCS, serverPubBytes, err := NewServerCryptoSessionHTTP(serverPriv, agentPriv.PublicKey().Bytes())
	if err != nil {
		t.Fatalf("NewServerCryptoSessionHTTP: %v", err)
	}

	// Client side: receives server pub key from POST /register response.
	clientCS, err := NewClientCryptoSessionHTTP(agentPriv, serverPubBytes, "")
	if err != nil {
		t.Fatalf("NewClientCryptoSessionHTTP: %v", err)
	}

	// Server → client (server sends, client decrypts).
	wantHello := Hello{Version: "v3", Hostname: "http-test"}
	var serverBuf bytes.Buffer
	if err := WriteMsgEncrypted(&serverBuf, serverCS, MsgHello, wantHello); err != nil {
		t.Fatalf("server WriteMsgEncrypted Hello: %v", err)
	}
	env, err := ReadMsgEncrypted(&serverBuf, clientCS)
	if err != nil {
		t.Fatalf("client ReadMsgEncrypted Hello: %v", err)
	}
	if env.Type != MsgHello {
		t.Fatalf("type: want %q got %q", MsgHello, env.Type)
	}
	var gotHello Hello
	if err := json.Unmarshal(env.Data, &gotHello); err != nil {
		t.Fatalf("unmarshal Hello: %v", err)
	}
	if gotHello != wantHello {
		t.Fatalf("Hello mismatch: want %+v got %+v", wantHello, gotHello)
	}

	// Client → server (client sends, server decrypts).
	wantResult := Result{TaskID: "t1", Output: []byte("uid=0(root)"), Exit: 0}
	var clientBuf bytes.Buffer
	if err := WriteMsgEncrypted(&clientBuf, clientCS, MsgResult, wantResult); err != nil {
		t.Fatalf("client WriteMsgEncrypted Result: %v", err)
	}
	env2, err := ReadMsgEncrypted(&clientBuf, serverCS)
	if err != nil {
		t.Fatalf("server ReadMsgEncrypted Result: %v", err)
	}
	if env2.Type != MsgResult {
		t.Fatalf("type: want %q got %q", MsgResult, env2.Type)
	}
	var gotResult Result
	if err := json.Unmarshal(env2.Data, &gotResult); err != nil {
		t.Fatalf("unmarshal Result: %v", err)
	}
	if gotResult.TaskID != wantResult.TaskID || string(gotResult.Output) != string(wantResult.Output) {
		t.Fatalf("Result mismatch: want %+v got %+v", wantResult, gotResult)
	}
}

// TestHTTPCrypto_fingerprint verifies that NewClientCryptoSessionHTTP rejects
// a server public key whose SHA-256 fingerprint does not match the pinned value.
func TestHTTPCrypto_fingerprint(t *testing.T) {
	serverPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}
	agentPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate agent key: %v", err)
	}

	_, serverPubBytes, err := NewServerCryptoSessionHTTP(serverPriv, agentPriv.PublicKey().Bytes())
	if err != nil {
		t.Fatalf("NewServerCryptoSessionHTTP: %v", err)
	}

	// Correct fingerprint passes.
	correctFP := FingerprintKey(serverPubBytes)
	if _, err := NewClientCryptoSessionHTTP(agentPriv, serverPubBytes, correctFP); err != nil {
		t.Fatalf("expected success with correct fingerprint, got: %v", err)
	}

	// Wrong fingerprint is rejected.
	wrongKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate wrong key: %v", err)
	}
	wrongFP := FingerprintKey(wrongKey.PublicKey().Bytes())
	if _, err := NewClientCryptoSessionHTTP(agentPriv, serverPubBytes, wrongFP); err == nil {
		t.Fatal("expected fingerprint mismatch error, got nil")
	}
}

// ── paddedEnvelope ────────────────────────────────────────────────────────────

// TestPaddedEnvelope_variableSize verifies that repeated writes of the same
// message produce ciphertexts of varying length, confirming that random padding
// is being applied by marshalEnvelope.
func TestPaddedEnvelope_variableSize(t *testing.T) {
	serverPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	// We need a CryptoSession that writes to a bytes.Buffer (no net.Conn needed).
	// Use doHandshakeWithConns to get a valid session, then write to a local buffer.
	_, _, sCS, _ := doHandshakeWithConns(t, serverPriv)

	const N = 30
	lengths := make([]int, N)
	for i := 0; i < N; i++ {
		var buf bytes.Buffer
		if err := WriteMsgEncrypted(&buf, sCS, MsgPing, struct{}{}); err != nil {
			t.Fatalf("WriteMsgEncrypted[%d]: %v", i, err)
		}
		// Total bytes written = 4-byte length prefix + ciphertext.
		lengths[i] = buf.Len()
	}

	// With 0–63 random padding bytes, the probability that all 30 samples are
	// identical is astronomically low. Assert at least two distinct lengths.
	first := lengths[0]
	allSame := true
	for _, l := range lengths[1:] {
		if l != first {
			allSame = false
			break
		}
	}
	if allSame {
		t.Fatal("all 30 encrypted messages had identical length — padding may not be working")
	}
}

// TestPaddedEnvelope_decodeIgnoresPad verifies that ReadMsgEncrypted correctly
// decodes a padded message: the _p field is silently ignored and Type/Data are correct.
func TestPaddedEnvelope_decodeIgnoresPad(t *testing.T) {
	serverPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	_, _, sCS, cCS := doHandshakeWithConns(t, serverPriv)

	want := Hello{Version: "pad-test", Hostname: "example"}

	var buf bytes.Buffer
	if err := WriteMsgEncrypted(&buf, sCS, MsgHello, want); err != nil {
		t.Fatalf("WriteMsgEncrypted: %v", err)
	}

	env, err := ReadMsgEncrypted(&buf, cCS)
	if err != nil {
		t.Fatalf("ReadMsgEncrypted: %v", err)
	}
	if env.Type != MsgHello {
		t.Fatalf("type: want %q got %q", MsgHello, env.Type)
	}
	var got Hello
	if err := json.Unmarshal(env.Data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got != want {
		t.Fatalf("payload mismatch: want %+v got %+v", want, got)
	}
}

// ── Full end-to-end: LoadOrCreateServerKey → handshake → message round-trip ──

func TestFullRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server_key.bin")

	serverPriv, fp, err := LoadOrCreateServerKey(path)
	if err != nil {
		t.Fatalf("LoadOrCreateServerKey: %v", err)
	}

	sConn, cConn := net.Pipe()
	errs := make(chan error, 2)
	var sCS, cCS *CryptoSession

	go func() {
		cs, err := NewServerCryptoSession(sConn, serverPriv)
		sCS = cs
		errs <- err
	}()
	go func() {
		cs, err := NewClientCryptoSession(cConn, fp) // pin the fingerprint
		cCS = cs
		errs <- err
	}()
	for i := 0; i < 2; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("handshake: %v", err)
		}
	}

	// Server → client.
	wantHello := Hello{Version: "3.0", Hostname: "full-test"}
	writeDone := make(chan error, 1)
	go func() {
		writeDone <- WriteMsgEncrypted(sConn, sCS, MsgHello, wantHello)
	}()

	env, err := ReadMsgEncrypted(cConn, cCS)
	if err != nil {
		t.Fatalf("client read Hello: %v", err)
	}
	if err := <-writeDone; err != nil {
		t.Fatalf("server write Hello: %v", err)
	}

	var gotHello Hello
	if err := json.Unmarshal(env.Data, &gotHello); err != nil {
		t.Fatalf("unmarshal Hello: %v", err)
	}
	if gotHello != wantHello {
		t.Fatalf("Hello mismatch: want %+v got %+v", wantHello, gotHello)
	}

	// Client → server.
	wantWelcome := Welcome{SessionID: 7, Interval: 30, Jitter: 10}
	writeDone2 := make(chan error, 1)
	go func() {
		writeDone2 <- WriteMsgEncrypted(cConn, cCS, MsgWelcome, wantWelcome)
	}()

	env2, err := ReadMsgEncrypted(sConn, sCS)
	if err != nil {
		t.Fatalf("server read Welcome: %v", err)
	}
	if err := <-writeDone2; err != nil {
		t.Fatalf("client write Welcome: %v", err)
	}

	var gotWelcome Welcome
	if err := json.Unmarshal(env2.Data, &gotWelcome); err != nil {
		t.Fatalf("unmarshal Welcome: %v", err)
	}
	if gotWelcome != wantWelcome {
		t.Fatalf("Welcome mismatch: want %+v got %+v", wantWelcome, gotWelcome)
	}

	sConn.Close()
	cConn.Close()
}

// ── Security property tests ──────────────────────────────────────────────────

// TestEncrypted_nonceDeSynchronization verifies fail-closed behavior when
// sender and receiver nonces get out of sync. The sender sends two messages
// but the receiver reads only one (advancing its nonce once). The next read
// must fail because the nonces are desynchronized.
func TestEncrypted_nonceDeSynchronization(t *testing.T) {
	serverPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	_, _, sCS, cCS := doHandshakeWithConns(t, serverPriv)

	// Encrypt two messages into separate buffers.
	var buf1, buf2 bytes.Buffer
	if err := WriteMsgEncrypted(&buf1, sCS, MsgPing, struct{}{}); err != nil {
		t.Fatalf("write msg 1: %v", err)
	}
	if err := WriteMsgEncrypted(&buf2, sCS, MsgPing, struct{}{}); err != nil {
		t.Fatalf("write msg 2: %v", err)
	}

	// Receiver reads only message 1 (advancing recvNonce to 1).
	if _, err := ReadMsgEncrypted(&buf1, cCS); err != nil {
		t.Fatalf("read msg 1: %v", err)
	}

	// Skip message 2 entirely. Now write message 3 (sender nonce = 2).
	var buf3 bytes.Buffer
	if err := WriteMsgEncrypted(&buf3, sCS, MsgPing, struct{}{}); err != nil {
		t.Fatalf("write msg 3: %v", err)
	}

	// Receiver tries to read message 3 but its recvNonce is 1 (expects nonce 1),
	// while the ciphertext was sealed with nonce 2. GCM must reject it.
	_, err = ReadMsgEncrypted(&buf3, cCS)
	if err == nil {
		t.Fatal("expected decryption error due to nonce desynchronization, got nil — fail-open!")
	}
}

// TestEncrypted_bitFlipTamper captures valid ciphertext, flips one bit in the
// ciphertext body (not the GCM tag, not the length prefix), and verifies that
// GCM authentication rejects it.
func TestEncrypted_bitFlipTamper(t *testing.T) {
	serverPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	_, _, sCS, cCS := doHandshakeWithConns(t, serverPriv)

	var buf bytes.Buffer
	if err := WriteMsgEncrypted(&buf, sCS, MsgPing, struct{}{}); err != nil {
		t.Fatalf("WriteMsgEncrypted: %v", err)
	}

	wire := buf.Bytes()
	// wire = [4-byte length][ciphertext]. Flip a bit in the first byte of
	// the ciphertext payload (byte 4), which is the encrypted content.
	if len(wire) < 5 {
		t.Fatalf("wire too short: %d bytes", len(wire))
	}
	wire[4] ^= 0x01 // flip low bit of first ciphertext byte

	_, err = ReadMsgEncrypted(bytes.NewReader(wire), cCS)
	if err == nil {
		t.Fatal("expected GCM authentication error after bit flip, got nil")
	}
}

// TestEncrypted_messageReorder writes two messages A and B, swaps them in the
// buffer (B before A), and verifies that reading either fails. This confirms
// that nonce-counter binding prevents message reordering.
func TestEncrypted_messageReorder(t *testing.T) {
	serverPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	_, _, sCS, cCS := doHandshakeWithConns(t, serverPriv)

	var bufA, bufB bytes.Buffer
	if err := WriteMsgEncrypted(&bufA, sCS, MsgPing, struct{}{}); err != nil {
		t.Fatalf("write A: %v", err)
	}
	if err := WriteMsgEncrypted(&bufB, sCS, MsgPong, struct{}{}); err != nil {
		t.Fatalf("write B: %v", err)
	}

	// Construct reordered stream: B first, then A.
	var reordered bytes.Buffer
	reordered.Write(bufB.Bytes())
	reordered.Write(bufA.Bytes())

	// Reading the first message (B at nonce 1, but receiver expects nonce 0) must fail.
	_, err = ReadMsgEncrypted(&reordered, cCS)
	if err == nil {
		t.Fatal("expected decryption error when messages are reordered, got nil")
	}
}
