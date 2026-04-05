package main

import (
	"encoding/hex"
	"testing"
)

// ── xorDecode ─────────────────────────────────────────────────────────────────

func TestXorDecode_roundTrip(t *testing.T) {
	// Manually XOR "hello" with key 0xab, 0xcd and hex-encode both.
	plain := "hello"
	key := []byte{0xab, 0xcd}
	enc := make([]byte, len(plain))
	for i := range enc {
		enc[i] = plain[i] ^ key[i%len(key)]
	}
	hexEnc := hex.EncodeToString(enc)
	hexKey := hex.EncodeToString(key)

	got := xorDecode(hexEnc, hexKey)
	if got != plain {
		t.Fatalf("roundTrip: want %q got %q", plain, got)
	}
}

func TestXorDecode_emptyEncoded(t *testing.T) {
	got := xorDecode("", "aabb")
	if got != "" {
		t.Fatalf("emptyEncoded: want %q got %q", "", got)
	}
}

func TestXorDecode_emptyKey(t *testing.T) {
	got := xorDecode("aabb", "")
	if got != "" {
		t.Fatalf("emptyKey: want %q got %q", "", got)
	}
}

func TestXorDecode_invalidHex(t *testing.T) {
	got := xorDecode("xyz", "aabb")
	if got != "" {
		t.Fatalf("invalidHex: want %q got %q", "", got)
	}
}

func TestXorDecode_multibyteKey(t *testing.T) {
	// Key longer than value — wrapping is not needed but must not panic.
	plain := "hi"
	key := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	enc := make([]byte, len(plain))
	for i := range enc {
		enc[i] = plain[i] ^ key[i%len(key)]
	}
	got := xorDecode(hex.EncodeToString(enc), hex.EncodeToString(key))
	if got != plain {
		t.Fatalf("multibyteKey: want %q got %q", plain, got)
	}
}

// ── resolveVar ────────────────────────────────────────────────────────────────

func TestResolveVar_usesPlainWhenNoEnc(t *testing.T) {
	got := resolveVar("plain", "", "")
	if got != "plain" {
		t.Fatalf("want %q got %q", "plain", got)
	}
}

func TestResolveVar_usesEncWhenPresent(t *testing.T) {
	plain := "10.0.0.1"
	key := []byte{0xde, 0xad, 0xbe, 0xef}
	enc := make([]byte, len(plain))
	for i := range enc {
		enc[i] = plain[i] ^ key[i%len(key)]
	}
	hexEnc := hex.EncodeToString(enc)
	hexKey := hex.EncodeToString(key)

	got := resolveVar("", hexEnc, hexKey)
	if got != plain {
		t.Fatalf("usesEncWhenPresent: want %q got %q", plain, got)
	}
}

func TestResolveVar_plainTakesPriorityWhenNoKey(t *testing.T) {
	// enc present but key is empty — falls back to plain
	got := resolveVar("plain", "something", "")
	if got != "plain" {
		t.Fatalf("want %q got %q", "plain", got)
	}
}
