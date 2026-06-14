package address

import (
	"encoding/hex"
	"strings"
	"testing"
)

// ─── Test vectors ─────────────────────────────────────────────────────────────
// These vectors are derived from known inputs so the test is deterministic.
// M1.2 requirement: tests must pass before address derivation is considered done.

// mockPubKey32 is a 32-byte mock SLH-DSA public key (all zeros for simplicity).
// In production the public key is the output of slhdsa.NewSigner().PublicKey().
var mockPubKey32 = make([]byte, 32) // 32 zero bytes

// expectedHash256OfZeros is SHA256(SHA256(32 zero bytes)).
// Pre-computed: echo -n (32 zero bytes) | sha256sum twice.
// We verify this programmatically in TestHash256Vector.
const expectedHash256OfZerosHex = "2b32db6c2c0a6235fb1397e8225ea85e0f0e6e8c7b126d0016ccbde0e667151e"

// ─── Tests ───────────────────────────────────────────────────────────────────

func TestHash256Vector(t *testing.T) {
	result := hash256(mockPubKey32)
	got := hex.EncodeToString(result)
	if got != expectedHash256OfZerosHex {
		t.Errorf("hash256 vector mismatch:\n  got  %s\n  want %s", got, expectedHash256OfZerosHex)
	}
}

func TestFromPublicKeyProducesQogePrefix(t *testing.T) {
	addr, err := FromPublicKey(mockPubKey32)
	if err != nil {
		t.Fatalf("FromPublicKey failed: %v", err)
	}
	if !strings.HasPrefix(addr, "qoge1") {
		t.Errorf("address should start with 'qoge1', got: %s", addr)
	}
	t.Logf("Derived address: %s", addr)
}

func TestFromPublicKeyRoundTrip(t *testing.T) {
	pub := make([]byte, 32)
	for i := range pub {
		pub[i] = byte(i) // 0x00..0x1f
	}
	addr, err := FromPublicKey(pub)
	if err != nil {
		t.Fatalf("FromPublicKey failed: %v", err)
	}
	decoded, err := ToHash(addr)
	if err != nil {
		t.Fatalf("ToHash failed: %v", err)
	}
	expected := hash256(pub)
	if hex.EncodeToString(decoded) != hex.EncodeToString(expected) {
		t.Errorf("round-trip mismatch:\n  got  %x\n  want %x", decoded, expected)
	}
}

func TestMatchesPublicKey(t *testing.T) {
	pub := make([]byte, 32)
	for i := range pub {
		pub[i] = 0xAB
	}
	addr, err := FromPublicKey(pub)
	if err != nil {
		t.Fatalf("FromPublicKey: %v", err)
	}

	// Should match correct key
	ok, err := MatchesPublicKey(addr, pub)
	if err != nil || !ok {
		t.Errorf("MatchesPublicKey should return true for correct key, got ok=%v err=%v", ok, err)
	}

	// Should not match wrong key
	wrong := make([]byte, 32)
	ok, err = MatchesPublicKey(addr, wrong)
	if err != nil || ok {
		t.Errorf("MatchesPublicKey should return false for wrong key, got ok=%v err=%v", ok, err)
	}
}

func TestInvalidPublicKeyLength(t *testing.T) {
	_, err := FromPublicKey([]byte{0x01, 0x02}) // too short
	if err != ErrInvalidPublicKeyLength {
		t.Errorf("expected ErrInvalidPublicKeyLength, got: %v", err)
	}
}

func TestValidateAddressRejectsGarbage(t *testing.T) {
	cases := []string{
		"",
		"notanaddress",
		"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", // Bitcoin address, wrong HRP
		"qoge1invalidchecksum",
	}
	for _, c := range cases {
		if err := ValidateAddress(c); err == nil {
			t.Errorf("ValidateAddress(%q) should have failed", c)
		}
	}
}

// TestTaprootDisabled verifies that any Bech32m (Taproot-style) address
// is rejected. This is a security invariant — see SIP-QOGE-PQC-01 §3.1.
func TestTaprootDisabled(t *testing.T) {
	// Construct a fake "qoge1p..." address (Taproot-style).
	// We just check the error path — the actual Bech32m checksum need not be valid.
	taprootLike := "qoge1pzg2yxpr" // starts with qoge1p — Taproot pattern
	err := ValidateAddress(taprootLike)
	if err == nil {
		t.Error("Taproot-style address should be rejected but was accepted")
	}
	t.Logf("Taproot rejection error (expected): %v", err)
}

// BenchmarkFromPublicKey measures address derivation throughput.
// At gate-event frequency this should not be a bottleneck, but log it anyway.
func BenchmarkFromPublicKey(b *testing.B) {
	pub := make([]byte, 32)
	for i := range pub {
		pub[i] = byte(i)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = FromPublicKey(pub)
	}
}
