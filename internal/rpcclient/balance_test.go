package rpcclient

import (
	"encoding/hex"
	"testing"

	"github.com/saogen/qoge-sphincs-wallet/address"
	slhdsa "github.com/saogen/qoge-sphincs-wallet/signer"
)

// makeTestAddr generates a real bq1z address from a deterministic seed for use
// in tests. Uses NewSignerFromSeed so the key material is reproducible.
func makeTestAddr(t *testing.T, seedByte byte) string {
	t.Helper()
	seed := make([]byte, slhdsa.SeedSize)
	for i := range seed {
		seed[i] = seedByte + byte(i)
	}
	s, _, err := slhdsa.NewSignerFromSeed(seed)
	if err != nil {
		t.Fatalf("NewSignerFromSeed: %v", err)
	}
	defer s.Clean()
	addr, err := address.FromPublicKey(s.PublicKey())
	if err != nil {
		t.Fatalf("FromPublicKey: %v", err)
	}
	return addr
}

// makeScript returns the expected P2QPK scriptPubKey hex for addr.
func makeScript(t *testing.T, addr string) string {
	t.Helper()
	script, err := P2QPKScript(addr)
	if err != nil {
		t.Fatalf("P2QPKScript(%s): %v", addr, err)
	}
	return hex.EncodeToString(script)
}

// ── P2QPKScript ───────────────────────────────────────────────────────────────

func TestP2QPKScript_Length(t *testing.T) {
	addr := makeTestAddr(t, 1)
	script, err := P2QPKScript(addr)
	if err != nil {
		t.Fatalf("P2QPKScript: %v", err)
	}
	if len(script) != 34 {
		t.Fatalf("script length = %d, want 34", len(script))
	}
}

func TestP2QPKScript_Prefix(t *testing.T) {
	addr := makeTestAddr(t, 1)
	script, err := P2QPKScript(addr)
	if err != nil {
		t.Fatalf("P2QPKScript: %v", err)
	}
	if script[0] != 0x52 {
		t.Errorf("script[0] = 0x%02x, want 0x52 (OP_2)", script[0])
	}
	if script[1] != 0x20 {
		t.Errorf("script[1] = 0x%02x, want 0x20 (PUSH32)", script[1])
	}
}

func TestP2QPKScript_RoundTrip(t *testing.T) {
	// Derive a real address, decode it to the witness program, build the
	// P2QPK script, and confirm the 32 payload bytes match ToHash.
	addr := makeTestAddr(t, 7)
	hash, err := address.ToHash(addr)
	if err != nil {
		t.Fatalf("ToHash: %v", err)
	}
	script, err := P2QPKScript(addr)
	if err != nil {
		t.Fatalf("P2QPKScript: %v", err)
	}
	got := script[2:]
	if len(got) != 32 {
		t.Fatalf("payload length = %d, want 32", len(got))
	}
	for i := range hash {
		if got[i] != hash[i] {
			t.Errorf("script[%d+2] = 0x%02x, want 0x%02x", i, got[i], hash[i])
		}
	}
}

func TestP2QPKScript_InvalidAddress(t *testing.T) {
	_, err := P2QPKScript("notanaddress")
	if err == nil {
		t.Fatal("expected error for invalid address, got nil")
	}
}

// ── AggregateBalances ─────────────────────────────────────────────────────────

func TestAggregateBalances_SingleUTXO(t *testing.T) {
	addr := makeTestAddr(t, 2)
	script := makeScript(t, addr)

	result := ScanResult{
		Unspents: []ScanUnspent{
			{ScriptPubKey: script, Amount: 22.0},
		},
	}
	balances, err := AggregateBalances(result, []string{addr})
	if err != nil {
		t.Fatalf("AggregateBalances: %v", err)
	}
	want := int64(22 * SatoshisPerQOGE)
	if got := balances[addr]; got != want {
		t.Errorf("balance = %d, want %d", got, want)
	}
}

func TestAggregateBalances_MultipleUTXOsSameAddress(t *testing.T) {
	addr := makeTestAddr(t, 3)
	script := makeScript(t, addr)

	result := ScanResult{
		Unspents: []ScanUnspent{
			{ScriptPubKey: script, Amount: 10.0},
			{ScriptPubKey: script, Amount: 5.5},
			{ScriptPubKey: script, Amount: 0.00000001}, // 1 satoshi
		},
	}
	balances, err := AggregateBalances(result, []string{addr})
	if err != nil {
		t.Fatalf("AggregateBalances: %v", err)
	}
	// 10 + 5.5 + 0.00000001 QOGE = 1,550,000,001 satoshis
	scale := float64(SatoshisPerQOGE)
	want := int64(10*SatoshisPerQOGE) + int64(5.5*scale+0.5) + int64(1)
	if got := balances[addr]; got != want {
		t.Errorf("balance = %d, want %d", got, want)
	}
}

func TestAggregateBalances_ZeroUTXOs(t *testing.T) {
	addr := makeTestAddr(t, 4)

	result := ScanResult{Unspents: nil}
	balances, err := AggregateBalances(result, []string{addr})
	if err != nil {
		t.Fatalf("AggregateBalances: %v", err)
	}
	// Address with no UTXOs must still be in the map with zero balance.
	if got, ok := balances[addr]; !ok {
		t.Errorf("addr not in balances map, want zero entry")
	} else if got != 0 {
		t.Errorf("balance = %d, want 0", got)
	}
}

func TestAggregateBalances_MultipleAddresses(t *testing.T) {
	addrA := makeTestAddr(t, 5)
	addrB := makeTestAddr(t, 6)
	scriptA := makeScript(t, addrA)
	scriptB := makeScript(t, addrB)

	result := ScanResult{
		Unspents: []ScanUnspent{
			{ScriptPubKey: scriptA, Amount: 3.0},
			{ScriptPubKey: scriptB, Amount: 7.0},
			{ScriptPubKey: scriptA, Amount: 2.0}, // second UTXO for A
		},
	}
	balances, err := AggregateBalances(result, []string{addrA, addrB})
	if err != nil {
		t.Fatalf("AggregateBalances: %v", err)
	}
	if got, want := balances[addrA], int64(5*SatoshisPerQOGE); got != want {
		t.Errorf("addrA balance = %d, want %d", got, want)
	}
	if got, want := balances[addrB], int64(7*SatoshisPerQOGE); got != want {
		t.Errorf("addrB balance = %d, want %d", got, want)
	}
}

func TestAggregateBalances_UnknownScriptIgnored(t *testing.T) {
	addr := makeTestAddr(t, 8)

	result := ScanResult{
		Unspents: []ScanUnspent{
			// A UTXO whose scriptPubKey is not in our address list.
			{ScriptPubKey: "deadbeef", Amount: 100.0},
		},
	}
	balances, err := AggregateBalances(result, []string{addr})
	if err != nil {
		t.Fatalf("AggregateBalances: %v", err)
	}
	if got := balances[addr]; got != 0 {
		t.Errorf("balance = %d after unknown script, want 0", got)
	}
}

func TestAggregateBalances_EmptyAddressList(t *testing.T) {
	result := ScanResult{
		Unspents: []ScanUnspent{
			{ScriptPubKey: "aabbcc", Amount: 5.0},
		},
	}
	balances, err := AggregateBalances(result, nil)
	if err != nil {
		t.Fatalf("AggregateBalances: %v", err)
	}
	if len(balances) != 0 {
		t.Errorf("len(balances) = %d, want 0", len(balances))
	}
}

// ── FormatQOGE ────────────────────────────────────────────────────────────────

func TestFormatQOGE(t *testing.T) {
	cases := []struct {
		satoshis int64
		want     string
	}{
		{0, "0.00000000"},
		{1, "0.00000001"},
		{100_000_000, "1.00000000"},
		{2_200_000_000, "22.00000000"},
		{123_456_789, "1.23456789"},
		{100_000_000_000_000, "1000000.00000000"},
	}
	for _, tc := range cases {
		got := FormatQOGE(tc.satoshis)
		if got != tc.want {
			t.Errorf("FormatQOGE(%d) = %q, want %q", tc.satoshis, got, tc.want)
		}
	}
}
