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

// ── FloatQOGEToSatoshis ───────────────────────────────────────────────────────

// TestFloatQOGEToSatoshis_ExactValues verifies conversion of exact QOGE amounts.
func TestFloatQOGEToSatoshis_ExactValues(t *testing.T) {
	cases := []struct {
		amount float64
		want   int64
	}{
		{22.0, 2_200_000_000},
		{1.0, 100_000_000},
		{0.0, 0},
		{0.00000001, 1}, // 1 satoshi
		// 92233720368.0 QOGE = math.MaxInt64/1e8 * 1e8 = max representable whole-QOGE value
		{92_233_720_368.0, 9_223_372_036_800_000_000},
	}
	for _, tc := range cases {
		got, err := FloatQOGEToSatoshis(tc.amount)
		if err != nil {
			t.Errorf("FloatQOGEToSatoshis(%v): unexpected error: %v", tc.amount, err)
			continue
		}
		if got != tc.want {
			t.Errorf("FloatQOGEToSatoshis(%v) = %d, want %d", tc.amount, got, tc.want)
		}
	}
}

// TestFloatQOGEToSatoshis_FloatProneValues confirms that amounts where naive
// float64 multiplication drifts away from the true integer result are still
// converted exactly. These are the cases the +0.5 rounding trick was meant to
// paper over but cannot guarantee for all inputs.
func TestFloatQOGEToSatoshis_FloatProneValues(t *testing.T) {
	cases := []struct {
		amount float64
		want   int64
		desc   string
	}{
		// 0.1 QOGE: float64 representation is slightly above 0.1,
		// so 0.1 * 1e8 in float64 = 10000000.000000002 — exact via string parse.
		{0.1, 10_000_000, "0.1 QOGE"},
		// 0.29 QOGE: float64 representation slightly below, 0.29*1e8 ≈ 28999999.999...
		{0.29, 29_000_000, "0.29 QOGE"},
		// 1.005 QOGE: float64 ≈ 1.00499999999999989..., *1e8 = 100499999.999...
		{1.005, 100_500_000, "1.005 QOGE"},
		// 21.99999999 QOGE: near the 22 QOGE boundary
		{21.99999999, 2_199_999_999, "21.99999999 QOGE"},
	}
	for _, tc := range cases {
		got, err := FloatQOGEToSatoshis(tc.amount)
		if err != nil {
			t.Errorf("FloatQOGEToSatoshis(%v [%s]): unexpected error: %v", tc.amount, tc.desc, err)
			continue
		}
		if got != tc.want {
			t.Errorf("FloatQOGEToSatoshis(%v [%s]) = %d, want %d", tc.amount, tc.desc, got, tc.want)
		}
	}
}

// TestFloatQOGEToSatoshis_VsNaiveMultiply demonstrates the class of discrepancy
// that the string-based path avoids: for 1.005 QOGE, naive float64 multiplication
// with +0.5 rounding may return a different value.
func TestFloatQOGEToSatoshis_VsNaiveMultiply(t *testing.T) {
	amount := 1.005
	want := int64(100_500_000)

	// String-based path (production code) must be exact.
	got, err := FloatQOGEToSatoshis(amount)
	if err != nil {
		t.Fatalf("FloatQOGEToSatoshis: %v", err)
	}
	if got != want {
		t.Errorf("FloatQOGEToSatoshis(1.005) = %d, want %d", got, want)
	}

	// Naive path for comparison — document what it would return.
	naive := int64(amount*float64(SatoshisPerQOGE) + 0.5)
	if naive != want {
		// This is not a test failure — it documents the motivation for the fix.
		t.Logf("naive float64 path: 1.005 * 1e8 + 0.5 -> %d (expected %d, diff=%d)",
			naive, want, want-naive)
	}
}

// ── ExceedsConcentrationThreshold ────────────────────────────────────────────

func TestExceedsConcentrationThreshold_ExactThreshold(t *testing.T) {
	// Exactly 5,000,000 QOGE (BalanceWarningThresholdSats) must NOT trigger.
	if ExceedsConcentrationThreshold(BalanceWarningThresholdSats) {
		t.Errorf("ExceedsConcentrationThreshold(%d) = true, want false (exactly 5,000,000 QOGE should not trigger)",
			BalanceWarningThresholdSats)
	}
}

func TestExceedsConcentrationThreshold_OneSatoshiOver(t *testing.T) {
	// 5,000,000 QOGE + 1 satoshi = 5,000,000.00000001 QOGE — must trigger.
	if !ExceedsConcentrationThreshold(BalanceWarningThresholdSats + 1) {
		t.Errorf("ExceedsConcentrationThreshold(%d) = false, want true (5,000,000.00000001 QOGE must trigger)",
			BalanceWarningThresholdSats+1)
	}
}

func TestExceedsConcentrationThreshold_Zero(t *testing.T) {
	if ExceedsConcentrationThreshold(0) {
		t.Error("ExceedsConcentrationThreshold(0) = true, want false")
	}
}

func TestExceedsConcentrationThreshold_LargeBalance(t *testing.T) {
	// 22 QOGE — well below threshold, must not trigger.
	if ExceedsConcentrationThreshold(2_200_000_000) {
		t.Error("ExceedsConcentrationThreshold(22 QOGE) = true, want false")
	}
	// 10,000,000 QOGE — well above threshold, must trigger.
	if !ExceedsConcentrationThreshold(int64(10_000_000) * SatoshisPerQOGE) {
		t.Error("ExceedsConcentrationThreshold(10,000,000 QOGE) = false, want true")
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
