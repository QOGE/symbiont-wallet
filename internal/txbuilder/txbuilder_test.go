package txbuilder

import (
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// ── TxIDLEFromHex ─────────────────────────────────────────────────────────────

func TestTxIDLEFromHex_Roundtrip(t *testing.T) {
	// Known txid as displayed by RPC (big-endian / human-readable order).
	// In wire order, the bytes are reversed.
	const displayHex = "ba436f3ee58cbbc80b536af13a37d949de42008bec20cd8c35004f09be9e7dcb"
	le, err := TxIDLEFromHex(displayHex)
	if err != nil {
		t.Fatalf("TxIDLEFromHex: %v", err)
	}
	// First byte of wire order == last byte of display hex.
	b, _ := hex.DecodeString(displayHex)
	if le[0] != b[31] {
		t.Errorf("le[0] = 0x%02x, want 0x%02x (last byte of display)", le[0], b[31])
	}
	if le[31] != b[0] {
		t.Errorf("le[31] = 0x%02x, want 0x%02x (first byte of display)", le[31], b[0])
	}
}

func TestTxIDLEFromHex_InvalidHex(t *testing.T) {
	if _, err := TxIDLEFromHex("notvalidhex"); err == nil {
		t.Fatal("expected error for invalid hex")
	}
}

func TestTxIDLEFromHex_WrongLength(t *testing.T) {
	if _, err := TxIDLEFromHex("aabbcc"); err == nil {
		t.Fatal("expected error for non-32-byte input")
	}
}

// ── QOGEToSatoshis ────────────────────────────────────────────────────────────

func TestQOGEToSatoshis(t *testing.T) {
	cases := []struct {
		input string
		want  int64
		ok    bool
	}{
		{"1", 100_000_000, true},
		{"1.0", 100_000_000, true},
		{"1.5", 150_000_000, true},
		{"0.0001", 10_000, true},
		{"22", 2_200_000_000, true},
		{"22.00000000", 2_200_000_000, true},
		{"0.00000001", 1, true},
		{"  1 ", 100_000_000, true},         // whitespace
		{"", 0, false},                       // empty
		{"abc", 0, false},                    // non-numeric
		{"1.000000000", 0, false},            // 9 decimal places
		{"-1", 0, false},                     // negative
	}
	for _, tc := range cases {
		got, err := QOGEToSatoshis(tc.input)
		if tc.ok {
			if err != nil {
				t.Errorf("QOGEToSatoshis(%q): unexpected error: %v", tc.input, err)
			} else if got != tc.want {
				t.Errorf("QOGEToSatoshis(%q) = %d, want %d", tc.input, got, tc.want)
			}
		} else {
			if err == nil {
				t.Errorf("QOGEToSatoshis(%q): expected error, got %d", tc.input, got)
			}
		}
	}
}

// ── QOGEToSatoshis overflow ───────────────────────────────────────────────────

func TestQOGEToSatoshis_OverflowWhole(t *testing.T) {
	// math.MaxInt64 / 100_000_000 = 92_233_720_368 (floor).
	// 92_233_720_369 * 100_000_000 = 9_223_372_036_900_000_000 > math.MaxInt64.
	if _, err := QOGEToSatoshis("92233720369"); err == nil {
		t.Fatal("expected overflow error for 92233720369 QOGE, got nil")
	}
}

func TestQOGEToSatoshis_MaxSafe(t *testing.T) {
	// 92_233_720_368 * 100_000_000 = 9_223_372_036_800_000_000 ≤ math.MaxInt64.
	got, err := QOGEToSatoshis("92233720368")
	if err != nil {
		t.Fatalf("QOGEToSatoshis(92233720368): unexpected error: %v", err)
	}
	want := int64(92_233_720_368) * 100_000_000
	if got != want {
		t.Errorf("got %d, want %d", got, want)
	}
}

// ── CalcChange ────────────────────────────────────────────────────────────────

func TestCalcChange_Normal(t *testing.T) {
	// 22 QOGE in, 1 QOGE out, 0.0001 QOGE fee → 20.9999 QOGE change
	utxo := int64(2_200_000_000)
	send := int64(100_000_000)
	fee := int64(10_000)
	want := int64(2_099_990_000)

	got, err := CalcChange(utxo, send, fee)
	if err != nil {
		t.Fatalf("CalcChange: unexpected error: %v", err)
	}
	if got != want {
		t.Errorf("CalcChange = %d, want %d", got, want)
	}
}

func TestCalcChange_InsufficientFunds(t *testing.T) {
	_, err := CalcChange(100_000_000, 100_000_000, 10_000)
	if err == nil {
		t.Fatal("expected error for insufficient funds (fee not covered)")
	}
}

func TestCalcChange_ExactBalance(t *testing.T) {
	// Exactly covers send + fee (change = 0)
	got, err := CalcChange(100_010_000, 100_000_000, 10_000)
	if err != nil {
		t.Fatalf("CalcChange: %v", err)
	}
	if got != 0 {
		t.Errorf("CalcChange = %d, want 0", got)
	}
}

func TestCalcChange_ZeroSendRejected(t *testing.T) {
	_, err := CalcChange(100_000_000, 0, 10_000)
	if err == nil {
		t.Fatal("expected error for zero send amount")
	}
}

func TestCalcChange_ZeroResult(t *testing.T) {
	// CalcChange returning 0 is valid — exact spend. Caller must build a
	// single-output tx rather than a zero-value change output.
	got, err := CalcChange(100_010_000, 100_000_000, 10_000)
	if err != nil {
		t.Fatalf("CalcChange (exact spend): %v", err)
	}
	if got != 0 {
		t.Errorf("CalcChange = %d, want 0 for exact spend", got)
	}
}

func TestCalcChange_OverflowSendPlusFee(t *testing.T) {
	// sendSats + feeSats overflows int64 — must be rejected.
	// math.MaxInt64 = 9223372036854775807
	const maxInt64 = int64(^uint64(0) >> 1)
	_, err := CalcChange(maxInt64, maxInt64-1, 2)
	if err == nil {
		t.Fatal("expected overflow error when sendSats + feeSats wraps int64")
	}
}

func TestCalcChange_NegativeFeeRejected(t *testing.T) {
	_, err := CalcChange(100_000_000, 50_000_000, -1)
	if err == nil {
		t.Fatal("expected error for negative fee")
	}
}

// ── SerializeBIP144 ───────────────────────────────────────────────────────────

// makeSyntheticTx returns a well-formed SignedP2QPKTx with dummy sig/pubkey
// bytes (all zeros) and a known 2-output structure for structural tests.
func makeSyntheticTx(t *testing.T) SignedP2QPKTx {
	t.Helper()

	txidLE, err := TxIDLEFromHex("ba436f3ee58cbbc80b536af13a37d949de42008bec20cd8c35004f09be9e7dcb")
	if err != nil {
		t.Fatalf("TxIDLEFromHex: %v", err)
	}

	// Synthetic 34-byte P2QPK scriptPubKey (OP_2 PUSH32 + 32 zero bytes).
	recipientScript := append([]byte{0x52, 0x20}, make([]byte, 32)...)
	changeScript := append([]byte{0x52, 0x20}, make([]byte, 32)...)

	return SignedP2QPKTx{
		NVersion:  2,
		NLockTime: 0,
		Inputs: []TxInput{
			{TxIDLE: txidLE, Vout: 0, NSequence: 0xFFFFFFFF},
		},
		Outputs: []TxOutput{
			{Amount: 100_000_000, Script: recipientScript},
			{Amount: 2_099_990_000, Script: changeScript},
		},
		Sig:    make([]byte, SLHDSASigLen),
		PubKey: make([]byte, SLHDSAPKLen),
	}
}

func TestSerializeBIP144_TotalLength(t *testing.T) {
	tx := makeSyntheticTx(t)
	raw, err := SerializeBIP144(tx)
	if err != nil {
		t.Fatalf("SerializeBIP144: %v", err)
	}

	// Expected breakdown (1 input, 2 outputs, synthetic 0-byte sig/pubkey padded to real lengths):
	//   nVersion:        4
	//   marker+flag:     2
	//   vin count:       1
	//   input[0]:        32(txid) + 4(vout) + 1(scriptSig=empty) + 4(nSeq) = 41
	//   vout count:      1
	//   output[0]:       8(amount) + 1(script len) + 34(script) = 43
	//   output[1]:       8 + 1 + 34 = 43
	//   witness[0] count:1
	//   sig item:        3(compact_size 17088) + 17088 = 17091
	//   pubkey item:     1(compact_size 32) + 32 = 33
	//   nLockTime:       4
	// Total: 4+2+1+41+1+43+43+1+17091+33+4 = 17264
	const want = 17264
	if len(raw) != want {
		t.Errorf("serialized length = %d, want %d", len(raw), want)
	}
}

func TestSerializeBIP144_Header(t *testing.T) {
	tx := makeSyntheticTx(t)
	raw, err := SerializeBIP144(tx)
	if err != nil {
		t.Fatalf("SerializeBIP144: %v", err)
	}

	// nVersion should be 2 (int32 LE = 02 00 00 00)
	ver := binary.LittleEndian.Uint32(raw[0:4])
	if ver != 2 {
		t.Errorf("nVersion = %d, want 2", ver)
	}

	// BIP144 marker (0x00) and flag (0x01)
	if raw[4] != 0x00 {
		t.Errorf("marker = 0x%02x, want 0x00", raw[4])
	}
	if raw[5] != 0x01 {
		t.Errorf("flag = 0x%02x, want 0x01", raw[5])
	}
}

func TestSerializeBIP144_NLockTime(t *testing.T) {
	tx := makeSyntheticTx(t)
	raw, err := SerializeBIP144(tx)
	if err != nil {
		t.Fatalf("SerializeBIP144: %v", err)
	}
	// nLockTime is the last 4 bytes, should be 0.
	lt := binary.LittleEndian.Uint32(raw[len(raw)-4:])
	if lt != 0 {
		t.Errorf("nLockTime = %d, want 0", lt)
	}
}

func TestSerializeBIP144_InputVout(t *testing.T) {
	tx := makeSyntheticTx(t)
	raw, err := SerializeBIP144(tx)
	if err != nil {
		t.Fatalf("SerializeBIP144: %v", err)
	}
	// vout starts at offset 4+2+1+32 = 39 (nVer, marker+flag, vin count, txid)
	vout := binary.LittleEndian.Uint32(raw[39:43])
	if vout != 0 {
		t.Errorf("vout = %d, want 0", vout)
	}
}

func TestSerializeBIP144_WrongSigLen(t *testing.T) {
	tx := makeSyntheticTx(t)
	tx.Sig = make([]byte, 100) // wrong
	_, err := SerializeBIP144(tx)
	if err == nil {
		t.Fatal("expected error for wrong sig length")
	}
}

func TestSerializeBIP144_WrongPubKeyLen(t *testing.T) {
	tx := makeSyntheticTx(t)
	tx.PubKey = make([]byte, 10) // wrong
	_, err := SerializeBIP144(tx)
	if err == nil {
		t.Fatal("expected error for wrong pubkey length")
	}
}

func TestSerializeBIP144_WitnessCompactSize(t *testing.T) {
	// Verify compact_size(17088) = fd c0 42 (3 bytes).
	// 17088 = 0x42C0 > 0xFC so it uses the 0xfd prefix.
	tx := makeSyntheticTx(t)
	raw, err := SerializeBIP144(tx)
	if err != nil {
		t.Fatalf("SerializeBIP144: %v", err)
	}
	// Find where witness starts:
	// offset 0:  nVersion (4)
	// offset 4:  marker+flag (2)
	// offset 6:  vin count (1)
	// offset 7:  input[0]: txid(32)+vout(4)+scriptSig(1)+nSeq(4) = 41
	// offset 48: vout count (1)
	// offset 49: output[0]: amount(8)+scriptLen(1)+script(34) = 43
	// offset 92: output[1]: 43
	// offset 135: witness item count for input[0] = 0x02 (1 byte)
	// offset 136: compact_size for sig len (should be fd c0 42)
	const witnessStart = 135
	if raw[witnessStart] != 0x02 {
		t.Errorf("witness item count = 0x%02x, want 0x02", raw[witnessStart])
	}
	// compact_size(17088) = fd c0 42
	if raw[witnessStart+1] != 0xfd {
		t.Errorf("sig compact_size[0] = 0x%02x, want 0xfd", raw[witnessStart+1])
	}
	if raw[witnessStart+2] != 0xc0 {
		t.Errorf("sig compact_size[1] = 0x%02x, want 0xc0", raw[witnessStart+2])
	}
	if raw[witnessStart+3] != 0x42 {
		t.Errorf("sig compact_size[2] = 0x%02x, want 0x42", raw[witnessStart+3])
	}
}

// ── P2QPKScript ───────────────────────────────────────────────────────────────

func TestP2QPKScript_Prefix(t *testing.T) {
	// Use the real mainnet address confirmed in TestAggregateBalances_RealMainnetResponse.
	const addr = "bq1z9zuhmnlat45jk8y3p4sxaptz0k082nsy82z2aa5f3k9u9campa7qzpy9hg"
	script, err := P2QPKScript(addr)
	if err != nil {
		t.Fatalf("P2QPKScript: %v", err)
	}
	if len(script) != 34 {
		t.Fatalf("len = %d, want 34", len(script))
	}
	if script[0] != 0x52 {
		t.Errorf("script[0] = 0x%02x, want 0x52 (OP_2)", script[0])
	}
	if script[1] != 0x20 {
		t.Errorf("script[1] = 0x%02x, want 0x20 (PUSH32)", script[1])
	}
	// Known witness program for this address.
	got := hex.EncodeToString(script)
	want := "522028b97dcffd5d692b1c910d606e85627d9e754e043a84aef6898d8bc2e3bb0f7c"
	if got != want {
		t.Errorf("script = %s\nwant   %s", got, want)
	}
}
