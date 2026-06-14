// Package address - bech32.go implements BIP173 (Bech32) and BIP350 (Bech32m)
// encoding and decoding.
//
// This is vendored rather than imported because the project's existing
// dependency (github.com/btcsuite/btcutil v1.0.2, bech32 package) implements
// BIP173 only — it has no Bech32m support (no EncodeM/DecodeGeneric/encoding
// type). Confirmed by inspecting that package's exported function list:
// only Encode, Decode, and ConvertBits are exported.
//
// BIP350 differs from BIP173 in exactly one place: the constant XORed into
// the checksum polynomial. BIP173 uses 1; BIP350 uses 0x2bc830a3. BIP350
// additionally specifies a validation rule binding the constant to the
// witness version: witness version 0 MUST use the BIP173 constant (plain
// Bech32) and witness versions 1-16 MUST use the BIP350 constant (Bech32m).
// An address using the "wrong" constant for its witness version is invalid —
// this prevents a class of cross-version checksum-confusion issues. This
// file implements both constants; address.go (decode) enforces the binding
// rule.
//
// ConvertBits (5-bit <-> 8-bit regrouping) is unaffected by the BIP350
// change and continues to be used from btcutil/bech32, which exports it.
//
// References:
//   https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
//   https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki
package address

import (
	"errors"
	"strings"
)

// charset is the bech32 character set (BIP173 Section "Specification").
// Identical for Bech32 and Bech32m — only the checksum constant differs.
const charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

// Checksum constants. See BIP173 and BIP350.
const (
	bech32Const  = 1          // BIP173 (Bech32) — required for witness version 0
	bech32mConst = 0x2bc830a3 // BIP350 (Bech32m) — required for witness versions 1-16
)

// Errors specific to the bech32/bech32m codec layer.
var (
	ErrBechInvalidChecksum  = errors.New("address: invalid bech32/bech32m checksum")
	ErrBechInvalidCharacter = errors.New("address: invalid character in bech32 string")
	ErrBechMixedCase        = errors.New("address: bech32 string has mixed case")
	ErrBechInvalidLength    = errors.New("address: bech32 string has invalid length")
	ErrBechNoSeparator      = errors.New("address: bech32 string missing '1' separator")
)

// charsetRev maps a byte to its index in charset, or -1 if not present.
// Built once at package init.
var charsetRev = func() [256]int8 {
	var t [256]int8
	for i := range t {
		t[i] = -1
	}
	for i, c := range charset {
		t[byte(c)] = int8(i)
	}
	return t
}()

// polymod is the BIP173/BIP350 checksum polynomial (the "generator" step).
// Identical for both BIP173 and BIP350 — the constant XORed into the final
// result (not into the polymod itself) is what differs; see
// createChecksum/verifyChecksum.
func polymod(values []int) int {
	gen := [5]int{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	chk := 1
	for _, v := range values {
		b := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ v
		for i := 0; i < 5; i++ {
			if (b>>uint(i))&1 == 1 {
				chk ^= gen[i]
			}
		}
	}
	return chk
}

// hrpExpand expands the human-readable part into the integer sequence used
// as the start of the checksum input, per BIP173.
func hrpExpand(hrp string) []int {
	ret := make([]int, 0, len(hrp)*2+1)
	for _, c := range hrp {
		ret = append(ret, int(c>>5))
	}
	ret = append(ret, 0)
	for _, c := range hrp {
		ret = append(ret, int(c&31))
	}
	return ret
}

// verifyChecksum checks data (5-bit values, INCLUDING the trailing 6
// checksum values) against hrp. Returns bech32Const or bech32mConst if the
// checksum matches that constant, or 0 if it matches neither (invalid).
func verifyChecksum(hrp string, data []byte) int {
	values := make([]int, 0, len(hrp)*2+1+len(data))
	values = append(values, hrpExpand(hrp)...)
	for _, b := range data {
		values = append(values, int(b))
	}
	pm := polymod(values)
	switch pm {
	case bech32Const:
		return bech32Const
	case bech32mConst:
		return bech32mConst
	default:
		return 0
	}
}

// createChecksum computes the 6 trailing 5-bit checksum values for hrp+data
// (data NOT including a checksum) using the given constant.
func createChecksum(hrp string, data []byte, constant int) []byte {
	values := make([]int, 0, len(hrp)*2+1+len(data)+6)
	values = append(values, hrpExpand(hrp)...)
	for _, b := range data {
		values = append(values, int(b))
	}
	values = append(values, 0, 0, 0, 0, 0, 0)
	pm := polymod(values) ^ constant
	ret := make([]byte, 6)
	for i := 0; i < 6; i++ {
		ret[i] = byte((pm >> uint(5*(5-i))) & 31)
	}
	return ret
}

// encodeGeneric encodes hrp + data (data as 5-bit values 0-31, NOT including
// a checksum) using the given checksum constant (bech32Const or
// bech32mConst), producing a lowercase bech32/bech32m string.
func encodeGeneric(hrp string, data []byte, constant int) (string, error) {
	if len(hrp) < 1 {
		return "", errors.New("address: empty hrp")
	}
	for i := 0; i < len(hrp); i++ {
		c := hrp[i]
		if c < 33 || c > 126 {
			return "", ErrBechInvalidCharacter
		}
	}
	lower := strings.ToLower(hrp)
	if lower != hrp && strings.ToUpper(hrp) != hrp {
		return "", ErrBechMixedCase
	}
	hrp = lower

	checksum := createChecksum(hrp, data, constant)
	combined := make([]byte, 0, len(data)+len(checksum))
	combined = append(combined, data...)
	combined = append(combined, checksum...)

	var sb strings.Builder
	sb.Grow(len(hrp) + 1 + len(combined))
	sb.WriteString(hrp)
	sb.WriteByte('1')
	for _, b := range combined {
		if int(b) >= len(charset) {
			return "", errors.New("address: 5-bit value out of range")
		}
		sb.WriteByte(charset[b])
	}
	return sb.String(), nil
}

// decodeGeneric decodes a bech32/bech32m string. Returns the (lowercased)
// human-readable part, the data payload as 5-bit values with the 6-value
// checksum stripped, and which constant (bech32Const or bech32mConst) the
// checksum matched. Returns an error if the string is malformed or the
// checksum matches neither constant.
//
// This function does NOT enforce BIP350's witness-version/constant binding
// rule — that is address-format-specific and is enforced by decode() in
// address.go, which knows the witness version (the first data byte).
func decodeGeneric(s string) (hrp string, data []byte, constant int, err error) {
	if len(s) < 8 || len(s) > 90 {
		return "", nil, 0, ErrBechInvalidLength
	}
	lower := strings.ToLower(s)
	upper := strings.ToUpper(s)
	if s != lower && s != upper {
		return "", nil, 0, ErrBechMixedCase
	}
	s = lower

	sep := strings.LastIndexByte(s, '1')
	if sep < 1 || sep+7 > len(s) {
		return "", nil, 0, ErrBechNoSeparator
	}
	hrp = s[:sep]
	for i := 0; i < len(hrp); i++ {
		c := hrp[i]
		if c < 33 || c > 126 {
			return "", nil, 0, ErrBechInvalidCharacter
		}
	}

	dataPart := s[sep+1:]
	values := make([]byte, len(dataPart))
	for i := 0; i < len(dataPart); i++ {
		v := charsetRev[dataPart[i]]
		if v < 0 {
			return "", nil, 0, ErrBechInvalidCharacter
		}
		values[i] = byte(v)
	}

	constant = verifyChecksum(hrp, values)
	if constant == 0 {
		return "", nil, 0, ErrBechInvalidChecksum
	}

	data = values[:len(values)-6]
	return hrp, data, constant, nil
}
