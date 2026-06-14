module github.com/saogen/qoge-sphincs-wallet

go 1.21

require (
	// segwit: reference Bech32/Bech32m encoder used by Bitcoin Core.
	// We reuse the Bech32 codec and supply our own HRP ("qoge").
	github.com/btcsuite/btcutil v1.0.2
	// liboqs-go: Open Quantum Safe Go bindings
	// IMPORTANT (M1.1): Pin to a build that exposes FIPS 205 SLH-DSA-SHA2-128f.
	// The ref repo used Round 3 "SPHINCS+-SHA2-128s-simple".
	// Once the OQS project tags a FIPS-205-final release, update this path.
	// For now we keep the same import path but the algorithm string constant
	// in crypto/slhdsa.go is set to the FIPS 205 name so the swap is one line.
	github.com/open-quantum-safe/liboqs-go v0.0.0-00010101000000-000000000000

	// Bolt: lightweight embedded key/value store for the index DB.
	// Pure Go, no CGo, battle-tested, suitable for the address index.
	go.etcd.io/bbolt v1.3.9

	// golang.org/x/crypto for HKDF key derivation and secure memory zeroing.
	golang.org/x/crypto v0.22.0
)

require golang.org/x/sys v0.19.0 // indirect

// Replace directive: point at your local fork of liboqs-go once you have
// updated it to FIPS 205 parameter sets (Milestone M1.1).
// Uncomment and adjust path when ready:
// replace github.com/open-quantum-safe/liboqs-go => ../liboqs-go-fips205

replace github.com/open-quantum-safe/liboqs-go => /home/ion/liboqs-go
