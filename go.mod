module github.com/saogen/qoge-sphincs-wallet

go 1.22.0

toolchain go1.22.2

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
	golang.org/x/crypto v0.33.0
)

require fyne.io/fyne/v2 v2.8.0

require (
	fyne.io/systray v1.12.2 // indirect
	github.com/BurntSushi/toml v1.6.0 // indirect
	github.com/FyshOS/fancyfs v0.0.1 // indirect
	github.com/anthonynsimon/bild v0.14.0 // indirect
	github.com/clipperhouse/uax29/v2 v2.2.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/fredbi/uri v1.1.1 // indirect
	github.com/fsnotify/fsnotify v1.9.0 // indirect
	github.com/fyne-io/gl-js v0.2.1-0.20260315212741-029c47fd27e8 // indirect
	github.com/fyne-io/glfw-js v0.4.0 // indirect
	github.com/fyne-io/image v0.1.1 // indirect
	github.com/fyne-io/oksvg v0.2.0 // indirect
	github.com/go-gl/gl v0.0.0-20260331235117-4566fea9a276 // indirect
	github.com/go-gl/glfw/v3.4/glfw v0.1.0-pre.1.0.20260707082822-2a407d02d01a // indirect
	github.com/go-text/render v0.2.1 // indirect
	github.com/go-text/typesetting v0.3.4 // indirect
	github.com/godbus/dbus/v5 v5.2.2 // indirect
	github.com/hack-pad/go-indexeddb v0.3.2 // indirect
	github.com/hack-pad/safejs v0.1.0 // indirect
	github.com/jeandeaual/go-locale v0.0.0-20250612000132-0ef82f21eade // indirect
	github.com/jsummers/gobmp v0.0.0-20230614200233-a9de23ed2e25 // indirect
	github.com/mattn/go-runewidth v0.0.24 // indirect
	github.com/nfnt/resize v0.0.0-20180221191011-83c6a9932646 // indirect
	github.com/nicksnyder/go-i18n/v2 v2.5.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/rymdport/portal v0.4.2 // indirect
	github.com/srwiley/oksvg v0.0.0-20221011165216-be6e8873101c // indirect
	github.com/srwiley/rasterx v0.0.0-20220730225603-2ab79fcdd4ef // indirect
	github.com/stretchr/testify v1.11.1 // indirect
	github.com/yuin/goldmark v1.8.2 // indirect
	golang.org/x/image v0.24.0 // indirect
	golang.org/x/net v0.35.0 // indirect
	golang.org/x/sys v0.30.0 // indirect
	golang.org/x/text v0.22.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

// Replace directive: point at your local fork of liboqs-go once you have
// updated it to FIPS 205 parameter sets (Milestone M1.1).
// Uncomment and adjust path when ready:
// replace github.com/open-quantum-safe/liboqs-go => ../liboqs-go-fips205

replace github.com/open-quantum-safe/liboqs-go => /home/ion/liboqs-go
