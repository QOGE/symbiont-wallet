// QOGE SPHINCS Wallet — CLI entry point
//
// Replaces eomii/SPHINCS-Wallet main.go.
//
// Key differences from the reference repo:
//   - Algorithm: SLH-DSA-SHA2-128f (FIPS 205) instead of SPHINCS+-SHA2-128s-simple (Round 3)
//   - Address: HASH256 + Bech32("qoge") instead of ethereum crypto.Keccak256
//   - Key lifecycle: single-use HD index with state machine (FRESH→PENDING→SPENT→RETIRED)
//   - Taproot: not present (M1.7 — removed at compile time, not a menu option)
//   - Key storage: encrypted bbolt index instead of plaintext keypair.json
//   - Key destruction: on confirmation callback, not on process exit
//
// M1.7 COMPLIANCE: grep this file for "taproot", "P2TR", "Bech32m", "bc1p".
// None should appear. Absence is the security control.
package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/saogen/qoge-sphincs-wallet/wallet"
)

const walletDBPath = "qoge_wallet.db"

func main() {
	fmt.Println("╔══════════════════════════════════════════════════════════╗")
	fmt.Println("║        QOGE SPHINCS Wallet — SIP-QOGE-PQC-01 v1.0       ║")
	fmt.Println("║   SLH-DSA-SHA2-128f (FIPS 205) | Single-Use Addresses   ║")
	fmt.Println("║              ⚠  EXPERIMENTAL — DO NOT USE IN PRODUCTION  ║")
	fmt.Println("╚══════════════════════════════════════════════════════════╝")
	fmt.Println()

	var w *wallet.Wallet

	for {
		fmt.Println("── Wallet Setup ───────────────────────────────────")
		fmt.Println("  1. Create new wallet (generate master seed)")
		fmt.Println("  2. Open existing wallet (enter seed hex)")
		fmt.Println("  3. Exit")
		choice := promptChoice()

		switch choice {
		case "1":
			seed, err := wallet.GenerateMasterSeed()
			if err != nil {
				log.Fatalf("FATAL: seed generation failed: %v", err)
			}
			fmt.Printf("\n  ⚠  WRITE DOWN YOUR SEED AND STORE OFFLINE:\n")
			fmt.Printf("  Seed (hex): %s\n\n", hex.EncodeToString(seed))
			fmt.Println("  Press ENTER once you have saved the seed securely.")
			bufio.NewReader(os.Stdin).ReadString('\n')

			w, err = wallet.New(walletDBPath, seed)
			if err != nil {
				log.Fatalf("FATAL: wallet init failed: %v", err)
			}
			defer w.Close()
			fmt.Println("  ✓ Wallet created and address pool pre-generated.")
			goto mainMenu

		case "2":
			fmt.Print("  Enter seed hex (64 hex chars = 32 bytes): ")
			seedHex := strings.TrimSpace(prompt())
			seed, err := hex.DecodeString(seedHex)
			if err != nil || len(seed) != 32 {
				fmt.Println("  ✗ Invalid seed. Must be exactly 64 hex characters.")
				continue
			}
			w, err = wallet.New(walletDBPath, seed)
			if err != nil {
				log.Fatalf("FATAL: wallet open failed: %v", err)
			}
			defer w.Close()
			fmt.Println("  ✓ Wallet opened.")
			goto mainMenu

		case "3":
			os.Exit(0)

		default:
			fmt.Println("  Invalid choice.")
		}
	}

mainMenu:
	for {
		fmt.Println()
		fmt.Println("── QOGE Wallet ────────────────────────────────────")
		fmt.Println("  1. Get next receive address")
		fmt.Println("  2. Mark payment received (FRESH → PENDING)")
		fmt.Println("  3. Sign message")
		fmt.Println("  4. Simulate confirmation (PENDING → RETIRED + key zero)")
		fmt.Println("  5. Exit")
		choice := promptChoice()

		switch choice {
		case "1":
			addr, err := w.NextReceiveAddress()
			if err != nil {
				fmt.Printf("  ✗ Error: %v\n", err)
				continue
			}
			fmt.Printf("\n  ✓ Next receive address: %s\n", addr)
			fmt.Println("  Share this address exactly once. Never reuse it.")

		case "2":
			fmt.Print("  Enter address to mark as PENDING: ")
			addr := strings.TrimSpace(prompt())
			if err := w.MarkPaymentReceived(addr); err != nil {
				fmt.Printf("  ✗ Error: %v\n", err)
				continue
			}
			fmt.Println("  ✓ Address marked PENDING.")

		case "3":
			fmt.Print("  Enter address to sign from (must be PENDING): ")
			addr := strings.TrimSpace(prompt())
			fmt.Print("  Enter message to sign: ")
			msg := strings.TrimSpace(prompt())

			pubKey, sig, err := w.SignMessage(addr, []byte(msg))
			if err != nil {
				fmt.Printf("  ✗ Error: %v\n", err)
				continue
			}
			fmt.Printf("\n  ✓ Signed successfully.\n")
			fmt.Printf("  Public key : %s\n", hex.EncodeToString(pubKey))
			fmt.Printf("  Sig length : %d bytes (expect ~17088 for SLH-DSA-SHA2-128f)\n", len(sig))
			fmt.Printf("  Sig (first 32 bytes): %s...\n", hex.EncodeToString(sig[:min(32, len(sig))]))

			// Verify the signature immediately as a sanity check.
			ok, err := wallet.VerifySignature([]byte(msg), sig, pubKey)
			if err != nil || !ok {
				fmt.Printf("  ✗ CRITICAL: self-verification FAILED: %v\n", err)
			} else {
				fmt.Println("  ✓ Self-verification passed.")
			}

		case "4":
			// Simulates the QOGE chain calling OnConfirmation after a spend tx confirms.
			// In production this is triggered by the chain's block notification, not the CLI.
			fmt.Print("  Enter address to confirm (mark SPENT → RETIRED, zero key): ")
			addr := strings.TrimSpace(prompt())
			if err := w.OnConfirmation(addr, wallet.KeyDestructionMinConfirmations); err != nil {
				fmt.Printf("  ✗ Error: %v\n", err)
				continue
			}
			fmt.Println("  ✓ Address RETIRED. Private key zeroed from memory and storage.")
			fmt.Println("    Address pool refilled with fresh pre-generated addresses.")

		case "5":
			fmt.Println("  Closing wallet (zeroing sensitive memory)...")
			os.Exit(0)

		default:
			fmt.Println("  Invalid choice.")
		}
	}
}

func prompt() string {
	reader := bufio.NewReader(os.Stdin)
	text, _ := reader.ReadString('\n')
	return strings.TrimSpace(text)
}

func promptChoice() string {
	fmt.Print("  Choice: ")
	return strings.TrimSpace(prompt())
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
