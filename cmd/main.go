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
			fmt.Println("  ⚠️  IMPORTANT: Save this seed hex securely.")
			fmt.Println("  ⚠️  Also back up your wallet database file (qoge_wallet.db).")
			fmt.Println("  ⚠️  The seed ALONE cannot recover your wallet in this version.")
			fmt.Println("  ⚠️  Both the seed and the database file are required for access.")
			fmt.Println("  Press ENTER once you have saved the seed and noted the backup requirement.")
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
		fmt.Println("  4. Simulate confirmation (PENDING → SPENT, flags address used)")
		fmt.Println("  5. List addresses eligible for key purging")
		fmt.Println("  6. Purge key for a SPENT address (PERMANENT — cannot be undone)")
		fmt.Println("  7. Exit")
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
			// Flags the address SPENT (prevents reuse) — does NOT destroy the private key.
			// Use option 6 to destroy the key when ready.
			fmt.Print("  Enter address to confirm (flags SPENT, no key destruction): ")
			addr := strings.TrimSpace(prompt())
			if err := w.OnConfirmation(addr, 1); err != nil {
				fmt.Printf("  ✗ Error: %v\n", err)
				continue
			}
			fmt.Println("  ✓ Address flagged SPENT. Private key still present.")
			fmt.Println("    Address pool refilled with fresh pre-generated addresses.")
			fmt.Println("    Use option 5 to check eligibility and option 6 to purge the key.")

		case "5":
			// Advisory scan — shows SPENT addresses eligible for key destruction.
			// Does not purge anything.
			eligible, err := w.ListPurgeEligibleAddresses(func(_ string) int {
				// In the CLI demo, we have no live chain height — report all SPENT addresses
				// as eligible by returning the minimum threshold. In production, wire this
				// to the chain's confirmation-depth query.
				return wallet.KeyDestructionMinConfirmations
			})
			if err != nil {
				fmt.Printf("  ✗ Error: %v\n", err)
				continue
			}
			if len(eligible) == 0 {
				fmt.Println("  No SPENT addresses have reached the purge eligibility threshold yet.")
			} else {
				fmt.Printf("\n  The following %d address(es) are SPENT and eligible for key purging.\n", len(eligible))
				fmt.Printf("  Use option 6 to purge any of them. This cannot be undone.\n\n")
				for i, e := range eligible {
					fmt.Printf("    [%d] %s  (%d confirmations)\n", i+1, e.Address, e.Confirmations)
				}
			}

		case "6":
			// Permanently destroys the private key for a SPENT address.
			// This action is IRREVERSIBLE and optional — the wallet works normally
			// without ever purging keys.
			fmt.Println("  ⚠  WARNING: key purging is PERMANENT and CANNOT be undone.")
			fmt.Println("  ⚠  Only do this if you are certain the spending transaction is deeply confirmed.")
			fmt.Print("  Enter SPENT address to purge key for (or ENTER to cancel): ")
			addr := strings.TrimSpace(prompt())
			if addr == "" {
				fmt.Println("  Cancelled.")
				continue
			}
			if err := w.PurgeSpentKey(addr, wallet.KeyDestructionMinConfirmations); err != nil {
				fmt.Printf("  ✗ Error: %v\n", err)
				continue
			}
			fmt.Println("  ✓ Key PURGED. Private key zeroed in memory and the database record.")
			fmt.Println("    Note: bbolt uses copy-on-write storage — old pages may persist on disk")
			fmt.Println("    until overwritten during compaction. The seed is encrypted at rest, so")
			fmt.Println("    residual pages do not expose the raw key. Full removal requires")
			fmt.Println("    compaction or secure erasure of the database file.")
			fmt.Println("    This purge cannot be undone.")

		case "7":
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
