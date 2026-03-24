package secrets

import (
	"bytes"
	"testing"

	"github.com/veilkey/veilkey-go-package/crypto"
)

// ══════════════════════════════════════════════════════════════════
// Domain-level cipher tests for LocalVault secrets
// The secrets package stores ciphertext encrypted with AES-256-GCM
// via the agent's DEK. These tests verify the fundamental encryption
// invariants that all secret storage depends on.
// ══════════════════════════════════════════════════════════════════

// --- Secret encrypt/decrypt roundtrip ---

// Guarantees: A secret value encrypted with a DEK can be recovered with the same DEK.
// This is the core secret storage contract: when VaultCenter pushes an encrypted
// secret to LocalVault, it must be decryptable for bulk-apply file rendering.
func TestSecretEncryptDecrypt_Roundtrip(t *testing.T) {
	tests := []struct {
		name      string
		plaintext []byte
	}{
		{"simple password", []byte("hunter2")},
		{"JSON credentials", []byte(`{"username":"admin","password":"s3cret"}`)},
		{"empty value", []byte("")},
		{"binary token", []byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01}},
		{"multiline PEM key", []byte("-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----\n")},
	}

	dek, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ciphertext, nonce, err := crypto.Encrypt(dek, tt.plaintext)
			if err != nil {
				t.Fatalf("Encrypt failed: %v", err)
			}

			decrypted, err := crypto.Decrypt(dek, ciphertext, nonce)
			if err != nil {
				t.Fatalf("Decrypt failed: %v", err)
			}

			if !bytes.Equal(decrypted, tt.plaintext) {
				t.Errorf("roundtrip failed: got %q, want %q", decrypted, tt.plaintext)
			}
		})
	}
}

// --- Different KEKs produce different ciphertext ---

// Guarantees: The same plaintext encrypted with different keys produces different ciphertext.
// This ensures key isolation between vaults: secrets from one vault cannot be
// confused with or decrypted by another vault's key.
func TestDifferentKEKs_ProduceDifferentCiphertext(t *testing.T) {
	key1, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey (key1) failed: %v", err)
	}
	key2, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey (key2) failed: %v", err)
	}

	plaintext := []byte("same-secret-for-both-keys")

	ct1, _, err := crypto.Encrypt(key1, plaintext)
	if err != nil {
		t.Fatalf("Encrypt with key1 failed: %v", err)
	}
	ct2, _, err := crypto.Encrypt(key2, plaintext)
	if err != nil {
		t.Fatalf("Encrypt with key2 failed: %v", err)
	}

	if bytes.Equal(ct1, ct2) {
		t.Error("different keys must produce different ciphertext")
	}
}

// --- Tampered ciphertext fails decrypt ---

// Guarantees: Tampered ciphertext is detected and rejected.
// AES-GCM provides authenticated encryption: any bit flip in the ciphertext
// causes decryption to fail. This prevents an attacker who has DB access
// from silently modifying secret values.
func TestTamperedCiphertext_FailsDecrypt(t *testing.T) {
	tests := []struct {
		name   string
		tamper func(ct []byte, nonce []byte) ([]byte, []byte)
	}{
		{
			name: "flipped ciphertext byte",
			tamper: func(ct, nonce []byte) ([]byte, []byte) {
				tampered := make([]byte, len(ct))
				copy(tampered, ct)
				tampered[0] ^= 0xff
				return tampered, nonce
			},
		},
		{
			name: "flipped nonce byte",
			tamper: func(ct, nonce []byte) ([]byte, []byte) {
				tampered := make([]byte, len(nonce))
				copy(tampered, nonce)
				tampered[0] ^= 0xff
				return ct, tampered
			},
		},
		{
			name: "truncated ciphertext",
			tamper: func(ct, nonce []byte) ([]byte, []byte) {
				if len(ct) < 2 {
					return ct, nonce
				}
				return ct[:len(ct)-1], nonce
			},
		},
		{
			name: "appended byte to ciphertext",
			tamper: func(ct, nonce []byte) ([]byte, []byte) {
				return append(ct, 0x42), nonce
			},
		},
	}

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plaintext := []byte("integrity-protected-secret")
			ct, nonce, err := crypto.Encrypt(key, plaintext)
			if err != nil {
				t.Fatalf("Encrypt failed: %v", err)
			}

			tamperedCT, tamperedNonce := tt.tamper(ct, nonce)
			_, err = crypto.Decrypt(key, tamperedCT, tamperedNonce)
			if err == nil {
				t.Error("Decrypt with tampered data must return error")
			}
		})
	}
}

// --- Cross-key decryption fails ---

// Guarantees: Ciphertext from one DEK cannot be decrypted with a different DEK.
// This ensures vault isolation: even if an attacker obtains the ciphertext
// from one vault's database, they cannot decrypt it with another vault's key.
func TestCrossKeyDecrypt_Fails(t *testing.T) {
	key1, _ := crypto.GenerateKey()
	key2, _ := crypto.GenerateKey()

	ct, nonce, err := crypto.Encrypt(key1, []byte("vault-A-secret"))
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	_, err = crypto.Decrypt(key2, ct, nonce)
	if err == nil {
		t.Error("decrypting with wrong key must fail")
	}
}
