package db

import (
	"bytes"
	"testing"

	"github.com/veilkey/veilkey-go-package/crypto"
)

// ══════════════════════════════════════════════════════════════════
// Domain-level encryption tests for VaultCenter DB layer
// The DB stores secrets encrypted with AES-256-GCM via the crypto package.
// These tests verify the invariants that the entire secret management
// system depends on.
// ══════════════════════════════════════════════════════════════════

// --- Encrypt/Decrypt roundtrip ---

// Guarantees: Data encrypted with a key can be decrypted with the same key.
// This is the fundamental contract of envelope encryption: KEK wraps DEK,
// DEK wraps secret values. If this roundtrip fails, all stored secrets are lost.
func TestEncryptDecrypt_Roundtrip(t *testing.T) {
	tests := []struct {
		name      string
		plaintext []byte
	}{
		{"short secret", []byte("my-password")},
		{"empty data", []byte("")},
		{"binary data", []byte{0x00, 0x01, 0xff, 0xfe, 0x80}},
		{"large payload", bytes.Repeat([]byte("A"), 1024*64)},
		{"unicode text", []byte("비밀키-テスト-секрет")},
	}

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ciphertext, nonce, err := crypto.Encrypt(key, tt.plaintext)
			if err != nil {
				t.Fatalf("Encrypt failed: %v", err)
			}

			decrypted, err := crypto.Decrypt(key, ciphertext, nonce)
			if err != nil {
				t.Fatalf("Decrypt failed: %v", err)
			}

			if !bytes.Equal(decrypted, tt.plaintext) {
				t.Errorf("roundtrip failed: got %q, want %q", decrypted, tt.plaintext)
			}
		})
	}
}

// --- Decrypt with wrong key fails ---

// Guarantees: Ciphertext encrypted with one key cannot be decrypted with a different key.
// This is the core confidentiality property: without the correct KEK, the
// encrypted DEK (and therefore all secrets) are inaccessible.
func TestDecrypt_WrongKey_Fails(t *testing.T) {
	key1, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	key2, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	plaintext := []byte("sensitive-data")
	ciphertext, nonce, err := crypto.Encrypt(key1, plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	_, err = crypto.Decrypt(key2, ciphertext, nonce)
	if err == nil {
		t.Error("Decrypt with wrong key must return error, got nil")
	}
}

// --- Encrypt produces different ciphertext (nonce uniqueness) ---

// Guarantees: Two encryptions of the same plaintext with the same key produce
// different ciphertext. This proves that a fresh random nonce is used each time,
// which is essential for AES-GCM security. Reusing a nonce would allow an
// attacker to recover plaintext.
func TestEncrypt_ProducesDifferentCiphertext(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	plaintext := []byte("same-data-encrypted-twice")

	ct1, nonce1, err := crypto.Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("first Encrypt failed: %v", err)
	}

	ct2, nonce2, err := crypto.Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("second Encrypt failed: %v", err)
	}

	if bytes.Equal(ct1, ct2) {
		t.Error("two encryptions of same data must produce different ciphertext (nonce reuse detected)")
	}
	if bytes.Equal(nonce1, nonce2) {
		t.Error("two encryptions must use different nonces")
	}
}

// --- DEK envelope encryption roundtrip ---

// Guarantees: A DEK encrypted with EncryptDEK can be recovered with DecryptDEK.
// This is the envelope encryption pattern used for all agent DEKs.
func TestDEK_EnvelopeEncryption_Roundtrip(t *testing.T) {
	kek, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey (KEK) failed: %v", err)
	}
	dek, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey (DEK) failed: %v", err)
	}

	encDEK, nonce, err := crypto.EncryptDEK(kek, dek)
	if err != nil {
		t.Fatalf("EncryptDEK failed: %v", err)
	}

	recovered, err := crypto.DecryptDEK(kek, encDEK, nonce)
	if err != nil {
		t.Fatalf("DecryptDEK failed: %v", err)
	}

	if !bytes.Equal(recovered, dek) {
		t.Error("DEK roundtrip failed: recovered DEK does not match original")
	}
}

// --- Tampered ciphertext detection ---

// Guarantees: AES-GCM detects tampered ciphertext and returns an error.
// This is the integrity property: any modification to the ciphertext or nonce
// is detected, preventing silent data corruption.
func TestDecrypt_TamperedCiphertext_Fails(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	plaintext := []byte("integrity-test")
	ciphertext, nonce, err := crypto.Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Tamper with the ciphertext
	tampered := make([]byte, len(ciphertext))
	copy(tampered, ciphertext)
	tampered[0] ^= 0xff

	_, err = crypto.Decrypt(key, tampered, nonce)
	if err == nil {
		t.Error("Decrypt with tampered ciphertext must return error")
	}
}
