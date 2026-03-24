package api

import (
	"bytes"
	"testing"
)

// ══════════════════════════════════════════════════════════════════
// Domain-level tests for LocalVault internal/api
// These verify the core invariants of the Server type that all
// higher-level features (heartbeat, unlock, secret management) rely on.
// ══════════════════════════════════════════════════════════════════

// --- DeriveDBKeyFromKEK ---

// Guarantees: The same KEK always produces the same DB encryption key.
// Without this property, a vault that was encrypted with one key
// could not be reopened after restart.
func TestDeriveDBKeyFromKEK_Deterministic(t *testing.T) {
	kek := []byte("0123456789abcdef0123456789abcdef") // 32 bytes
	key1 := DeriveDBKeyFromKEK(kek)
	key2 := DeriveDBKeyFromKEK(kek)
	if key1 != key2 {
		t.Errorf("DeriveDBKeyFromKEK is not deterministic: %q != %q", key1, key2)
	}
	if len(key1) != 64 {
		t.Errorf("expected 64-char hex string, got length %d", len(key1))
	}
}

// Guarantees: Different KEKs produce different DB encryption keys.
// This ensures that a wrong password cannot accidentally open the database.
func TestDeriveDBKeyFromKEK_DifferentKEKs(t *testing.T) {
	kek1 := []byte("0123456789abcdef0123456789abcdef")
	kek2 := []byte("fedcba9876543210fedcba9876543210")
	key1 := DeriveDBKeyFromKEK(kek1)
	key2 := DeriveDBKeyFromKEK(kek2)
	if key1 == key2 {
		t.Error("different KEKs must produce different DB keys")
	}
}

// --- Identity copy semantics ---

// Guarantees: Identity() returns a defensive copy.
// Callers modifying the returned struct must not corrupt server state.
func TestIdentity_CopySemantics(t *testing.T) {
	s := &Server{}
	original := &NodeIdentity{
		NodeID:    "node-1",
		Version:   1,
		VaultHash: "abc123",
		VaultName: "test-vault",
	}
	s.SetIdentity(original)

	// Get a copy and mutate it
	copy := s.Identity()
	copy.NodeID = "MUTATED"
	copy.VaultName = "MUTATED"

	// Server state must be unaffected
	got := s.Identity()
	if got.NodeID != "node-1" {
		t.Errorf("Identity() did not return a copy: NodeID was mutated to %q", got.NodeID)
	}
	if got.VaultName != "test-vault" {
		t.Errorf("Identity() did not return a copy: VaultName was mutated to %q", got.VaultName)
	}
}

// --- SetIdentity / Identity roundtrip ---

// Guarantees: SetIdentity followed by Identity returns the same values.
func TestSetIdentity_Identity_Roundtrip(t *testing.T) {
	tests := []struct {
		name     string
		identity *NodeIdentity
	}{
		{
			name: "full identity",
			identity: &NodeIdentity{
				NodeID:    "node-abc",
				Version:   42,
				VaultHash: "deadbeef",
				VaultName: "my-vault",
			},
		},
		{
			name: "empty strings",
			identity: &NodeIdentity{
				NodeID:    "",
				Version:   0,
				VaultHash: "",
				VaultName: "",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Server{}
			s.SetIdentity(tt.identity)
			got := s.Identity()
			if got == nil {
				t.Fatal("Identity() returned nil after SetIdentity")
			}
			if got.NodeID != tt.identity.NodeID {
				t.Errorf("NodeID = %q, want %q", got.NodeID, tt.identity.NodeID)
			}
			if got.Version != tt.identity.Version {
				t.Errorf("Version = %d, want %d", got.Version, tt.identity.Version)
			}
			if got.VaultHash != tt.identity.VaultHash {
				t.Errorf("VaultHash = %q, want %q", got.VaultHash, tt.identity.VaultHash)
			}
			if got.VaultName != tt.identity.VaultName {
				t.Errorf("VaultName = %q, want %q", got.VaultName, tt.identity.VaultName)
			}
		})
	}
}

// Guarantees: Identity() returns nil when no identity has been set.
func TestIdentity_NilWhenUnset(t *testing.T) {
	s := &Server{}
	if got := s.Identity(); got != nil {
		t.Errorf("Identity() = %+v, want nil when no identity set", got)
	}
}

// --- IsLocked initial state ---

// Guarantees: A server created with nil KEK starts in locked state.
// This ensures no data can be accessed before the vault password is provided.
func TestIsLocked_InitialState(t *testing.T) {
	s := NewServer(nil, nil, nil)
	defer s.Close()
	if !s.IsLocked() {
		t.Error("server must start locked when created with nil KEK")
	}
}

// Guarantees: A server created with a non-nil KEK starts unlocked.
func TestIsLocked_UnlockedWithKEK(t *testing.T) {
	kek := []byte("0123456789abcdef0123456789abcdef")
	s := NewServer(nil, kek, nil)
	defer s.Close()
	if s.IsLocked() {
		t.Error("server must start unlocked when created with non-nil KEK")
	}
}

// --- Salt ---

// Guarantees: Salt() returns the value set via SetDBPath.
// The salt is essential for KEK derivation — losing it means losing vault access.
func TestSalt_ReturnsValueAfterSetDBPath(t *testing.T) {
	s := &Server{}
	salt := []byte("test-salt-value-32-bytes-long!!")
	s.SetDBPath("/tmp/test.db", salt)
	got := s.Salt()
	if got == nil {
		t.Fatal("Salt() returned nil after SetDBPath")
	}
	if !bytes.Equal(got, salt) {
		t.Errorf("Salt() = %x, want %x", got, salt)
	}
}

// Guarantees: Salt() returns nil when no salt has been set.
func TestSalt_NilWhenUnset(t *testing.T) {
	s := &Server{}
	if got := s.Salt(); got != nil {
		t.Errorf("Salt() = %x, want nil when no salt set", got)
	}
}

// --- agentAuthHeader ---

// Guarantees: agentAuthHeader returns empty string when server is locked.
// This prevents any authenticated communication with VaultCenter before
// the vault is unlocked, which would be a security violation.
func TestAgentAuthHeader_EmptyWhenLocked(t *testing.T) {
	s := NewServer(nil, nil, nil)
	defer s.Close()
	if !s.IsLocked() {
		t.Fatal("precondition: server must be locked")
	}
	if got := s.agentAuthHeader(); got != "" {
		t.Errorf("agentAuthHeader() = %q, want empty string when locked", got)
	}
}

// --- VaultUnlockKey lifecycle ---

// Guarantees: VaultUnlockKey set/get/clear cycle works correctly.
// The vault unlock key is held in memory temporarily until VC confirms storage.
func TestVaultUnlockKey_Lifecycle(t *testing.T) {
	s := &Server{}

	// Initially empty
	if got := s.VaultUnlockKey(); got != "" {
		t.Errorf("VaultUnlockKey() = %q, want empty initially", got)
	}

	// Set
	s.SetVaultUnlockKey("my-secret-password")
	if got := s.VaultUnlockKey(); got != "my-secret-password" {
		t.Errorf("VaultUnlockKey() = %q, want %q", got, "my-secret-password")
	}

	// Clear
	s.ClearVaultUnlockKey()
	if got := s.VaultUnlockKey(); got != "" {
		t.Errorf("VaultUnlockKey() = %q, want empty after clear", got)
	}
}

// --- GetKEK copy semantics ---

// Guarantees: GetKEK returns a copy, not the internal slice.
// Callers must not be able to corrupt the server's KEK by modifying the returned slice.
func TestGetKEK_ReturnsCopy(t *testing.T) {
	kek := []byte("0123456789abcdef0123456789abcdef")
	s := NewServer(nil, kek, nil)
	defer s.Close()

	got := s.GetKEK()
	// Mutate the returned slice
	for i := range got {
		got[i] = 0xff
	}

	// Server's KEK must be unaffected
	kek2 := s.GetKEK()
	if bytes.Equal(kek2, got) {
		t.Error("GetKEK must return a copy — mutating the result corrupted server state")
	}
}
