package db

import (
	"os"
	"strings"
	"testing"
)

// ── v2 migration: ref_vault, ref_group, ref_key, ref_path columns ────────────

func TestSource_TokenRefModel_HasV2Columns(t *testing.T) {
	src, err := os.ReadFile("../db/models.go")
	if err != nil {
		t.Fatalf("failed to read models.go: %v", err)
	}
	content := string(src)

	v2Fields := map[string]string{
		"RefVault": "TokenRef must have RefVault field for v2 path-based refs",
		"RefGroup": "TokenRef must have RefGroup field for v2 path-based refs",
		"RefKey":   "TokenRef must have RefKey field for v2 path-based refs",
		"RefPath":  "TokenRef must have RefPath field for v2 path-based refs",
	}
	for field, msg := range v2Fields {
		if !strings.Contains(content, field) {
			t.Error(msg)
		}
	}
}

func TestSource_TokenRefModel_V2ColumnsHaveDefaults(t *testing.T) {
	src, err := os.ReadFile("../db/models.go")
	if err != nil {
		t.Fatalf("failed to read models.go: %v", err)
	}
	content := string(src)

	// v2 columns must have default:'' so v1 records are unaffected
	v2Columns := []string{"ref_vault", "ref_group", "ref_key", "ref_path"}
	for _, col := range v2Columns {
		// Find the line containing this column definition
		lines := strings.Split(content, "\n")
		found := false
		for _, line := range lines {
			if strings.Contains(line, "column:"+col) {
				found = true
				if !strings.Contains(line, "default:''") {
					t.Errorf("column %s must have default:'' for v1 compatibility", col)
				}
				break
			}
		}
		if !found {
			t.Errorf("column %s not found in model", col)
		}
	}
}

func TestSource_TokenRefModel_VaultIndex(t *testing.T) {
	src, err := os.ReadFile("../db/models.go")
	if err != nil {
		t.Fatalf("failed to read models.go: %v", err)
	}
	content := string(src)

	// Must have idx_token_refs_vault index on ref_vault
	if !strings.Contains(content, "idx_token_refs_vault") {
		t.Error("TokenRef must have idx_token_refs_vault index on ref_vault")
	}
}

func TestSource_TokenRefModel_VaultPathCompositeIndex(t *testing.T) {
	src, err := os.ReadFile("../db/models.go")
	if err != nil {
		t.Fatalf("failed to read models.go: %v", err)
	}
	content := string(src)

	// Must have idx_token_refs_vault_path composite index on (ref_vault, ref_path)
	if !strings.Contains(content, "idx_token_refs_vault_path") {
		t.Error("TokenRef must have idx_token_refs_vault_path composite index")
	}

	// Both ref_vault and ref_path must participate in the composite index
	lines := strings.Split(content, "\n")
	vaultHasIdx := false
	pathHasIdx := false
	for _, line := range lines {
		if strings.Contains(line, "column:ref_vault") && strings.Contains(line, "idx_token_refs_vault_path") {
			vaultHasIdx = true
		}
		if strings.Contains(line, "column:ref_path") && strings.Contains(line, "idx_token_refs_vault_path") {
			pathHasIdx = true
		}
	}
	if !vaultHasIdx {
		t.Error("ref_vault must be part of idx_token_refs_vault_path composite index")
	}
	if !pathHasIdx {
		t.Error("ref_path must be part of idx_token_refs_vault_path composite index")
	}
}

func TestSource_RollbackScript_Exists(t *testing.T) {
	_, err := os.ReadFile("rollback_v2_columns.sql")
	if err != nil {
		t.Fatal("rollback_v2_columns.sql must exist for v2 migration rollback")
	}
}

func TestSource_RollbackScript_DropsV2Indexes(t *testing.T) {
	src, err := os.ReadFile("rollback_v2_columns.sql")
	if err != nil {
		t.Fatalf("failed to read rollback script: %v", err)
	}
	content := string(src)

	if !strings.Contains(content, "DROP INDEX IF EXISTS idx_token_refs_vault") {
		t.Error("rollback script must drop idx_token_refs_vault index")
	}
	if !strings.Contains(content, "DROP INDEX IF EXISTS idx_token_refs_vault_path") {
		t.Error("rollback script must drop idx_token_refs_vault_path index")
	}
}

func TestSource_RollbackScript_PreservesV1Columns(t *testing.T) {
	src, err := os.ReadFile("rollback_v2_columns.sql")
	if err != nil {
		t.Fatalf("failed to read rollback script: %v", err)
	}
	content := string(src)

	v1Columns := []string{
		"ref_canonical",
		"ref_family",
		"ref_scope",
		"ref_id",
		"secret_name",
		"agent_hash",
		"ciphertext",
		"version",
		"status",
		"expires_at",
		"created_at",
	}
	for _, col := range v1Columns {
		if !strings.Contains(content, col) {
			t.Errorf("rollback script must preserve v1 column: %s", col)
		}
	}
}

func TestSource_RollbackScript_RemovesV2Columns(t *testing.T) {
	src, err := os.ReadFile("rollback_v2_columns.sql")
	if err != nil {
		t.Fatalf("failed to read rollback script: %v", err)
	}
	content := string(src)

	// The rollback creates a backup table without v2 columns
	if !strings.Contains(content, "token_refs_backup") {
		t.Error("rollback script must use backup table strategy for SQLite compatibility")
	}
	if !strings.Contains(content, "DROP TABLE token_refs") {
		t.Error("rollback script must drop the original table before recreating")
	}
}

func TestSource_V2ColumnsNotInV1Queries(t *testing.T) {
	src, err := os.ReadFile("db_token_ref.go")
	if err != nil {
		t.Fatalf("failed to read db_token_ref.go: %v", err)
	}
	content := string(src)

	// SaveRef (v1 flow) must NOT require v2 columns — they should remain empty
	// Check that the INSERT in SaveRefWithName doesn't include ref_vault/ref_path
	saveRefIdx := strings.Index(content, "func (d *DB) SaveRefWithName(")
	if saveRefIdx == -1 {
		t.Fatal("SaveRefWithName function not found")
	}
	// Get the function body (up to the next top-level func)
	nextFuncIdx := strings.Index(content[saveRefIdx+1:], "\nfunc ")
	if nextFuncIdx == -1 {
		nextFuncIdx = len(content) - saveRefIdx - 1
	}
	saveRefBody := content[saveRefIdx : saveRefIdx+1+nextFuncIdx]

	// v1 SaveRef should not set ref_vault — v2 columns get default ''
	if strings.Contains(saveRefBody, "ref_vault") || strings.Contains(saveRefBody, "ref_path") {
		t.Error("SaveRefWithName (v1 flow) should not set v2 columns — they use default ''")
	}
}
