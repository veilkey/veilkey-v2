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

	// Must have idx_token_refs_vault as a standalone index (not just as part of
	// idx_token_refs_vault_path). Both may appear on the same gorm tag line, so
	// strip all occurrences of the longer name before checking for the shorter one.
	stripped := strings.ReplaceAll(content, "idx_token_refs_vault_path", "")
	if !strings.Contains(stripped, "idx_token_refs_vault") {
		t.Error("TokenRef must have idx_token_refs_vault index on ref_vault (distinct from idx_token_refs_vault_path)")
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

	// Line-level matching to distinguish idx_token_refs_vault from idx_token_refs_vault_path
	foundVault := false
	foundVaultPath := false
	for _, line := range strings.Split(string(src), "\n") {
		if strings.Contains(line, "DROP INDEX IF EXISTS idx_token_refs_vault_path") {
			foundVaultPath = true
		} else if strings.Contains(line, "DROP INDEX IF EXISTS idx_token_refs_vault") {
			foundVault = true
		}
	}
	if !foundVault {
		t.Error("rollback script must drop idx_token_refs_vault index")
	}
	if !foundVaultPath {
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

func TestSource_RollbackScript_HasTransaction(t *testing.T) {
	src, err := os.ReadFile("rollback_v2_columns.sql")
	if err != nil {
		t.Fatalf("failed to read rollback script: %v", err)
	}
	content := string(src)

	if !strings.Contains(content, "BEGIN;") {
		t.Error("rollback script must be wrapped in a transaction (missing BEGIN;)")
	}
	if !strings.Contains(content, "COMMIT;") {
		t.Error("rollback script must be wrapped in a transaction (missing COMMIT;)")
	}
}

// ── Runtime tests: real DB verification ─────────────────────────────────────

func TestRuntime_V2IndexesExist(t *testing.T) {
	d, err := New(":memory:")
	if err != nil {
		t.Fatalf("failed to create test DB: %v", err)
	}
	defer d.Close()

	var indexes []struct {
		Name string `gorm:"column:name"`
	}
	if err := d.conn.Raw("PRAGMA index_list('token_refs')").Scan(&indexes).Error; err != nil {
		t.Fatalf("PRAGMA index_list failed: %v", err)
	}

	idxSet := make(map[string]bool)
	for _, idx := range indexes {
		idxSet[idx.Name] = true
	}

	if !idxSet["idx_token_refs_vault"] {
		t.Error("idx_token_refs_vault index not found in runtime DB")
	}
	if !idxSet["idx_token_refs_vault_path"] {
		t.Error("idx_token_refs_vault_path index not found in runtime DB")
	}
}

func TestRuntime_RollbackRemovesV2Columns(t *testing.T) {
	d, err := New(":memory:")
	if err != nil {
		t.Fatalf("failed to create test DB: %v", err)
	}
	defer d.Close()

	// Insert a v1 record so we can verify data survives rollback
	parts := RefParts{Family: "VK", Scope: RefScopeLocal, ID: "rolltest1"}
	if err := d.SaveRef(parts, "cipher-rolltest1", 1, RefStatusActive, ""); err != nil {
		t.Fatalf("SaveRef failed: %v", err)
	}

	// Execute rollback script
	sql, err := os.ReadFile("rollback_v2_columns.sql")
	if err != nil {
		t.Fatalf("failed to read rollback script: %v", err)
	}
	if err := d.conn.Exec(string(sql)).Error; err != nil {
		t.Fatalf("rollback script execution failed: %v", err)
	}

	// Verify v2 indexes are gone
	var indexes []struct {
		Name string `gorm:"column:name"`
	}
	if err := d.conn.Raw("PRAGMA index_list('token_refs')").Scan(&indexes).Error; err != nil {
		t.Fatalf("PRAGMA index_list failed: %v", err)
	}
	for _, idx := range indexes {
		if idx.Name == "idx_token_refs_vault" || idx.Name == "idx_token_refs_vault_path" {
			t.Errorf("v2 index %s still exists after rollback", idx.Name)
		}
	}

	// Verify v2 columns are gone
	var cols []struct {
		Name string `gorm:"column:name"`
	}
	if err := d.conn.Raw("PRAGMA table_info('token_refs')").Scan(&cols).Error; err != nil {
		t.Fatalf("PRAGMA table_info failed: %v", err)
	}
	colSet := make(map[string]bool)
	for _, c := range cols {
		colSet[c.Name] = true
	}
	for _, v2col := range []string{"ref_vault", "ref_group", "ref_key", "ref_path"} {
		if colSet[v2col] {
			t.Errorf("v2 column %s still exists after rollback", v2col)
		}
	}

	// Verify v1 data survived
	var count int64
	if err := d.conn.Raw("SELECT COUNT(*) FROM token_refs WHERE ref_canonical = ?", "VK:LOCAL:rolltest1").Scan(&count).Error; err != nil {
		t.Fatalf("count query failed: %v", err)
	}
	if count != 1 {
		t.Errorf("v1 data lost after rollback: expected 1 row, got %d", count)
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
