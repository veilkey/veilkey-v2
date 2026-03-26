package hkm

import (
	"os"
	"strings"
	"testing"
	"time"

	"veilkey-vaultcenter/internal/db"
)

// ── Source analysis: handler.go — resolve route registration ─────────────────

func TestSource_ResolveAgent_RouteUsesWildcardToken(t *testing.T) {
	src, err := os.ReadFile("handler.go")
	if err != nil {
		t.Fatalf("failed to read handler.go: %v", err)
	}
	content := string(src)

	// The resolve-agent route must use {token...} wildcard to capture
	// v2 path-based tokens containing "/" (e.g., "host-lv/owner/password").
	if !strings.Contains(content, `GET /api/resolve-agent/{token...}`) {
		t.Error("resolve-agent route must use {token...} wildcard to support v2 path tokens with slashes")
	}
}

func TestSource_ResolveAgent_WrappedWithReady(t *testing.T) {
	src, err := os.ReadFile("handler.go")
	if err != nil {
		t.Fatalf("failed to read handler.go: %v", err)
	}
	content := string(src)

	// The resolve-agent route must be wrapped with ready() middleware
	// to ensure the server is unlocked before processing resolve requests.
	if !strings.Contains(content, `ready(h.handleAgentResolve)`) {
		t.Error("resolve-agent must be wrapped with ready() middleware")
	}
}

// ── Source analysis: hkm_agent_resolve.go — v1/v2 routing ───────────────────

func TestSource_Resolve_V2PathDetection(t *testing.T) {
	src, err := os.ReadFile("hkm_agent_resolve.go")
	if err != nil {
		t.Fatalf("failed to read hkm_agent_resolve.go: %v", err)
	}
	content := string(src)

	// handleAgentResolve must detect "/" to dispatch v2 path-based resolution.
	if !strings.Contains(content, `strings.Contains(token, "/")`) {
		t.Error("handleAgentResolve must check for '/' to detect v2 path-based tokens")
	}
	if !strings.Contains(content, "handleAgentResolveV2") {
		t.Error("handleAgentResolve must call handleAgentResolveV2 for path-based tokens")
	}
	if !strings.Contains(content, "handleAgentResolveV1") {
		t.Error("handleAgentResolve must call handleAgentResolveV1 for hash-based tokens")
	}
}

func TestSource_Resolve_EmptyTokenRejected(t *testing.T) {
	src, err := os.ReadFile("hkm_agent_resolve.go")
	if err != nil {
		t.Fatalf("failed to read hkm_agent_resolve.go: %v", err)
	}
	content := string(src)

	if !strings.Contains(content, `token == ""`) {
		t.Error("handleAgentResolve must reject empty token")
	}
	if !strings.Contains(content, "token is required") {
		t.Error("handleAgentResolve must return descriptive error for empty token")
	}
}

// ── Source analysis: v1 resolve ─────────────────────────────────────────────

func TestSource_ResolveV1_TokenLengthCheck(t *testing.T) {
	src, err := os.ReadFile("hkm_agent_resolve.go")
	if err != nil {
		t.Fatalf("failed to read hkm_agent_resolve.go: %v", err)
	}
	content := string(src)

	// v1 tokens must be longer than 8 characters (8 for agentHash + remainder for secretRef).
	if !strings.Contains(content, "len(token) <= 8") {
		t.Error("handleAgentResolveV1 must reject tokens with 8 or fewer characters")
	}
	if !strings.Contains(content, "token[:8]") {
		t.Error("handleAgentResolveV1 must extract first 8 chars as agentHash")
	}
	if !strings.Contains(content, "token[8:]") {
		t.Error("handleAgentResolveV1 must extract remaining chars as secretRef")
	}
}

func TestSource_ResolveV1_AgentLookupByHash(t *testing.T) {
	src, err := os.ReadFile("hkm_agent_resolve.go")
	if err != nil {
		t.Fatalf("failed to read hkm_agent_resolve.go: %v", err)
	}
	content := string(src)

	if !strings.Contains(content, "GetAgentByHash(agentHash)") {
		t.Error("handleAgentResolveV1 must look up agent by hash")
	}
	if !strings.Contains(content, "validateAgentAvailability") {
		t.Error("handleAgentResolveV1 must validate agent availability (blocked/rebind)")
	}
}

func TestSource_ResolveV1_DecryptionFlow(t *testing.T) {
	src, err := os.ReadFile("hkm_agent_resolve.go")
	if err != nil {
		t.Fatalf("failed to read hkm_agent_resolve.go: %v", err)
	}
	content := string(src)

	if !strings.Contains(content, "decryptAgentDEK") {
		t.Error("handleAgentResolveV1 must decrypt agent DEK")
	}
	if !strings.Contains(content, "fetchAgentCiphertext") {
		t.Error("handleAgentResolveV1 must fetch ciphertext from agent")
	}
	if !strings.Contains(content, "crypto.Decrypt") {
		t.Error("handleAgentResolveV1 must decrypt secret using crypto.Decrypt")
	}
}

func TestSource_ResolveV1_ResponseFields(t *testing.T) {
	src, err := os.ReadFile("hkm_agent_resolve.go")
	if err != nil {
		t.Fatalf("failed to read hkm_agent_resolve.go: %v", err)
	}
	content := string(src)

	fields := []string{`"ref"`, `"vault"`, `"name"`, `"value"`}
	for _, field := range fields {
		if !strings.Contains(content, field) {
			t.Errorf("v1 resolve response must include field: %s", field)
		}
	}
	if !strings.Contains(content, "setRuntimeHashAliases") {
		t.Error("v1 resolve response must include runtime hash aliases")
	}
}

// ── Source analysis: v2 resolve ─────────────────────────────────────────────

func TestSource_ResolveV2_PathParsing(t *testing.T) {
	src, err := os.ReadFile("hkm_agent_resolve.go")
	if err != nil {
		t.Fatalf("failed to read hkm_agent_resolve.go: %v", err)
	}
	content := string(src)

	if !strings.Contains(content, "parseV2Path(token)") {
		t.Error("handleAgentResolveV2 must parse token using parseV2Path")
	}
}

func TestSource_ResolveV2_VaultLookup(t *testing.T) {
	src, err := os.ReadFile("hkm_agent_resolve.go")
	if err != nil {
		t.Fatalf("failed to read hkm_agent_resolve.go: %v", err)
	}
	content := string(src)

	if !strings.Contains(content, "GetAgentByVaultName(parsed.Vault)") {
		t.Error("handleAgentResolveV2 must look up agent by vault name")
	}
	if !strings.Contains(content, `"vault not found: "`) {
		t.Error("handleAgentResolveV2 must return descriptive 404 when vault not found")
	}
}

func TestSource_ResolveV2_AgentAvailabilityCheck(t *testing.T) {
	src, err := os.ReadFile("hkm_agent_resolve.go")
	if err != nil {
		t.Fatalf("failed to read hkm_agent_resolve.go: %v", err)
	}
	content := string(src)

	if !strings.Contains(content, "validateAgentAvailability") {
		t.Error("handleAgentResolveV2 must validate agent availability")
	}
	if !strings.Contains(content, "respondAgentLookupError") {
		t.Error("handleAgentResolveV2 must handle agent state errors (blocked/rebind)")
	}
}

func TestSource_ResolveV2_FetchesByGroupKeyPath(t *testing.T) {
	src, err := os.ReadFile("hkm_agent_resolve.go")
	if err != nil {
		t.Fatalf("failed to read hkm_agent_resolve.go: %v", err)
	}
	content := string(src)

	// v2 must fetch ciphertext using the group/key path, not the full vault/group/key.
	if !strings.Contains(content, "parsed.groupKeyPath()") {
		t.Error("handleAgentResolveV2 must fetch ciphertext using groupKeyPath()")
	}
}

func TestSource_ResolveV2_ResponseFields(t *testing.T) {
	src, err := os.ReadFile("hkm_agent_resolve.go")
	if err != nil {
		t.Fatalf("failed to read hkm_agent_resolve.go: %v", err)
	}
	content := string(src)

	// v2 response must include path-specific fields in addition to common fields.
	fields := []string{`"ref"`, `"vault"`, `"group"`, `"key"`, `"path"`, `"name"`, `"value"`}
	for _, field := range fields {
		if !strings.Contains(content, field) {
			t.Errorf("v2 resolve response must include field: %s", field)
		}
	}
	if !strings.Contains(content, "setRuntimeHashAliases") {
		t.Error("v2 resolve response must include runtime hash aliases")
	}
}

func TestSource_ResolveV2_SecretNotFoundError(t *testing.T) {
	src, err := os.ReadFile("hkm_agent_resolve.go")
	if err != nil {
		t.Fatalf("failed to read hkm_agent_resolve.go: %v", err)
	}
	content := string(src)

	if !strings.Contains(content, `"secret not found: "`) {
		t.Error("handleAgentResolveV2 must return descriptive 404 when secret not found")
	}
}

// ── Source analysis: hkm_v2_path.go — path parser structure ─────────────────

func TestSource_V2Path_SegmentValidation(t *testing.T) {
	src, err := os.ReadFile("hkm_v2_path.go")
	if err != nil {
		t.Fatalf("failed to read hkm_v2_path.go: %v", err)
	}
	content := string(src)

	if !strings.Contains(content, "v2PathSegmentPattern") {
		t.Error("v2 path parser must use segment validation pattern")
	}
	if !strings.Contains(content, `[a-z0-9_]`) {
		t.Error("v2 path segments must allow lowercase, digits, and underscore")
	}
	if !strings.Contains(content, `SplitN(token, "/", 3)`) {
		t.Error("v2 path parser must split into exactly 3 parts")
	}
}

func TestSource_V2Path_EmptySegmentRejected(t *testing.T) {
	src, err := os.ReadFile("hkm_v2_path.go")
	if err != nil {
		t.Fatalf("failed to read hkm_v2_path.go: %v", err)
	}
	content := string(src)

	if !strings.Contains(content, `vault == "" || group == "" || key == ""`) {
		t.Error("v2 path parser must reject empty segments")
	}
}

// ── Source analysis: db_agent.go — GetAgentByVaultName ──────────────────────

func TestSource_DB_GetAgentByVaultName(t *testing.T) {
	src, err := os.ReadFile("../../db/db_agent.go")
	if err != nil {
		t.Fatalf("failed to read db_agent.go: %v", err)
	}
	content := string(src)

	if !strings.Contains(content, "GetAgentByVaultName") {
		t.Error("DB must provide GetAgentByVaultName method for v2 resolve")
	}
	// Must filter out archived and deleted agents.
	if !strings.Contains(content, "archived_at IS NULL") {
		t.Error("GetAgentByVaultName must filter out archived agents")
	}
	if !strings.Contains(content, "deleted_at IS NULL") {
		t.Error("GetAgentByVaultName must filter out deleted agents")
	}
}

// ── Source analysis: models.go — TokenRef v2 fields ─────────────────────────

func TestSource_TokenRef_V2PathFields(t *testing.T) {
	src, err := os.ReadFile("../../db/models.go")
	if err != nil {
		t.Fatalf("failed to read models.go: %v", err)
	}
	content := string(src)

	fields := []struct {
		name   string
		column string
	}{
		{"RefVault", "ref_vault"},
		{"RefGroup", "ref_group"},
		{"RefKey", "ref_key"},
		{"RefPath", "ref_path"},
	}
	for _, f := range fields {
		if !strings.Contains(content, f.name) {
			t.Errorf("TokenRef must have %s field for v2 path-based references", f.name)
		}
		if !strings.Contains(content, f.column) {
			t.Errorf("TokenRef.%s must map to column %s", f.name, f.column)
		}
	}
}

func TestSource_TokenRef_V2FieldsHaveDefaults(t *testing.T) {
	src, err := os.ReadFile("../../db/models.go")
	if err != nil {
		t.Fatalf("failed to read models.go: %v", err)
	}
	content := string(src)

	// v2 fields must default to empty string for backward compatibility with v1 refs.
	for _, field := range []string{"ref_vault", "ref_group", "ref_key", "ref_path"} {
		// Check that the field line contains default:''
		lines := strings.Split(content, "\n")
		found := false
		for _, line := range lines {
			if strings.Contains(line, field) && strings.Contains(line, "default:''") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("TokenRef column %s must have default:'' for backward compatibility", field)
		}
	}
}

// ── Source analysis: hkm_agent_common.go — agent validation ─────────────────

func TestSource_ValidateAgentAvailability_BlockedReturns423(t *testing.T) {
	src, err := os.ReadFile("hkm_agent_common.go")
	if err != nil {
		t.Fatalf("failed to read hkm_agent_common.go: %v", err)
	}
	content := string(src)

	if !strings.Contains(content, "http.StatusLocked") {
		t.Error("validateAgentAvailability must return 423 Locked for blocked agents")
	}
	if !strings.Contains(content, "agent is blocked") {
		t.Error("validateAgentAvailability must describe blocked state in error message")
	}
}

func TestSource_ValidateAgentAvailability_RebindReturns409(t *testing.T) {
	src, err := os.ReadFile("hkm_agent_common.go")
	if err != nil {
		t.Fatalf("failed to read hkm_agent_common.go: %v", err)
	}
	content := string(src)

	if !strings.Contains(content, "http.StatusConflict") {
		t.Error("validateAgentAvailability must return 409 Conflict for rebind-required agents")
	}
	if !strings.Contains(content, "agent requires human-approved rebind") {
		t.Error("validateAgentAvailability must describe rebind requirement in error message")
	}
}

// ── Unit tests: validateAgentAvailability ───────────────────────────────────

func TestValidateAgentAvailability_OK(t *testing.T) {
	agent := &db.Agent{}
	if err := validateAgentAvailability(agent); err != nil {
		t.Errorf("expected nil error for healthy agent, got: %v", err)
	}
}

func TestValidateAgentAvailability_Blocked(t *testing.T) {
	now := time.Now()
	agent := &db.Agent{BlockedAt: &now}
	err := validateAgentAvailability(agent)
	if err == nil {
		t.Fatal("expected error for blocked agent")
	}
	stateErr, ok := err.(*agentStateError)
	if !ok {
		t.Fatalf("expected *agentStateError, got %T", err)
	}
	if stateErr.statusCode != 423 {
		t.Errorf("expected status 423, got %d", stateErr.statusCode)
	}
}

func TestValidateAgentAvailability_RebindRequired(t *testing.T) {
	agent := &db.Agent{RebindRequired: true}
	err := validateAgentAvailability(agent)
	if err == nil {
		t.Fatal("expected error for rebind-required agent")
	}
	stateErr, ok := err.(*agentStateError)
	if !ok {
		t.Fatalf("expected *agentStateError, got %T", err)
	}
	if stateErr.statusCode != 409 {
		t.Errorf("expected status 409, got %d", stateErr.statusCode)
	}
}
