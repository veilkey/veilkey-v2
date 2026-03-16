package api

import (
	"strings"
	"testing"
)

func TestVaultAuditRouteIncludesNonVaultEntityTypes(t *testing.T) {
	srv, handler := setupTestServer(t)
	_, agentHash := registerMockAgent(t, srv, "audit-test", nil, nil)

	srv.saveAuditEvent("secret", "VK:LOCAL:testref", "resolve", "api", agentHash, "", "resolve", nil, map[string]any{"ref": "VK:LOCAL:testref"})

	w := getJSON(handler, "/api/vaults/"+agentHash+"/audit")
	body := w.Body.String()
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, body)
	}
	if !strings.Contains(body, "resolve") {
		t.Fatalf("expected vault audit to include secret resolve event, got: %s", body)
	}
}
