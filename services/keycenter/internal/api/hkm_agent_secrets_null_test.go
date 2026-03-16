package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHKM_AgentSecretsNormalizesNullAgentPayload(t *testing.T) {
	srv, handler := setupHKMServer(t)

	mockSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/secrets":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte("null"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer mockSrv.Close()

	registerMockAgentWithServer(t, srv, "null-secrets-agent", mockSrv)

	resp := getJSON(handler, "/api/agents/null-secrets-agent/secrets")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.Code, resp.Body.String())
	}

	var body struct {
		Vault   string        `json:"vault"`
		Count   int           `json:"count"`
		Secrets []interface{} `json:"secrets"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Vault != "null-secrets-agent" {
		t.Fatalf("vault = %q, want %q", body.Vault, "null-secrets-agent")
	}
	if body.Count != 0 {
		t.Fatalf("count = %d, want 0", body.Count)
	}
	if body.Secrets == nil {
		t.Fatalf("secrets should be an empty array, got nil")
	}
	if len(body.Secrets) != 0 {
		t.Fatalf("len(secrets) = %d, want 0", len(body.Secrets))
	}
}
