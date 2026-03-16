package api

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestBulkApplyRoutesServeTemplateAndWorkflowLists(t *testing.T) {
	t.Setenv("VEILKEY_BULK_APPLY_DIR", t.TempDir())

	srv, handler := setupHKMServer(t)

	_, agentHash := registerMockAgent(t, srv, "bulk-apply-agent", map[string]string{
		"REPO_ORIGIN_URL": "https://gitlab.example/veilkey/services/veilkey.git",
	}, nil)

	enabled := true
	if _, err := srv.saveBulkApplyTemplateFile(agentHash, "", &bulkApplyTemplatePayload{
		Name:       "repo-origin-config",
		Format:     "raw",
		TargetPath: "/opt/.git/config",
		Body:       "url = {{ VE.REPO_ORIGIN_URL }}\n",
		Hook:       "reload_repo_origin",
		Enabled:    &enabled,
	}); err != nil {
		t.Fatalf("save bulk template: %v", err)
	}

	if err := srv.saveBulkApplyWorkflowFile(agentHash, &bulkApplyWorkflowFile{
		APIVersion:       "veilkey.io/v1",
		Kind:             bulkApplyWorkflowKind,
		Name:             "repo-origin-apply",
		VaultRuntimeHash: agentHash,
		Label:            "Repo Origin Apply",
		Steps: []bulkApplyWorkflowStepFile{
			{Template: "repo-origin-config"},
		},
	}); err != nil {
		t.Fatalf("save bulk workflow: %v", err)
	}

	for _, path := range []string{
		"/api/vaults/" + agentHash + "/bulk-apply/templates",
		"/api/vaults/" + agentHash + "/bulk-apply/workflows",
	} {
		w := getJSON(handler, path)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: expected 200, got %d: %s", path, w.Code, w.Body.String())
		}
		if !json.Valid(w.Body.Bytes()) {
			t.Fatalf("%s: expected valid json, got %q", path, w.Body.String())
		}
	}
}
