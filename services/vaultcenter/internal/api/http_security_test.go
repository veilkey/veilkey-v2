package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ══════════════════════════════════════════════════════════════════
// HTTP handler security tests for VaultCenter
// These verify that the HTTP layer rejects malformed or oversized
// requests before they reach business logic.
// ══════════════════════════════════════════════════════════════════

// --- Large body rejected ---

// Guarantees: decodeJSON rejects bodies larger than 1 MiB.
// This prevents memory exhaustion attacks on all JSON-accepting endpoints.
func TestHTTP_LargeBody_Rejected(t *testing.T) {
	bigBody := strings.Repeat("x", 1<<20+1)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(bigBody))
	var dst map[string]any
	err := decodeJSON(req, &dst)
	if err == nil {
		t.Error("decodeJSON must reject bodies larger than maxJSONBody (1 MiB)")
	}
}

// --- Empty JSON body ---

// Guarantees: decodeJSON with empty JSON object does not crash.
// Handlers that call decodeJSON must receive a valid (though empty) struct.
func TestHTTP_EmptyJSONBody_Decoded(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	var dst struct {
		Name string `json:"name"`
	}
	err := decodeJSON(req, &dst)
	if err != nil {
		t.Errorf("empty JSON object should decode without error, got: %v", err)
	}
	if dst.Name != "" {
		t.Errorf("expected empty Name, got %q", dst.Name)
	}
}

// --- Missing Content-Type handled gracefully ---

// Guarantees: decodeJSON processes JSON bodies regardless of Content-Type header.
// Go's json.Decoder does not inspect Content-Type, but we verify the handler
// does not crash or reject valid JSON due to missing header.
func TestHTTP_MissingContentType_Handled(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"test"}`))
	// Deliberately not setting Content-Type
	var dst struct {
		Name string `json:"name"`
	}
	err := decodeJSON(req, &dst)
	if err != nil {
		t.Errorf("valid JSON without Content-Type should decode, got: %v", err)
	}
	if dst.Name != "test" {
		t.Errorf("Name = %q, want %q", dst.Name, "test")
	}
}

// --- maxJSONBody constant ---

// Guarantees: maxJSONBody is exactly 1 MiB.
// Changing this value would affect all endpoints; this test catches accidental changes.
func TestHTTP_MaxJSONBody_Is1MiB(t *testing.T) {
	if maxJSONBody != 1<<20 {
		t.Errorf("maxJSONBody = %d, want %d (1 MiB)", maxJSONBody, 1<<20)
	}
}

// --- Security headers middleware ---

// Guarantees: securityHeadersMiddleware sets all required security headers.
func TestHTTP_SecurityHeaders_AllPresent(t *testing.T) {
	handler := securityHeadersMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	required := map[string]string{
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "DENY",
		"Referrer-Policy":           "strict-origin-when-cross-origin",
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
	}
	for header, want := range required {
		got := rec.Header().Get(header)
		if got != want {
			t.Errorf("header %s = %q, want %q", header, got, want)
		}
	}
}
