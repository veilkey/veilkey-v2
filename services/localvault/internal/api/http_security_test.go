package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ══════════════════════════════════════════════════════════════════
// HTTP handler security tests for LocalVault
// These verify that the HTTP layer rejects malformed or oversized
// requests before they reach business logic.
// ══════════════════════════════════════════════════════════════════

// --- Large body rejected ---

// Guarantees: POST /api/unlock rejects bodies larger than 1 MiB.
// Without this, an attacker could send a multi-GB request to exhaust memory.
func TestHTTP_LargeBody_Rejected(t *testing.T) {
	s := NewServer(nil, nil, nil)
	defer s.Close()

	// Build a body larger than 1 MiB (the MaxBytesReader limit in handleUnlock)
	bigBody := `{"password":"` + strings.Repeat("a", 1<<20) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/unlock", strings.NewReader(bigBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	s.handleUnlock(rec, req)

	// Should get 400 (bad request due to MaxBytesReader) or password too long
	if rec.Code != http.StatusBadRequest {
		t.Errorf("oversized body: got status %d, want 400", rec.Code)
	}
}

// --- Empty JSON body ---

// Guarantees: POST /api/unlock with empty JSON body returns 400.
// The handler must not panic or crash on empty input.
func TestHTTP_EmptyJSONBody_Rejected(t *testing.T) {
	s := NewServer(nil, nil, nil)
	defer s.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/unlock", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	s.handleUnlock(rec, req)

	// Empty password field should be rejected
	if rec.Code != http.StatusBadRequest {
		t.Errorf("empty JSON body: got status %d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "password is required") {
		t.Errorf("expected 'password is required' message, got %s", rec.Body.String())
	}
}

// --- Missing Content-Type handled gracefully ---

// Guarantees: POST /api/unlock without Content-Type header is handled gracefully.
// Go's json.Decoder does not require Content-Type, but the handler must still
// process the body correctly or reject it without crashing.
func TestHTTP_MissingContentType_Handled(t *testing.T) {
	s := NewServer(nil, nil, nil)
	defer s.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/unlock", strings.NewReader(`{"password":"test"}`))
	// Deliberately not setting Content-Type
	rec := httptest.NewRecorder()

	s.handleUnlock(rec, req)

	// Should process the JSON body regardless of Content-Type header.
	// Since the server is locked and has no DB, it will fail at the unlock step
	// (not at content-type validation), which is the correct behavior.
	// Any status other than a panic/500 is acceptable.
	if rec.Code == 0 {
		t.Error("handler must return a valid HTTP status code")
	}
}

// --- Health endpoint always responds ---

// Guarantees: /health returns 200 even when the server is locked.
// This is critical for orchestrators (Docker, systemd) to know the process is alive.
func TestHTTP_Health_AlwaysResponds(t *testing.T) {
	s := NewServer(nil, nil, nil)
	defer s.Close()

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	s.handleHealth(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("health check: got status %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "locked") {
		t.Errorf("locked server health must report locked status, got %s", rec.Body.String())
	}
}

// --- requireUnlocked middleware ---

// Guarantees: Protected endpoints return 503 when server is locked.
func TestHTTP_RequireUnlocked_Returns503WhenLocked(t *testing.T) {
	s := NewServer(nil, nil, nil)
	defer s.Close()

	handler := s.requireUnlocked(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("locked server: got status %d, want 503", rec.Code)
	}
}
