package api

import (
	"os"
	"strings"
	"testing"
)

// ══════════════════════════════════════════════════════════════════
// LocalVault: unlock endpoint body size limit
// ══════════════════════════════════════════════════════════════════

func TestLocalVaultUnlockHasMaxBytesReader(t *testing.T) {
	src, err := os.ReadFile("api.go")
	if err != nil {
		t.Fatalf("failed to read api.go: %v", err)
	}
	code := string(src)

	idx := strings.Index(code, "func (s *Server) handleUnlock(")
	if idx < 0 {
		t.Fatal("handleUnlock function must exist")
	}
	rest := code[idx:]
	nextFunc := strings.Index(rest[1:], "\nfunc ")
	if nextFunc < 0 {
		nextFunc = len(rest) - 1
	}
	body := rest[:nextFunc+1]

	if !strings.Contains(body, "MaxBytesReader") {
		t.Error("LocalVault handleUnlock must use http.MaxBytesReader to limit request body size")
	}
}

// ══════════════════════════════════════════════════════════════════
// LocalVault: requireTrustedIP must use net.SplitHostPort for IPv6
// ══════════════════════════════════════════════════════════════════

func TestLocalVaultTrustedIPUsesNetSplitHostPort(t *testing.T) {
	src, err := os.ReadFile("api.go")
	if err != nil {
		t.Fatalf("failed to read api.go: %v", err)
	}
	code := string(src)

	idx := strings.Index(code, "func (s *Server) requireTrustedIP(")
	if idx < 0 {
		t.Fatal("requireTrustedIP function must exist")
	}
	rest := code[idx:]
	nextFunc := strings.Index(rest[1:], "\nfunc ")
	if nextFunc < 0 {
		nextFunc = len(rest) - 1
	}
	body := rest[:nextFunc+1]

	// Must use net.SplitHostPort, not strings.Split for IP parsing
	if strings.Contains(body, `strings.Split(r.RemoteAddr, ":")`) {
		t.Error("requireTrustedIP must use net.SplitHostPort instead of strings.Split — IPv6 addresses like [::1]:8080 break with Split")
	}
}

// ══════════════════════════════════════════════════════════════════
// LocalVault: agent secret bypass — locked state must not pass through
// requireAgentSecret when server is locked should block, not pass
// ══════════════════════════════════════════════════════════════════

func TestAgentSecretNotBypassedWhenLocked(t *testing.T) {
	src, err := os.ReadFile("api.go")
	if err != nil {
		t.Fatalf("failed to read api.go: %v", err)
	}
	code := string(src)

	idx := strings.Index(code, "func (s *Server) requireAgentSecret(")
	if idx < 0 {
		t.Fatal("requireAgentSecret function must exist")
	}
	rest := code[idx:]
	nextFunc := strings.Index(rest[1:], "\nfunc ")
	if nextFunc < 0 {
		nextFunc = len(rest) - 1
	}
	body := rest[:nextFunc+1]

	// When locked, should NOT pass through — should return 503
	if strings.Contains(body, "s.IsLocked()") {
		// Check that it blocks (returns error), not passes through
		lockedIdx := strings.Index(body, "s.IsLocked()")
		if lockedIdx >= 0 {
			afterLocked := body[lockedIdx:lockedIdx+200]
			if strings.Contains(afterLocked, "next(w, r)") && !strings.Contains(afterLocked, "respondError") {
				t.Error("requireAgentSecret must NOT pass through when server is locked — should return 503")
			}
		}
	}
}

// ══════════════════════════════════════════════════════════════════
// LocalVault: unlock password max length
// ══════════════════════════════════════════════════════════════════

func TestLocalVaultUnlockPasswordMaxLength(t *testing.T) {
	src, err := os.ReadFile("api.go")
	if err != nil {
		t.Fatalf("failed to read api.go: %v", err)
	}
	code := string(src)

	idx := strings.Index(code, "func (s *Server) handleUnlock(")
	if idx < 0 {
		t.Fatal("handleUnlock function must exist")
	}
	rest := code[idx:]
	nextFunc := strings.Index(rest[1:], "\nfunc ")
	if nextFunc < 0 {
		nextFunc = len(rest) - 1
	}
	body := rest[:nextFunc+1]

	if !strings.Contains(body, "len(req.Password) >") && !strings.Contains(body, "len(req.Password)>") {
		t.Error("LocalVault handleUnlock must enforce maximum password length")
	}
}

// ══════════════════════════════════════════════════════════════════
// LocalVault: HSTS header
// ══════════════════════════════════════════════════════════════════

func TestLocalVaultHSTSHeader(t *testing.T) {
	src, err := os.ReadFile("api.go")
	if err != nil {
		t.Fatalf("failed to read api.go: %v", err)
	}
	code := string(src)

	idx := strings.Index(code, "func securityHeadersMiddleware(")
	if idx < 0 {
		t.Fatal("securityHeadersMiddleware must exist in LocalVault")
	}
	rest := code[idx:]
	nextFunc := strings.Index(rest[1:], "\nfunc ")
	if nextFunc < 0 {
		nextFunc = len(rest) - 1
	}
	body := rest[:nextFunc+1]

	if !strings.Contains(body, "Strict-Transport-Security") {
		t.Error("LocalVault must set Strict-Transport-Security (HSTS) header")
	}
}

// ══════════════════════════════════════════════════════════════════
// LocalVault: /api/reencrypt must require trusted IP
// ══════════════════════════════════════════════════════════════════

func TestReencryptRequiresTrustedIP(t *testing.T) {
	src, err := os.ReadFile("api.go")
	if err != nil {
		t.Fatalf("failed to read api.go: %v", err)
	}
	code := string(src)

	line := ""
	for _, l := range strings.Split(code, "\n") {
		if strings.Contains(l, "/api/reencrypt") {
			line = l
			break
		}
	}
	if line == "" {
		t.Fatal("/api/reencrypt route must exist")
	}
	if !strings.Contains(line, "requireTrustedIP") {
		t.Error("/api/reencrypt must be behind requireTrustedIP — critical crypto operation")
	}
}

// ══════════════════════════════════════════════════════════════════
// LocalVault: GET /api/configs must require auth
// ══════════════════════════════════════════════════════════════════

func TestLocalVaultConfigsRequireAuth(t *testing.T) {
	src, err := os.ReadFile("configs/handler.go")
	if err != nil {
		t.Fatalf("failed to read configs/handler.go: %v", err)
	}
	code := string(src)

	// GET /api/configs must be wrapped with trusted() or similar middleware
	for _, l := range strings.Split(code, "\n") {
		if strings.Contains(l, `"GET /api/configs"`) && !strings.Contains(l, "{key}") {
			// Must NOT be a bare handler — must be wrapped (e.g., trusted(h.handleListConfigs))
			if strings.Contains(l, "h.handleListConfigs)") && !strings.Contains(l, "trusted(") {
				t.Error("GET /api/configs must require auth middleware (trusted/requireTrustedIP)")
			}
			return
		}
	}
}
