package api

import (
	"os"
	"strings"
	"testing"
)

// ══════════════════════════════════════════════════════════════════
// #2 HIGH: JSON request body size limit
// decodeJSON must use http.MaxBytesReader to prevent DoS
// ══════════════════════════════════════════════════════════════════

func TestDecodeJSONHasMaxBytesReader(t *testing.T) {
	src, err := os.ReadFile("api.go")
	if err != nil {
		t.Fatalf("failed to read api.go: %v", err)
	}
	code := string(src)

	// decodeJSON must apply MaxBytesReader before decoding
	idx := strings.Index(code, "func decodeJSON(")
	if idx < 0 {
		t.Fatal("decodeJSON function must exist")
	}
	// Find the function body (up to next top-level func)
	rest := code[idx:]
	nextFunc := strings.Index(rest[1:], "\nfunc ")
	if nextFunc < 0 {
		nextFunc = len(rest) - 1
	}
	body := rest[:nextFunc+1]

	if !strings.Contains(body, "MaxBytesReader") {
		t.Error("decodeJSON must use http.MaxBytesReader to limit request body size (DoS prevention)")
	}
}

// ══════════════════════════════════════════════════════════════════
// #3 HIGH: Trusted IP — X-Forwarded-For loopback spoof prevention
// remoteIP must reject loopback addresses from forwarded headers
// ══════════════════════════════════════════════════════════════════

func TestRemoteIPRejectsLoopbackFromForwardedHeaders(t *testing.T) {
	src, err := os.ReadFile("handle_admin_auth.go")
	if err != nil {
		t.Fatalf("failed to read handle_admin_auth.go: %v", err)
	}
	code := string(src)

	idx := strings.Index(code, "func remoteIP(")
	if idx < 0 {
		t.Fatal("remoteIP function must exist")
	}
	rest := code[idx:]
	nextFunc := strings.Index(rest[1:], "\nfunc ")
	if nextFunc < 0 {
		nextFunc = len(rest) - 1
	}
	body := rest[:nextFunc+1]

	// Must validate that forwarded IP is not loopback
	if !strings.Contains(body, "isPrivateIP") && !strings.Contains(body, "IsLoopback") {
		t.Error("remoteIP must validate forwarded headers — check for loopback spoofing")
	}

	// Must reject loopback from X-Real-IP / X-Forwarded-For
	if !strings.Contains(body, "IsLoopback") {
		t.Error("remoteIP must reject loopback addresses (127.0.0.0/8, ::1) from forwarded headers")
	}
}

// ══════════════════════════════════════════════════════════════════
// #4 HIGH: /api/admin/check must require authentication
// ══════════════════════════════════════════════════════════════════

func TestAdminCheckEndpointRequiresAuth(t *testing.T) {
	src, err := os.ReadFile("handlers.go")
	if err != nil {
		t.Fatalf("failed to read handlers.go: %v", err)
	}
	code := string(src)

	// Find the admin/check route registration
	if !strings.Contains(code, "/api/admin/check") {
		t.Fatal("/api/admin/check route must exist")
	}

	// Must have requireTrustedIP or requireAdminAuth
	line := ""
	for _, l := range strings.Split(code, "\n") {
		if strings.Contains(l, "/api/admin/check") {
			line = l
			break
		}
	}
	if line == "" {
		t.Fatal("could not find /api/admin/check route line")
	}

	if !strings.Contains(line, "requireTrustedIP") {
		t.Error("/api/admin/check must be behind requireTrustedIP to prevent unauthenticated state disclosure")
	}
}

// ══════════════════════════════════════════════════════════════════
// #6 MEDIUM: Password max length validation
// Must enforce maximum length to prevent bcrypt DoS
// ══════════════════════════════════════════════════════════════════

func TestAdminPasswordHasMaxLength(t *testing.T) {
	src, err := os.ReadFile("handle_admin_auth.go")
	if err != nil {
		t.Fatalf("failed to read handle_admin_auth.go: %v", err)
	}
	code := string(src)

	// handleAdminSetup must enforce max password length
	if !strings.Contains(code, "len(req.AdminPassword) >") && !strings.Contains(code, "len(req.AdminPassword)>") {
		t.Error("handleAdminSetup must enforce maximum password length to prevent bcrypt DoS")
	}
}

func TestUnlockPasswordHasMaxLength(t *testing.T) {
	src, err := os.ReadFile("api.go")
	if err != nil {
		t.Fatalf("failed to read api.go: %v", err)
	}
	code := string(src)

	// handleUnlock must enforce max password length
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
		t.Error("handleUnlock must enforce maximum password length")
	}
}

// ══════════════════════════════════════════════════════════════════
// #9 MEDIUM: Registration token validation rate limiting
// ══════════════════════════════════════════════════════════════════

func TestRegistrationTokenValidateHasRateLimit(t *testing.T) {
	src, err := os.ReadFile("handlers.go")
	if err != nil {
		t.Fatalf("failed to read handlers.go: %v", err)
	}
	code := string(src)

	// Find the token validate route
	line := ""
	for _, l := range strings.Split(code, "\n") {
		if strings.Contains(l, "registration-tokens") && strings.Contains(l, "validate") {
			line = l
			break
		}
	}
	if line == "" {
		t.Fatal("registration token validate route must exist")
	}

	if !strings.Contains(line, "requireTrustedIP") {
		t.Error("registration token validate must be behind requireTrustedIP to prevent enumeration")
	}
}

// ══════════════════════════════════════════════════════════════════
// #11 LOW: Session timeout consistency
// ══════════════════════════════════════════════════════════════════

func TestSessionTimeoutsConsistent(t *testing.T) {
	authSrc, err := os.ReadFile("handle_admin_auth.go")
	if err != nil {
		t.Fatalf("failed to read handle_admin_auth.go: %v", err)
	}

	adminSrc, err := os.ReadFile("admin/admin_auth.go")
	if err != nil {
		t.Fatalf("failed to read admin/admin_auth.go: %v", err)
	}

	// Both files must use the same env-var-based durations, not different hardcoded defaults
	authCode := string(authSrc)
	adminCode := string(adminSrc)

	// Both must read session durations from env vars (not hardcoded-only)
	authUsesEnv := strings.Contains(authCode, "ParseDurationEnv") || strings.Contains(authCode, "envDuration")
	adminUsesEnv := strings.Contains(adminCode, "ParseDurationEnv") || strings.Contains(adminCode, "envDuration")

	if authUsesEnv && !adminUsesEnv {
		t.Error("session timeout: handle_admin_auth uses env vars but admin_auth uses hardcoded defaults — must be consistent")
	}

	// Default values must match between the two files
	// handle_admin_auth: 8*time.Hour, 1*time.Hour
	// admin_auth: must match
	if strings.Contains(adminCode, "2 * time.Hour") && strings.Contains(authCode, "8*time.Hour") {
		t.Error("session timeout defaults differ: admin_auth=2h vs handle_admin_auth=8h")
	}
}

// ══════════════════════════════════════════════════════════════════
// HSTS header — required for public-facing TLS service
// ══════════════════════════════════════════════════════════════════

func TestSecurityHeadersIncludeHSTS(t *testing.T) {
	src, err := os.ReadFile("api.go")
	if err != nil {
		t.Fatalf("failed to read api.go: %v", err)
	}
	code := string(src)

	idx := strings.Index(code, "func securityHeadersMiddleware(")
	if idx < 0 {
		t.Fatal("securityHeadersMiddleware function must exist")
	}
	rest := code[idx:]
	nextFunc := strings.Index(rest[1:], "\nfunc ")
	if nextFunc < 0 {
		nextFunc = len(rest) - 1
	}
	body := rest[:nextFunc+1]

	if !strings.Contains(body, "Strict-Transport-Security") {
		t.Error("securityHeadersMiddleware must set Strict-Transport-Security (HSTS) header")
	}
}

// ══════════════════════════════════════════════════════════════════
// /api/chain/info must require trusted IP
// Exposes genesis.json + persistent_peers (network topology)
// ══════════════════════════════════════════════════════════════════

func TestChainInfoRequiresTrustedIP(t *testing.T) {
	src, err := os.ReadFile("api.go")
	if err != nil {
		t.Fatalf("failed to read api.go: %v", err)
	}
	code := string(src)

	line := ""
	for _, l := range strings.Split(code, "\n") {
		if strings.Contains(l, "/api/chain/info") {
			line = l
			break
		}
	}
	if line == "" {
		t.Fatal("/api/chain/info route must exist")
	}
	if !strings.Contains(line, "requireTrustedIP") {
		t.Error("/api/chain/info must be behind requireTrustedIP — exposes genesis.json and peer topology")
	}
}

// ══════════════════════════════════════════════════════════════════
// /api/admin/setup must require trusted IP
// Sets initial admin password — must not be remotely accessible
// ══════════════════════════════════════════════════════════════════

func TestAdminSetupRequiresTrustedIP(t *testing.T) {
	src, err := os.ReadFile("handlers.go")
	if err != nil {
		t.Fatalf("failed to read handlers.go: %v", err)
	}
	code := string(src)

	line := ""
	for _, l := range strings.Split(code, "\n") {
		if strings.Contains(l, "/api/admin/setup") {
			line = l
			break
		}
	}
	if line == "" {
		t.Fatal("/api/admin/setup route must exist")
	}
	if !strings.Contains(line, "requireTrustedIP") {
		t.Error("/api/admin/setup must be behind requireTrustedIP — sets initial admin password")
	}
}
