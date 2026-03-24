package api

import (
	"os"
	"strings"
	"testing"
)

func extractFn(code, sig string) string {
	i := strings.Index(code, sig)
	if i < 0 {
		return ""
	}
	r := code[i:]
	n := strings.Index(r[1:], "\nfunc ")
	if n < 0 {
		return r
	}
	return r[:n+1]
}

func routeLine(code, path string) string {
	for _, l := range strings.Split(code, "\n") {
		if strings.Contains(l, path) && strings.Contains(l, "HandleFunc") {
			return l
		}
	}
	return ""
}

func TestDecodeJSONMaxBytes(t *testing.T) {
	s, _ := os.ReadFile("api.go")
	if !strings.Contains(extractFn(string(s), "func decodeJSON("), "MaxBytesReader") {
		t.Error("decodeJSON must use MaxBytesReader")
	}
}

func TestRemoteIPLoopback(t *testing.T) {
	s, _ := os.ReadFile("handle_admin_auth.go")
	if !strings.Contains(extractFn(string(s), "func remoteIP("), "IsLoopback") {
		t.Error("remoteIP must reject loopback from forwarded headers")
	}
}

func TestAdminCheckAuth(t *testing.T) {
	s, _ := os.ReadFile("handlers.go")
	if l := routeLine(string(s), "/api/admin/check"); !strings.Contains(l, "requireTrustedIP") {
		t.Error("/api/admin/check needs requireTrustedIP")
	}
}

func TestAdminSetupAuth(t *testing.T) {
	s, _ := os.ReadFile("handlers.go")
	if l := routeLine(string(s), "/api/admin/setup"); !strings.Contains(l, "requireTrustedIP") {
		t.Error("/api/admin/setup needs requireTrustedIP")
	}
}

func TestChainInfoAuth(t *testing.T) {
	s, _ := os.ReadFile("api.go")
	if l := routeLine(string(s), "/api/chain/info"); !strings.Contains(l, "requireTrustedIP") {
		t.Error("/api/chain/info needs requireTrustedIP")
	}
}

func TestTokenValidateAuth(t *testing.T) {
	s, _ := os.ReadFile("handlers.go")
	for _, l := range strings.Split(string(s), "\n") {
		if strings.Contains(l, "validate") && strings.Contains(l, "registration-tokens") {
			if !strings.Contains(l, "requireTrustedIP") {
				t.Error("token validate needs requireTrustedIP")
			}
			return
		}
	}
	t.Fatal("token validate route not found")
}

func TestHeartbeatAuth(t *testing.T) {
	s, _ := os.ReadFile("hkm/handler.go")
	if l := routeLine(string(s), "/api/agents/heartbeat"); !strings.Contains(l, "trusted(") {
		t.Error("/api/agents/heartbeat needs trusted() wrapper")
	}
}

func TestPasswordMaxLen(t *testing.T) {
	s, _ := os.ReadFile("handle_admin_auth.go")
	if !strings.Contains(string(s), "len(req.AdminPassword) > ") {
		t.Error("admin password needs max length check")
	}
}

func TestUnlockMaxLen(t *testing.T) {
	s, _ := os.ReadFile("api.go")
	if !strings.Contains(extractFn(string(s), "func (s *Server) handleUnlock("), "len(req.Password) >") {
		t.Error("unlock password needs max length check")
	}
}

func TestHSTS(t *testing.T) {
	s, _ := os.ReadFile("api.go")
	if !strings.Contains(extractFn(string(s), "func securityHeadersMiddleware("), "Strict-Transport-Security") {
		t.Error("missing HSTS header")
	}
}

func TestSessionDefaults(t *testing.T) {
	s, _ := os.ReadFile("admin/admin_auth.go")
	if strings.Contains(string(s), "2 * time.Hour") {
		t.Error("session TTL default must be 8h not 2h")
	}
}

func TestSetupRoutesError(t *testing.T) {
	s, _ := os.ReadFile("api.go")
	if strings.Contains(string(s), "func (s *Server) SetupRoutes() http.Handler {") {
		t.Error("SetupRoutes must return (http.Handler, error)")
	}
}

func TestTokenGCModel(t *testing.T) {
	s, _ := os.ReadFile("../db/db_registration_token.go")
	if !strings.Contains(extractFn(string(s), "func (d *DB) DeleteExpiredRegistrationTokens("), "Model(") {
		t.Error("GC must use .Model()")
	}
}

func TestNoPanic(t *testing.T) {
	s, _ := os.ReadFile("static_assets.go")
	if strings.Contains(string(s), "panic(") {
		t.Error("static_assets must not panic")
	}
}
