package hkm

import (
	"os"
	"strings"
	"testing"
)

// TestResolveAgentTrustedMiddleware verifies that handleAgentResolve
// is wrapped with the trusted() (requireTrustedIP) middleware, preventing
// untrusted IPs from calling the resolve-agent endpoint.
func TestResolveAgentTrustedMiddleware(t *testing.T) {
	src, err := os.ReadFile("handler.go")
	if err != nil {
		t.Fatal("cannot read handler.go:", err)
	}
	code := string(src)

	for i, line := range strings.Split(code, "\n") {
		if !strings.Contains(line, "resolve-agent") {
			continue
		}
		if !strings.Contains(line, "trusted(") {
			t.Fatalf("line %d: resolve-agent route must be wrapped with trusted() middleware: %s", i+1, strings.TrimSpace(line))
		}
		if !strings.Contains(line, "trusted(ready(") {
			t.Errorf("line %d: resolve-agent route should use trusted(ready(...)) pattern: %s", i+1, strings.TrimSpace(line))
		}
		return
	}
	t.Fatal("resolve-agent route not found in handler.go")
}

// TestAgentEndpointsTrustedConsistency verifies that all agent mutation/
// sensitive endpoints (except unlock-key which uses agentAuth) are
// protected by the trusted() middleware.
func TestAgentEndpointsTrustedConsistency(t *testing.T) {
	src, err := os.ReadFile("handler.go")
	if err != nil {
		t.Fatal("cannot read handler.go:", err)
	}

	// Endpoints that must have trusted() wrapping.
	requiredTrusted := []string{
		"resolve-agent",
		"heartbeat",
		"by-node",
		"rebind-plan",
		"rotate-all",
		"tracked-refs/cleanup",
		"tracked-refs/sync",
	}

	code := string(src)
	for _, endpoint := range requiredTrusted {
		found := false
		for i, line := range strings.Split(code, "\n") {
			if !strings.Contains(line, endpoint) || !strings.Contains(line, "HandleFunc") {
				continue
			}
			found = true
			if !strings.Contains(line, "trusted(") {
				t.Errorf("line %d: endpoint containing %q must be wrapped with trusted(): %s",
					i+1, endpoint, strings.TrimSpace(line))
			}
		}
		if !found {
			t.Errorf("endpoint containing %q not found in handler.go", endpoint)
		}
	}
}
