package hkm

import (
	"os"
	"strings"
	"testing"
)

// ══════════════════════════════════════════════════════════════════
// Domain-level tests for VaultCenter HKM handler layer
// These verify the critical agent management invariants:
// authentication, heartbeat registration, and rate limiting.
// ══════════════════════════════════════════════════════════════════

// --- Heartbeat: valid registration token ---

// Guarantees: Heartbeat accepts a registration_token field for new agent registration.
// Without this, new LocalVault nodes cannot join the cluster.
func TestSource_Heartbeat_AcceptsRegistrationToken(t *testing.T) {
	src, err := os.ReadFile("hkm_agent_heartbeat.go")
	if err != nil {
		t.Fatalf("failed to read hkm_agent_heartbeat.go: %v", err)
	}
	content := string(src)

	// Request struct must accept registration_token
	if !strings.Contains(content, `json:"registration_token"`) {
		t.Error("heartbeat request must accept registration_token field")
	}
	// On success, must return node identity info
	if !strings.Contains(content, `"status"`) {
		t.Error("heartbeat response must include status field")
	}
	if !strings.Contains(content, "StatusOK") || !strings.Contains(content, "200") {
		// Check for respondJSON with 200 or StatusOK
		if !strings.Contains(content, "http.StatusOK") {
			t.Error("heartbeat must return 200 on successful registration")
		}
	}
}

// --- Heartbeat: invalid token ---

// Guarantees: Heartbeat rejects invalid/expired registration tokens with 403.
// This prevents unauthorized nodes from joining the cluster.
func TestSource_Heartbeat_RejectsInvalidToken(t *testing.T) {
	src, err := os.ReadFile("hkm_agent_heartbeat.go")
	if err != nil {
		t.Fatalf("failed to read hkm_agent_heartbeat.go: %v", err)
	}
	content := string(src)

	if !strings.Contains(content, "ConsumeRegistrationToken") {
		t.Error("heartbeat must atomically consume registration token to prevent reuse")
	}
	if !strings.Contains(content, "StatusForbidden") {
		t.Error("heartbeat must return 403 for invalid/expired tokens")
	}
	if !strings.Contains(content, "invalid, expired, or already used registration token") {
		t.Error("heartbeat must provide clear error message for rejected tokens")
	}
}

// --- Heartbeat: vault_unlock_key not stored without auth ---

// Guarantees: On existing agents, vault_unlock_key injection requires agent auth.
// Without this check, any client that knows a node_id could inject a fake unlock key.
func TestSource_Heartbeat_VaultUnlockKeyRequiresAuth(t *testing.T) {
	src, err := os.ReadFile("hkm_agent_heartbeat.go")
	if err != nil {
		t.Fatalf("failed to read hkm_agent_heartbeat.go: %v", err)
	}
	content := string(src)

	// Must verify agent identity before storing vault_unlock_key on existing agents
	if !strings.Contains(content, "authenticateAgentBySecret") {
		t.Error("vault_unlock_key update on existing agent must verify agent_secret")
	}
	if !strings.Contains(content, "authedAgent.NodeID != nodeID") {
		t.Error("vault_unlock_key must verify the authenticated agent matches the requesting node")
	}
	if !strings.Contains(content, "rejected vault_unlock_key") {
		t.Error("must log rejection when auth fails for vault_unlock_key")
	}
}

// --- Agent unlock key: requires auth middleware ---

// Guarantees: The unlock-key endpoint requires agent authentication.
// Without this, any client could fetch vault passwords from VaultCenter.
func TestSource_AgentUnlockKey_RequiresAuth(t *testing.T) {
	src, err := os.ReadFile("handler.go")
	if err != nil {
		t.Fatalf("failed to read handler.go: %v", err)
	}
	content := string(src)

	// The route must be wrapped with agentAuth middleware
	for _, line := range strings.Split(content, "\n") {
		if strings.Contains(line, "agents/unlock-key") {
			if !strings.Contains(line, "agentAuth(") {
				t.Error("GET /api/agents/unlock-key must be wrapped with agentAuth middleware")
			}
			return
		}
	}
	t.Error("agents/unlock-key route not found in handler.go")
}

// Guarantees: handleAgentUnlockKey checks the context-injected auth key.
func TestSource_AgentUnlockKey_ChecksContextAuth(t *testing.T) {
	src, err := os.ReadFile("hkm_agent_unlock_key.go")
	if err != nil {
		t.Fatalf("failed to read hkm_agent_unlock_key.go: %v", err)
	}
	content := string(src)

	if !strings.Contains(content, "agentAuthKey") {
		t.Error("handleAgentUnlockKey must verify agent authentication from context")
	}
	if !strings.Contains(content, "StatusUnauthorized") {
		t.Error("handleAgentUnlockKey must return 401 when auth is missing")
	}
}

// --- Rate limiter ---

// Guarantees: The unlock-key rate limiter blocks the 6th request within 1 minute.
// This prevents brute-force attacks on the auto-unlock endpoint.
func TestCheckUnlockKeyRateLimit_BlocksSixthRequest(t *testing.T) {
	// Reset limiter state for this test
	unlockKeyLimiter.mu.Lock()
	delete(unlockKeyLimiter.windows, "test-agent-rate")
	unlockKeyLimiter.mu.Unlock()

	agentHash := "test-agent-rate"

	// First 5 requests should be allowed (limit is 5)
	for i := 1; i <= unlockKeyRateLimit; i++ {
		if !checkUnlockKeyRateLimit(agentHash) {
			t.Errorf("request %d should be allowed (limit=%d)", i, unlockKeyRateLimit)
		}
	}

	// 6th request should be blocked
	if checkUnlockKeyRateLimit(agentHash) {
		t.Errorf("request %d should be blocked (exceeds limit=%d per %v)", unlockKeyRateLimit+1, unlockKeyRateLimit, unlockKeyRateWindow)
	}

	// Cleanup
	unlockKeyLimiter.mu.Lock()
	delete(unlockKeyLimiter.windows, agentHash)
	unlockKeyLimiter.mu.Unlock()
}

// Guarantees: The rate limiter correctly reports the 429 status code.
func TestSource_AgentUnlockKey_RateLimiterReturns429(t *testing.T) {
	src, err := os.ReadFile("hkm_agent_unlock_key.go")
	if err != nil {
		t.Fatalf("failed to read hkm_agent_unlock_key.go: %v", err)
	}
	content := string(src)

	if !strings.Contains(content, "checkUnlockKeyRateLimit") {
		t.Error("handleAgentUnlockKey must call checkUnlockKeyRateLimit")
	}
	if !strings.Contains(content, "StatusTooManyRequests") {
		t.Error("rate-limited requests must return 429 Too Many Requests")
	}
	if !strings.Contains(content, "Retry-After") {
		t.Error("rate-limited responses must include Retry-After header")
	}
}

// Guarantees: Different agents have independent rate limit windows.
func TestCheckUnlockKeyRateLimit_IndependentPerAgent(t *testing.T) {
	agent1 := "test-agent-independent-1"
	agent2 := "test-agent-independent-2"

	// Cleanup
	unlockKeyLimiter.mu.Lock()
	delete(unlockKeyLimiter.windows, agent1)
	delete(unlockKeyLimiter.windows, agent2)
	unlockKeyLimiter.mu.Unlock()

	// Exhaust agent1's limit
	for i := 0; i < unlockKeyRateLimit; i++ {
		checkUnlockKeyRateLimit(agent1)
	}

	// agent2 should still be allowed
	if !checkUnlockKeyRateLimit(agent2) {
		t.Error("rate limit for one agent must not affect another agent")
	}

	// Cleanup
	unlockKeyLimiter.mu.Lock()
	delete(unlockKeyLimiter.windows, agent1)
	delete(unlockKeyLimiter.windows, agent2)
	unlockKeyLimiter.mu.Unlock()
}
