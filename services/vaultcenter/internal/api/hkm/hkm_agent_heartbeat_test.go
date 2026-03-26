package hkm

import (
	"os"
	"strings"
	"testing"
)


// ══════════════════════════════════════════════════════════════════
// Security tests: agent_secret exposure prevention
// ══════════════════════════════════════════════════════════════════

func TestSource_Heartbeat_AgentSecretOnlyOnRequest(t *testing.T) {
	src, err := os.ReadFile("hkm_agent_heartbeat.go")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	c := string(src)

	// SECURITY: agent_secret must only be sent when LV requests it
	if !strings.Contains(c, "NeedsAgentSecret") {
		t.Error("heartbeat must check NeedsAgentSecret flag before sending agent_secret")
	}
	if !strings.Contains(c, `json:"needs_agent_secret`) {
		t.Error("heartbeat request struct must have needs_agent_secret field")
	}

	// The "always include" pattern must NOT exist
	if strings.Contains(c, "Always include existing agent_secret") {
		t.Error("SECURITY: agent_secret must NOT be always included in heartbeat — only when needs_agent_secret=true")
	}
}

func TestSource_Heartbeat_AgentSecretReissueLogged(t *testing.T) {
	src, err := os.ReadFile("hkm_agent_heartbeat.go")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	c := string(src)

	// Re-issue must be logged
	if !strings.Contains(c, "undecryptable") || !strings.Contains(c, "re-issu") {
		t.Error("agent_secret re-issue on decrypt failure must be logged")
	}
	// Re-send on request must be logged
	if !strings.Contains(c, "re-sent agent_secret") {
		t.Error("agent_secret re-send on LV request must be logged")
	}
}

func TestSource_Heartbeat_NeverSendSecretUnconditionally(t *testing.T) {
	src, err := os.ReadFile("hkm_agent_heartbeat.go")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	lines := strings.Split(string(src), "\n")

	// Find all lines that set resp["agent_secret"]
	for i, line := range lines {
		if strings.Contains(line, `resp["agent_secret"]`) {
			// Each occurrence must be inside a conditional block
			// Check that a preceding line has an if/else condition
			context := ""
			for j := max(0, i-5); j < i; j++ {
				context += lines[j] + "\n"
			}
			if !strings.Contains(context, "if ") && !strings.Contains(context, "} else") {
				t.Errorf("line %d: resp[\"agent_secret\"] set without conditional guard — potential unconditional exposure", i+1)
			}
		}
	}
}
