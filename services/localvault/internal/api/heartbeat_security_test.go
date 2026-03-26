package api

import (
	"os"
	"strings"
	"testing"
)

// ══════════════════════════════════════════════════════════════════
// Security tests: heartbeat agent_secret request + thread-safety
// ══════════════════════════════════════════════════════════════════

func TestSource_Heartbeat_SendsNeedsAgentSecretFlag(t *testing.T) {
	src, err := os.ReadFile("heartbeat.go")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	c := string(src)

	if !strings.Contains(c, "needs_agent_secret") {
		t.Error("heartbeat payload must include needs_agent_secret flag")
	}
	if !strings.Contains(c, "ReadAgentSecretFile") {
		t.Error("needs_agent_secret must be determined by ReadAgentSecretFile()")
	}
}

func TestSource_Heartbeat_ParamsProtectedByMutex(t *testing.T) {
	// heartbeat.go: write must be locked
	src, err := os.ReadFile("heartbeat.go")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	c := string(src)

	if !strings.Contains(c, "heartbeatMu.Lock()") {
		t.Error("heartbeat param write must be protected by heartbeatMu.Lock()")
	}
	if !strings.Contains(c, "heartbeatMu.Unlock()") {
		t.Error("heartbeat param write must call heartbeatMu.Unlock()")
	}

	// api.go: read must be locked
	apiSrc, err := os.ReadFile("api.go")
	if err != nil {
		t.Fatalf("read api.go: %v", err)
	}
	ac := string(apiSrc)

	if !strings.Contains(ac, "heartbeatMu.RLock()") {
		t.Error("heartbeat param read in post-unlock must be protected by heartbeatMu.RLock()")
	}
}

func TestSource_PostUnlockHeartbeat_Exists(t *testing.T) {
	src, err := os.ReadFile("api.go")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	c := string(src)

	if !strings.Contains(c, "Post-unlock heartbeat") {
		t.Error("handleUnlock must trigger post-unlock heartbeat")
	}
	if !strings.Contains(c, "SendHeartbeatOnce") {
		t.Error("post-unlock must call SendHeartbeatOnce")
	}
}

func TestSource_HeartbeatMu_DeclaredOnServer(t *testing.T) {
	src, err := os.ReadFile("api.go")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	c := string(src)

	if !strings.Contains(c, "heartbeatMu") || !strings.Contains(c, "sync.RWMutex") {
		t.Error("Server struct must declare heartbeatMu sync.RWMutex")
	}
}
