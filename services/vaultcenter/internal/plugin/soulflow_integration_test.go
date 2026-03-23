package plugin

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestSoulflowSyncPlugin(t *testing.T) {
	wasm, err := os.ReadFile("/root/jeonghan/repository/veilkey-plugins/soulflow-sync/soulflow-sync.wasm")
	if err != nil { t.Skipf("wasm not found: %v", err) }
	ctx := context.Background()
	inst, err := LoadInstance(ctx, wasm, HostFunctions{})
	if err != nil { t.Fatalf("load: %v", err) }
	defer func() { _ = inst.Close(ctx) }()

	t.Run("info", func(t *testing.T) {
		if inst.Info().Name != "soulflow-sync" { t.Errorf("name = %q", inst.Info().Name) }
	})

	t.Run("init_paths", func(t *testing.T) {
		r, _ := inst.Init(ctx, map[string]any{})
		if len(r.Paths) != 4 { t.Errorf("paths = %d, want 4", len(r.Paths)) }
		found := false
		for _, p := range r.Paths {
			if strings.Contains(p, ".credentials.json") { found = true }
		}
		if !found { t.Error("missing credentials.json path") }
	})

	t.Run("hooks", func(t *testing.T) {
		hooks, _ := inst.Hooks(ctx)
		if hooks[0].Name != "restart_soulflow" { t.Errorf("hook = %q", hooks[0].Name) }
		if hooks[0].Cmd[0] != "docker" { t.Errorf("cmd = %v", hooks[0].Cmd) }
	})

	t.Run("validate_env_ok", func(t *testing.T) {
		r, _ := inst.Validate(ctx, "/root/workspace/.env", "KEY=value\n# comment\nFOO=bar")
		if !r.OK { t.Errorf("expected ok: %s", r.Error) }
	})

	t.Run("validate_env_bad", func(t *testing.T) {
		r, _ := inst.Validate(ctx, "/root/workspace/.env", "KEY=value\nBAD LINE NO EQUALS")
		if r.OK { t.Error("expected fail") }
	})

	t.Run("validate_json_ok", func(t *testing.T) {
		r, _ := inst.Validate(ctx, "/root/workspace/.agents/.claude/.credentials.json",
			`{"claudeAiOauth":{"accessToken":"sk-ant-test"}}`)
		if !r.OK { t.Errorf("expected ok: %s", r.Error) }
	})

	t.Run("validate_json_bad", func(t *testing.T) {
		r, _ := inst.Validate(ctx, "/root/workspace/.agents/.codex/auth.json", "not json")
		if r.OK { t.Error("expected fail") }
	})

	t.Run("render_env", func(t *testing.T) {
		r, _ := inst.Render(ctx, "generate_env", map[string]any{
			"ANTHROPIC_API_KEY":        "sk-ant-test",
			"MATTERMOST_BOT_TOKEN":     "mm-token-123",
			"MATTERMOST_URL":           "http://10.50.0.202:8065",
			"SOULFLOW_ADMIN_PASSWORD":  "admin123",
		})
		if r.Error != "" { t.Fatal(r.Error) }
		if !strings.Contains(r.Output, "ANTHROPIC_API_KEY=sk-ant-test") { t.Error("missing api key") }
		if !strings.Contains(r.Output, "MATTERMOST_BOT_TOKEN=mm-token-123") { t.Error("missing mm token") }
		t.Logf("env:\n%s", r.Output)
	})

	t.Run("render_provider", func(t *testing.T) {
		r, _ := inst.Render(ctx, "generate_provider", map[string]any{
			"type":        "claude_cli",
			"instance_id": "orchestrator_llm",
			"label":       "Claude Code CLI",
			"settings":    map[string]any{"model": "claude-sonnet-4-6"},
		})
		if r.Error != "" { t.Fatal(r.Error) }
		if !strings.Contains(r.Output, "claude_cli") { t.Error("missing provider type") }
		if !strings.Contains(r.Output, "claude-sonnet-4-6") { t.Error("missing model") }
		t.Logf("provider:\n%s", r.Output)
	})
}
