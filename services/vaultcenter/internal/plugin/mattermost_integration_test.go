package plugin

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestMattermostSyncPlugin(t *testing.T) {
	wasm, err := os.ReadFile("/root/jeonghan/repository/veilkey-plugins/mattermost-sync/mattermost-sync.wasm")
	if err != nil { t.Skipf("wasm not found: %v", err) }

	ctx := context.Background()
	inst, err := LoadInstance(ctx, wasm, HostFunctions{})
	if err != nil { t.Fatalf("load: %v", err) }
	defer inst.Close(ctx)

	t.Run("info", func(t *testing.T) {
		if inst.Info().Name != "mattermost-sync" { t.Errorf("name = %q", inst.Info().Name) }
	})

	t.Run("init_paths", func(t *testing.T) {
		r, _ := inst.Init(ctx, map[string]any{})
		if len(r.Paths) != 3 { t.Errorf("paths = %v", r.Paths) }
	})

	t.Run("hooks_depends", func(t *testing.T) {
		hooks, _ := inst.Hooks(ctx)
		if hooks[0].Depends[0] != "systemd-sync:reload_systemd" { t.Errorf("depends = %v", hooks[0].Depends) }
	})

	t.Run("validate_ok", func(t *testing.T) {
		cfg := `{"ServiceSettings":{"SiteURL":"http://mm.test"},"SqlSettings":{"DataSource":"postgres://..."}}`
		r, _ := inst.Validate(ctx, "/opt/mattermost/config/config.json", cfg)
		if !r.OK { t.Errorf("expected ok: %s", r.Error) }
	})

	t.Run("validate_missing_siteurl", func(t *testing.T) {
		cfg := `{"ServiceSettings":{"SiteURL":""},"SqlSettings":{"DataSource":"postgres://..."}}`
		r, _ := inst.Validate(ctx, "/opt/mattermost/config/config.json", cfg)
		if r.OK { t.Error("expected fail") }
		if !strings.Contains(r.Error, "SiteURL") { t.Errorf("error = %q", r.Error) }
	})

	t.Run("validate_invalid_json", func(t *testing.T) {
		r, _ := inst.Validate(ctx, "/opt/mattermost/config/config.json", "not json")
		if r.OK { t.Error("expected fail") }
	})

	t.Run("render", func(t *testing.T) {
		r, _ := inst.Render(ctx, "generate_config", map[string]any{
			"site_url":        "http://10.50.0.202:8065",
			"listen_address":  ":8065",
			"data_source":     "postgres://mmuser:pass@localhost:5432/mattermost?sslmode=disable",
			"site_name":       "Prelik",
			"max_users":       float64(50),
		})
		if r.Error != "" { t.Fatal(r.Error) }
		if !strings.Contains(r.Output, "10.50.0.202") { t.Error("missing site_url") }
		if !strings.Contains(r.Output, "postgres://") { t.Error("missing datasource") }
		t.Logf("config:\n%s", r.Output)
	})
}
