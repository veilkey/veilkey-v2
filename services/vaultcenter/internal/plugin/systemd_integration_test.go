package plugin

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestSystemdSyncPlugin(t *testing.T) {
	wasm, err := os.ReadFile("/root/jeonghan/repository/veilkey-plugins/systemd-sync/systemd-sync.wasm")
	if err != nil { t.Skipf("wasm not found: %v", err) }

	ctx := context.Background()
	inst, err := LoadInstance(ctx, wasm, HostFunctions{})
	if err != nil { t.Fatalf("load: %v", err) }
	defer inst.Close(ctx)

	t.Run("info", func(t *testing.T) {
		if inst.Info().Name != "systemd-sync" { t.Errorf("name = %q", inst.Info().Name) }
	})

	t.Run("hooks", func(t *testing.T) {
		hooks, err := inst.Hooks(ctx)
		if err != nil { t.Fatal(err) }
		if hooks[0].Name != "reload_systemd" { t.Errorf("hook = %q", hooks[0].Name) }
		if hooks[0].Cmd[0] != "systemctl" { t.Errorf("cmd = %v", hooks[0].Cmd) }
	})

	t.Run("validate_ok", func(t *testing.T) {
		r, err := inst.Validate(ctx, "/etc/systemd/system/myapp.service.d/override.conf", "[Service]\nEnvironment=FOO=bar")
		if err != nil { t.Fatal(err) }
		if !r.OK { t.Errorf("expected ok: %s", r.Error) }
	})

	t.Run("validate_fail", func(t *testing.T) {
		r, err := inst.Validate(ctx, "/etc/systemd/system/myapp.service", "just text no section")
		if err != nil { t.Fatal(err) }
		if r.OK { t.Error("expected fail") }
	})

	t.Run("render_override", func(t *testing.T) {
		r, err := inst.Render(ctx, "generate_override", map[string]any{
			"environment":      map[string]any{"DB_HOST": "localhost", "DB_PORT": "5432"},
			"environment_file": "/etc/myapp/.env",
			"restart":          "always",
			"limit_nofile":     float64(65536),
		})
		if err != nil { t.Fatal(err) }
		if !strings.Contains(r.Output, "[Service]") { t.Error("missing [Service]") }
		if !strings.Contains(r.Output, "DB_HOST=localhost") { t.Error("missing env") }
		if !strings.Contains(r.Output, "LimitNOFILE=65536") { t.Error("missing limit") }
		t.Logf("override:\n%s", r.Output)
	})

	t.Run("render_service", func(t *testing.T) {
		r, err := inst.Render(ctx, "generate_service", map[string]any{
			"description":       "My App",
			"after":             "network.target",
			"exec_start":        "/usr/bin/myapp serve",
			"user":              "myapp",
			"working_directory": "/opt/myapp",
		})
		if err != nil { t.Fatal(err) }
		if !strings.Contains(r.Output, "[Unit]") { t.Error("missing [Unit]") }
		if !strings.Contains(r.Output, "ExecStart=/usr/bin/myapp serve") { t.Error("missing ExecStart") }
		if !strings.Contains(r.Output, "WantedBy=multi-user.target") { t.Error("missing WantedBy") }
		t.Logf("service:\n%s", r.Output)
	})
}
