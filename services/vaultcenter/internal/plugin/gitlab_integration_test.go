package plugin

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestGitLabPluginWASM(t *testing.T) {
	wasmPath := "/root/jeonghan/repository/veilkey-plugins/gitlab/gitlab.wasm"
	wasm, err := os.ReadFile(wasmPath)
	if err != nil {
		t.Skipf("gitlab.wasm not found: %v", err)
	}

	ctx := context.Background()
	inst, err := LoadInstance(ctx, wasm, HostFunctions{
		ResolveSecret: func(name string) (string, bool) { return "secret-" + name, true },
		ResolveConfig: func(name string) (string, bool) { return "config-" + name, true },
	})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	defer inst.Close(ctx)

	// plugin_info
	info := inst.Info()
	if info.Name != "gitlab" {
		t.Errorf("name = %q, want gitlab", info.Name)
	}
	if info.Version != "1.0.0" {
		t.Errorf("version = %q", info.Version)
	}
	t.Logf("plugin_info: %+v", info)

	// plugin_init
	initResult, err := inst.Init(ctx, map[string]any{})
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	if len(initResult.Paths) != 1 || initResult.Paths[0] != "/etc/gitlab/gitlab.rb" {
		t.Errorf("paths = %v", initResult.Paths)
	}
	if len(initResult.Hooks) != 1 || initResult.Hooks[0].Name != "reconfigure_gitlab" {
		t.Errorf("hooks = %v", initResult.Hooks)
	}
	t.Logf("plugin_init: paths=%v hooks=%d api_routes=%d", initResult.Paths, len(initResult.Hooks), len(initResult.APIRoutes))

	// plugin_paths
	paths, err := inst.Paths(ctx)
	if err != nil {
		t.Fatalf("paths: %v", err)
	}
	if len(paths) != 1 {
		t.Errorf("paths count = %d", len(paths))
	}

	// plugin_hooks
	hooks, err := inst.Hooks(ctx)
	if err != nil {
		t.Fatalf("hooks: %v", err)
	}
	if hooks[0].Cmd[0] != "gitlab-ctl" {
		t.Errorf("hook cmd = %v", hooks[0].Cmd)
	}

	// plugin_validate — valid
	valid, err := inst.Validate(ctx, "/etc/gitlab/gitlab.rb", "external_url 'http://test'")
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if !valid.OK {
		t.Errorf("expected valid, got error: %s", valid.Error)
	}

	// plugin_validate — invalid (missing external_url)
	invalid, err := inst.Validate(ctx, "/etc/gitlab/gitlab.rb", "# no url here")
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if invalid.OK {
		t.Error("expected invalid")
	}
	if !strings.Contains(invalid.Error, "external_url") {
		t.Errorf("error = %q", invalid.Error)
	}

	// plugin_render — generate_config
	render, err := inst.Render(ctx, "generate_config", map[string]any{
		"external_url": "http://10.50.0.120",
		"gitlab_rails": map[string]any{
			"time_zone": "Asia/Seoul",
		},
		"nginx": map[string]any{
			"listen_port":  float64(80),
			"listen_https": false,
		},
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if render.Error != "" {
		t.Fatalf("render error: %s", render.Error)
	}

	// Verify rendered config
	var output struct{ Output string }
	_ = json.Unmarshal([]byte(render.Output), &output)
	config := output.Output
	if config == "" {
		config = render.Output
	}
	if !strings.Contains(config, "external_url") {
		t.Error("missing external_url in rendered config")
	}
	if !strings.Contains(config, "10.50.0.120") {
		t.Error("missing IP in rendered config")
	}
	t.Logf("rendered gitlab.rb:\n%s", config)
}
