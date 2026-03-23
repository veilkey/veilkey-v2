package plugin

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func pctExec(vmid string, cmd string) (string, error) {
	out, err := exec.Command("pct", "exec", vmid, "--", "bash", "-c", cmd).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func TestRealDeploy_GitLabSync(t *testing.T) {
	wasm, err := os.ReadFile("/root/jeonghan/repository/veilkey-plugins/gitlab/gitlab.wasm")
	if err != nil { t.Skip("wasm not found") }

	ctx := context.Background()
	inst, err := LoadInstance(ctx, wasm, HostFunctions{})
	if err != nil { t.Fatal(err) }
	defer inst.Close(ctx)

	// 1. 현재 gitlab.rb 백업
	before, _ := pctExec("120", "head -5 /etc/gitlab/gitlab.rb 2>/dev/null")
	t.Logf("BEFORE: %s", before)

	// 2. 플러그인으로 새 config 렌더링
	result, err := inst.Render(ctx, "generate_config", map[string]any{
		"external_url": "http://10.50.0.120",
		"gitlab_rails": map[string]any{
			"time_zone":            "Asia/Seoul",
			"gitlab_email_enabled": false,
		},
		"nginx": map[string]any{
			"listen_port":  float64(80),
			"listen_https": false,
		},
	})
	if err != nil { t.Fatal(err) }

	// output에서 실제 config 추출
	var rendered struct{ Output string }
	json.Unmarshal([]byte(result.Output), &rendered)
	config := rendered.Output
	if config == "" { config = result.Output }
	t.Logf("RENDERED:\n%s", config)

	// 3. 검증
	valid, _ := inst.Validate(ctx, "/etc/gitlab/gitlab.rb", config)
	if !valid.OK { t.Fatalf("validate failed: %s", valid.Error) }

	// 4. LXC 120에 실제 배포
	tmpFile := "/tmp/gitlab.rb.veilkey"
	os.WriteFile(tmpFile, []byte(config), 0644)
	exec.Command("pct", "push", "120", tmpFile, "/etc/gitlab/gitlab.rb").Run()

	// 5. 배포된 파일 확인
	after, _ := pctExec("120", "cat /etc/gitlab/gitlab.rb")
	if !strings.Contains(after, "Asia/Seoul") {
		t.Error("timezone not found in deployed file")
	}
	if !strings.Contains(after, "10.50.0.120") {
		t.Error("external_url not found")
	}
	t.Logf("AFTER (deployed): %s", after[:min(len(after), 200)])

	// 6. reconfigure 실행 (hook 시뮬레이션)
	t.Log("Running gitlab-ctl reconfigure...")
	hookOut, err := pctExec("120", "LANG=en_US.UTF-8 gitlab-ctl reconfigure 2>&1 | tail -3")
	t.Logf("HOOK: %s (err=%v)", hookOut, err)
	if !strings.Contains(hookOut, "Reconfigured") && err != nil {
		t.Errorf("reconfigure failed: %s", hookOut)
	}

	// 7. GitLab 정상 동작 확인
	httpCode, _ := pctExec("120", "curl -so /dev/null -w '%{http_code}' http://localhost 2>/dev/null")
	t.Logf("HTTP: %s", httpCode)
	if httpCode != "302" && httpCode != "200" {
		t.Errorf("GitLab not responding: %s", httpCode)
	}
}

func min(a, b int) int { if a < b { return a }; return b }
