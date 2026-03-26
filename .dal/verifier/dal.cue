uuid:           "v2-verifier-20260326"
name:           "verifier"
version:        "2.0.0"
player:         "claude"
player_version: "go"
role:           "member"
skills:         ["skills/go-ci", "skills/rust-ci", "skills/security-audit", "skills/code-review"]
hooks:          []
auto_task:      "veilkey-selfhosted 자체 검증: 1) go vet ./... && go test ./... 2) cd services/veil-cli && cargo test. 실패 시 실패 항목과 에러를 정리해서 보고. 전부 통과하면 PASS 한줄로 보고."
auto_interval:  "1h"
git: {
	user:         "dal-verifier"
	email:        "dal-verifier@dalcenter.local"
	github_token: "env:GITHUB_TOKEN"
}
