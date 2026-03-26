uuid:           "v2-dev-20260326"
name:           "dev"
version:        "2.0.0"
player:         "claude"
player_version: "go"
role:            "member"
skills:  ["skills/go-security", "skills/code-review", "skills/go-ci", "skills/rust-ci", "skills/security-audit"]
hooks:   []
git: {
	user:         "dal-dev"
	email:        "dal-dev@dalcenter.local"
	github_token: "env:GITHUB_TOKEN"
}
