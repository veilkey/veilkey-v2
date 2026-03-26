uuid:    "v2-improver-20260327"
name:    "improver"
version: "1.0.0"
player:  "claude"
role:    "member"
skills:  ["skills/go-security", "skills/code-review", "skills/rust-ci", "skills/security-audit"]
hooks:   []
git: {
	user:         "dal-improver"
	email:        "dal-improver@dalcenter.local"
	github_token: "env:GITHUB_TOKEN"
}
