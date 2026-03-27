package hkm

import (
	"testing"
)

func TestParseV2Path_Valid(t *testing.T) {
	cases := []struct {
		token string
		vault string
		group string
		key   string
	}{
		{"host-lv/owner/password", "host-lv", "owner", "password"},
		{"soulflow-lv/db/password", "soulflow-lv", "db", "password"},
		{"host-lv/cloudflare/api-key", "host-lv", "cloudflare", "api-key"},
		{"host-lv/mailgun/api-key", "host-lv", "mailgun", "api-key"},
		{"host-lv/_temp/session-token", "host-lv", "_temp", "session-token"},
		{"host-lv/_ssh/deploy-key", "host-lv", "_ssh", "deploy-key"},
		{"a/b/c", "a", "b", "c"},
		{"vault1/group2/key3", "vault1", "group2", "key3"},
		{"0start/1group/2key", "0start", "1group", "2key"},
		{"_under/score_group/key_name", "_under", "score_group", "key_name"},
	}
	for _, tc := range cases {
		ref, err := parseV2Path(tc.token)
		if err != nil {
			t.Errorf("parseV2Path(%q) unexpected error: %v", tc.token, err)
			continue
		}
		if ref.Vault != tc.vault {
			t.Errorf("parseV2Path(%q).Vault = %q, want %q", tc.token, ref.Vault, tc.vault)
		}
		if ref.Group != tc.group {
			t.Errorf("parseV2Path(%q).Group = %q, want %q", tc.token, ref.Group, tc.group)
		}
		if ref.Key != tc.key {
			t.Errorf("parseV2Path(%q).Key = %q, want %q", tc.token, ref.Key, tc.key)
		}
	}
}

func TestParseV2Path_Invalid(t *testing.T) {
	cases := []struct {
		token string
		desc  string
	}{
		{"host-lv/owner", "only two segments"},
		{"host-lv", "single segment"},
		{"", "empty string"},
		{"host-lv//password", "empty group segment"},
		{"/owner/password", "empty vault segment"},
		{"host-lv/owner/", "empty key segment"},
		{"HOST-LV/owner/password", "uppercase vault"},
		{"host-lv/Owner/password", "uppercase group"},
		{"host-lv/owner/Password", "uppercase key"},
		{"host lv/owner/password", "space in vault"},
		{"host-lv/own er/password", "space in group"},
		{"host-lv/owner/pass word", "space in key"},
		{"host.lv/owner/password", "dot in vault"},
		{"host-lv/owner/pass.word", "dot in key"},
		{"-host/owner/password", "vault starts with hyphen"},
		{"host-lv/-group/password", "group starts with hyphen"},
		{"host-lv/owner/-key", "key starts with hyphen"},
	}
	for _, tc := range cases {
		ref, err := parseV2Path(tc.token)
		if err == nil {
			t.Errorf("parseV2Path(%q) [%s] expected error, got %+v", tc.token, tc.desc, ref)
		}
	}
}

func TestV2PathRef_GroupKeyPath(t *testing.T) {
	cases := []struct {
		group string
		key   string
		want  string
	}{
		{"owner", "password", "owner/password"},
		{"cloudflare", "api-key", "cloudflare/api-key"},
		{"_temp", "session-token", "_temp/session-token"},
		{"_ssh", "deploy-key", "_ssh/deploy-key"},
		{"db", "password", "db/password"},
	}
	for _, tc := range cases {
		ref := &v2PathRef{Vault: "test", Group: tc.group, Key: tc.key}
		got := ref.groupKeyPath()
		if got != tc.want {
			t.Errorf("groupKeyPath() for group=%q key=%q = %q, want %q", tc.group, tc.key, got, tc.want)
		}
	}
}

func TestV2PathSegmentPattern(t *testing.T) {
	valid := []string{
		"host-lv", "soulflow-lv", "owner", "password", "api-key",
		"_temp", "_ssh", "a", "0", "abc123", "a-b-c", "a_b_c",
		"_underscore-start", "0digit-start",
	}
	for _, seg := range valid {
		if !v2PathSegmentPattern.MatchString(seg) {
			t.Errorf("v2PathSegmentPattern should match %q", seg)
		}
	}

	invalid := []string{
		"", "-start", "UPPER", "MixedCase", "has space", "has.dot",
		"has/slash", "has@at", "has!bang",
	}
	for _, seg := range invalid {
		if v2PathSegmentPattern.MatchString(seg) {
			t.Errorf("v2PathSegmentPattern should NOT match %q", seg)
		}
	}
}
