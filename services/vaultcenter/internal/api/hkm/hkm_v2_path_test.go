package hkm

import "testing"

func TestParseV2Path(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		vault   string
		group   string
		key     string
		wantErr bool
	}{
		{"valid", "host-lv/mailgun/api-key", "host-lv", "mailgun", "api-key", false},
		{"temp group", "host-lv/_temp/session-token", "host-lv", "_temp", "session-token", false},
		{"ssh group", "host-lv/_ssh/deploy-key", "host-lv", "_ssh", "deploy-key", false},
		{"numeric", "vault1/group2/key3", "vault1", "group2", "key3", false},
		{"too few segments", "host-lv/api-key", "", "", "", true},
		{"too many segments", "host-lv/group/sub/key", "", "", "", true},
		{"empty vault", "/mailgun/api-key", "", "", "", true},
		{"empty group", "host-lv//api-key", "", "", "", true},
		{"empty key", "host-lv/mailgun/", "", "", "", true},
		{"uppercase", "Host-LV/Mailgun/Api-Key", "", "", "", true},
		{"spaces", "host lv/mail gun/api key", "", "", "", true},
		{"dots", "host.lv/mailgun/api.key", "", "", "", true},
		{"empty string", "", "", "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseV2Path(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("parseV2Path(%q) expected error, got %+v", tt.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseV2Path(%q) unexpected error: %v", tt.input, err)
			}
			if got.Vault != tt.vault || got.Group != tt.group || got.Key != tt.key {
				t.Errorf("parseV2Path(%q) = {%s,%s,%s}, want {%s,%s,%s}", tt.input, got.Vault, got.Group, got.Key, tt.vault, tt.group, tt.key)
			}
		})
	}
}

func TestV2PathRefGroupKeyPath(t *testing.T) {
	ref := &v2PathRef{Vault: "host-lv", Group: "mailgun", Key: "api-key"}
	if got := ref.groupKeyPath(); got != "mailgun/api-key" {
		t.Errorf("groupKeyPath() = %q, want %q", got, "mailgun/api-key")
	}
}
