package hkm

import (
	"testing"
)

func TestParseV2Path(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    *v2PathRef
		wantErr bool
	}{
		{
			name:  "valid path",
			input: "host-lv/mailgun/api-key",
			want:  &v2PathRef{Vault: "host-lv", Group: "mailgun", Key: "api-key"},
		},
		{
			name:  "reserved _temp group",
			input: "host-lv/_temp/session-token",
			want:  &v2PathRef{Vault: "host-lv", Group: "_temp", Key: "session-token"},
		},
		{
			name:  "reserved _ssh group",
			input: "host-lv/_ssh/deploy-key",
			want:  &v2PathRef{Vault: "host-lv", Group: "_ssh", Key: "deploy-key"},
		},
		{
			name:  "numeric segments",
			input: "vault1/group2/key3",
			want:  &v2PathRef{Vault: "vault1", Group: "group2", Key: "key3"},
		},
		{
			name:    "too few segments",
			input:   "host-lv/api-key",
			wantErr: true,
		},
		{
			name:    "too many segments",
			input:   "host-lv/group/sub/key",
			wantErr: true,
		},
		{
			name:    "empty vault",
			input:   "/mailgun/api-key",
			wantErr: true,
		},
		{
			name:    "empty group",
			input:   "host-lv//api-key",
			wantErr: true,
		},
		{
			name:    "empty key",
			input:   "host-lv/mailgun/",
			wantErr: true,
		},
		{
			name:    "uppercase rejected",
			input:   "Host-LV/Mailgun/Api-Key",
			wantErr: true,
		},
		{
			name:    "spaces rejected",
			input:   "host lv/mail gun/api key",
			wantErr: true,
		},
		{
			name:    "dots rejected",
			input:   "host.lv/mailgun/api.key",
			wantErr: true,
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
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
			if got.Vault != tt.want.Vault || got.Group != tt.want.Group || got.Key != tt.want.Key {
				t.Errorf("parseV2Path(%q) = %+v, want %+v", tt.input, got, tt.want)
			}
		})
	}
}

func TestV2PathRefGroupKeyPath(t *testing.T) {
	ref := &v2PathRef{Vault: "host-lv", Group: "mailgun", Key: "api-key"}
	got := ref.groupKeyPath()
	want := "mailgun/api-key"
	if got != want {
		t.Errorf("groupKeyPath() = %q, want %q", got, want)
	}
}
