package hkm

import (
	"testing"
)

// ══════════════════════════════════════════════════════════════════
// Unit tests for v2 path-based reference parsing (hkm_v2_path.go)
// ══════════════════════════════════════════════════════════════════

// --- parseV2Path: valid inputs ---

func TestParseV2Path_ValidThreeSegments(t *testing.T) {
	ref, err := parseV2Path("host-lv/mailgun/api-key")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ref.Vault != "host-lv" || ref.Group != "mailgun" || ref.Key != "api-key" {
		t.Errorf("got vault=%q group=%q key=%q", ref.Vault, ref.Group, ref.Key)
	}
}

func TestParseV2Path_ValidDigitStart(t *testing.T) {
	ref, err := parseV2Path("0prod/1db/2pass")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ref.Vault != "0prod" || ref.Group != "1db" || ref.Key != "2pass" {
		t.Errorf("got vault=%q group=%q key=%q", ref.Vault, ref.Group, ref.Key)
	}
}

func TestParseV2Path_ValidUnderscorePrefix(t *testing.T) {
	ref, err := parseV2Path("vault/_temp/session-key")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ref.Group != "_temp" {
		t.Errorf("expected group _temp, got %q", ref.Group)
	}
}

func TestParseV2Path_GroupKeyPath(t *testing.T) {
	ref, err := parseV2Path("host-lv/mailgun/api-key")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ref.groupKeyPath() != "mailgun/api-key" {
		t.Errorf("expected groupKeyPath mailgun/api-key, got %q", ref.groupKeyPath())
	}
}

// --- parseV2Path: invalid inputs ---

func TestParseV2Path_TwoSegments(t *testing.T) {
	_, err := parseV2Path("only/two")
	if err == nil {
		t.Error("expected error for two-segment path")
	}
}

func TestParseV2Path_FourSegments(t *testing.T) {
	// SplitN(token, "/", 3) collapses 4th segment into key — key must still be valid
	_, err := parseV2Path("a/b/c/d")
	if err == nil {
		// "c/d" contains "/" which fails the segment pattern
		t.Error("expected error for four-segment path (key contains /)")
	}
}

func TestParseV2Path_SingleSegment(t *testing.T) {
	_, err := parseV2Path("just-one")
	if err == nil {
		t.Error("expected error for single-segment path")
	}
}

func TestParseV2Path_EmptySegment(t *testing.T) {
	_, err := parseV2Path("vault//key")
	if err == nil {
		t.Error("expected error for empty middle segment")
	}
}

func TestParseV2Path_EmptyString(t *testing.T) {
	_, err := parseV2Path("")
	if err == nil {
		t.Error("expected error for empty string")
	}
}

// --- Security: path traversal ---

func TestParseV2Path_PathTraversal(t *testing.T) {
	_, err := parseV2Path("../etc/passwd")
	if err == nil {
		t.Error("expected error for path traversal (..)")
	}
}

func TestParseV2Path_DotSegment(t *testing.T) {
	_, err := parseV2Path("./current/dir")
	if err == nil {
		t.Error("expected error for dot segment (.)")
	}
}

// --- Security: hyphen-start segment ---

func TestParseV2Path_HyphenStartVault(t *testing.T) {
	_, err := parseV2Path("-bad/group/key")
	if err == nil {
		t.Error("expected error for hyphen-start vault segment")
	}
}

func TestParseV2Path_HyphenStartGroup(t *testing.T) {
	_, err := parseV2Path("vault/-bad/key")
	if err == nil {
		t.Error("expected error for hyphen-start group segment")
	}
}

func TestParseV2Path_HyphenStartKey(t *testing.T) {
	_, err := parseV2Path("vault/group/-bad")
	if err == nil {
		t.Error("expected error for hyphen-start key segment")
	}
}

// --- Security: uppercase / special chars ---

func TestParseV2Path_UppercaseRejected(t *testing.T) {
	_, err := parseV2Path("Vault/Group/Key")
	if err == nil {
		t.Error("expected error for uppercase segments")
	}
}

func TestParseV2Path_SpecialCharsRejected(t *testing.T) {
	cases := []string{
		"vault/group/key@1",
		"vault/group/key.pem",
		"vault/group/key space",
		"vault/group/key$var",
	}
	for _, c := range cases {
		_, err := parseV2Path(c)
		if err == nil {
			t.Errorf("expected error for path with special chars: %q", c)
		}
	}
}
