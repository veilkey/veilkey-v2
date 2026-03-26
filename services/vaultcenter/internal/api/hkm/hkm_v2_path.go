package hkm

import (
	"fmt"
	"regexp"
	"strings"
)

// v2PathRef holds the parsed components of a v2 path-based reference.
// Format: {vault}/{group}/{key}
type v2PathRef struct {
	Vault string // e.g. "host-lv"
	Group string // e.g. "mailgun", "_temp", "_ssh"
	Key   string // e.g. "api-key"
}

// v2PathSegmentPattern validates each segment of a v2 path reference.
var v2PathSegmentPattern = regexp.MustCompile(`^[a-z0-9_][a-z0-9_-]*$`)

// parseV2Path parses a v2 path-based reference token into its components.
// The token format is "{vault}/{group}/{key}".
func parseV2Path(token string) (*v2PathRef, error) {
	parts := strings.SplitN(token, "/", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("expected {vault}/{group}/{key}, got %q", token)
	}

	vault, group, key := parts[0], parts[1], parts[2]

	if vault == "" || group == "" || key == "" {
		return nil, fmt.Errorf("empty segment in %q", token)
	}
	if !v2PathSegmentPattern.MatchString(vault) {
		return nil, fmt.Errorf("bad vault segment %q", vault)
	}
	if !v2PathSegmentPattern.MatchString(group) {
		return nil, fmt.Errorf("bad group segment %q", group)
	}
	if !v2PathSegmentPattern.MatchString(key) {
		return nil, fmt.Errorf("bad key segment %q", key)
	}

	return &v2PathRef{
		Vault: vault,
		Group: group,
		Key:   key,
	}, nil
}

// groupKeyPath returns the "{group}/{key}" portion used to fetch ciphertext
// from a LocalVault agent.
func (p *v2PathRef) groupKeyPath() string {
	return p.Group + "/" + p.Key
}
