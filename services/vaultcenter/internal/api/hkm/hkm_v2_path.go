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
// Segments must start with a lowercase letter or digit, optionally followed by
// lowercase letters, digits, hyphens, or underscores.
var v2PathSegmentPattern = regexp.MustCompile(`^[a-z0-9_][a-z0-9_-]*$`)

// parseV2Path parses a v2 path-based reference token into its components.
// The token format is "{vault}/{group}/{key}".
// Returns an error if the format is invalid.
func parseV2Path(token string) (*v2PathRef, error) {
	if strings.Count(token, "/") > 2 {
		return nil, fmt.Errorf("invalid v2 path: too many segments in %%q", token)
	}
	parts := strings.SplitN(token, "/", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid v2 path: expected {vault}/{group}/{key}, got %q", token)
	}

	vault, group, key := parts[0], parts[1], parts[2]

	if vault == "" || group == "" || key == "" {
		return nil, fmt.Errorf("invalid v2 path: empty segment in %q", token)
	}
	if !v2PathSegmentPattern.MatchString(vault) {
		return nil, fmt.Errorf("invalid v2 path: bad vault segment %q", vault)
	}
	if !v2PathSegmentPattern.MatchString(group) {
		return nil, fmt.Errorf("invalid v2 path: bad group segment %q", group)
	}
	if !v2PathSegmentPattern.MatchString(key) {
		return nil, fmt.Errorf("invalid v2 path: bad key segment %q", key)
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
