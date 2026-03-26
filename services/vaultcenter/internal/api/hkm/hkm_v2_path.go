package hkm
import ("fmt";"regexp";"strings")
type v2PathRef struct {Vault, Group, Key string}
var v2PathSegmentPattern = regexp.MustCompile(`^[a-z0-9_][a-z0-9_-]*$`)
func parseV2Path(token string) (*v2PathRef, error) {
	parts := strings.SplitN(token, "/", 3)
	if len(parts) != 3 { return nil, fmt.Errorf("expected {vault}/{group}/{key}, got %q", token) }
	v, g, k := parts[0], parts[1], parts[2]
	if v == "" || g == "" || k == "" { return nil, fmt.Errorf("empty segment in %q", token) }
	if !v2PathSegmentPattern.MatchString(v) { return nil, fmt.Errorf("bad vault segment %q", v) }
	if !v2PathSegmentPattern.MatchString(g) { return nil, fmt.Errorf("bad group segment %q", g) }
	if !v2PathSegmentPattern.MatchString(k) { return nil, fmt.Errorf("bad key segment %q", k) }
	return &v2PathRef{Vault: v, Group: g, Key: k}, nil
}
func (p *v2PathRef) groupKeyPath() string { return p.Group + "/" + p.Key }
