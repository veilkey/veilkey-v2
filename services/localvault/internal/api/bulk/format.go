package bulk

// FormatProvider handles format-specific apply, validate, and postcheck logic.
type FormatProvider interface {
	Name() string
	Validate(content string) error
	Apply(targetPath string, content string) error
	Postchecks() []string
}

// FormatRegistry maps format names to providers.
type FormatRegistry struct {
	providers map[string]FormatProvider
}

func NewFormatRegistry() *FormatRegistry {
	r := &FormatRegistry{providers: make(map[string]FormatProvider)}
	// Register builtins
	r.Register(&RawFormat{})
	r.Register(&EnvFormat{})
	r.Register(&JSONFormat{})
	r.Register(&JSONMergeFormat{})
	return r
}

func (r *FormatRegistry) Register(p FormatProvider) { r.providers[p.Name()] = p }
func (r *FormatRegistry) Get(name string) (FormatProvider, bool) {
	p, ok := r.providers[name]
	return p, ok
}
