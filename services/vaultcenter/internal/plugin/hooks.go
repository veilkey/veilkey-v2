package plugin

import "fmt"

// SortHooks performs a topological sort on hooks based on their Depends fields.
// Uses Kahn's algorithm. Returns an error if a cycle is detected.
// Unknown dependencies (plugin not loaded) are logged and skipped.
func SortHooks(hooks []HookDef) ([]HookDef, error) {
	if len(hooks) <= 1 {
		return hooks, nil
	}

	// Build name → hook map
	byName := make(map[string]HookDef, len(hooks))
	for _, h := range hooks {
		byName[h.Name] = h
	}

	// Build adjacency and in-degree
	inDegree := make(map[string]int, len(hooks))
	dependents := make(map[string][]string) // dep → list of hooks that depend on it

	for _, h := range hooks {
		if _, ok := inDegree[h.Name]; !ok {
			inDegree[h.Name] = 0
		}
		for _, dep := range h.Depends {
			if _, known := byName[dep]; !known {
				// Dependency from unloaded plugin — skip
				continue
			}
			inDegree[h.Name]++
			dependents[dep] = append(dependents[dep], h.Name)
		}
	}

	// Kahn's algorithm
	var queue []string
	for _, h := range hooks {
		if inDegree[h.Name] == 0 {
			queue = append(queue, h.Name)
		}
	}

	var sorted []HookDef
	for len(queue) > 0 {
		name := queue[0]
		queue = queue[1:]
		sorted = append(sorted, byName[name])

		for _, dep := range dependents[name] {
			inDegree[dep]--
			if inDegree[dep] == 0 {
				queue = append(queue, dep)
			}
		}
	}

	if len(sorted) != len(hooks) {
		return nil, fmt.Errorf("cycle detected in hook dependencies")
	}
	return sorted, nil
}
