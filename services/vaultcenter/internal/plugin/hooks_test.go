package plugin

import (
	"strings"
	"testing"
)

func TestSortHooks_Empty(t *testing.T) {
	sorted, err := SortHooks(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(sorted) != 0 {
		t.Fatalf("expected empty, got %d", len(sorted))
	}
}

func TestSortHooks_Single(t *testing.T) {
	hooks := []HookDef{{Name: "reload_systemd", Cmd: []string{"systemctl", "daemon-reload"}}}
	sorted, err := SortHooks(hooks)
	if err != nil {
		t.Fatal(err)
	}
	if len(sorted) != 1 || sorted[0].Name != "reload_systemd" {
		t.Fatalf("got %v", sorted)
	}
}

func TestSortHooks_LinearDeps(t *testing.T) {
	// reload_systemd → restart_mattermost (restart depends on reload)
	hooks := []HookDef{
		{Name: "restart_mattermost", Cmd: []string{"systemctl", "restart", "mattermost"}, Depends: []string{"reload_systemd"}},
		{Name: "reload_systemd", Cmd: []string{"systemctl", "daemon-reload"}},
	}
	sorted, err := SortHooks(hooks)
	if err != nil {
		t.Fatal(err)
	}
	if len(sorted) != 2 {
		t.Fatalf("expected 2, got %d", len(sorted))
	}
	if sorted[0].Name != "reload_systemd" {
		t.Errorf("expected reload_systemd first, got %s", sorted[0].Name)
	}
	if sorted[1].Name != "restart_mattermost" {
		t.Errorf("expected restart_mattermost second, got %s", sorted[1].Name)
	}
}

func TestSortHooks_DiamondDeps(t *testing.T) {
	// A → B, A → C, B → D, C → D  (D must be first, A must be last)
	hooks := []HookDef{
		{Name: "A", Depends: []string{"B", "C"}},
		{Name: "B", Depends: []string{"D"}},
		{Name: "C", Depends: []string{"D"}},
		{Name: "D"},
	}
	sorted, err := SortHooks(hooks)
	if err != nil {
		t.Fatal(err)
	}
	if sorted[0].Name != "D" {
		t.Errorf("D must be first, got %s", sorted[0].Name)
	}
	// A must be last
	if sorted[3].Name != "A" {
		t.Errorf("A must be last, got %s", sorted[3].Name)
	}
}

func TestSortHooks_CycleDetected(t *testing.T) {
	hooks := []HookDef{
		{Name: "A", Depends: []string{"B"}},
		{Name: "B", Depends: []string{"A"}},
	}
	_, err := SortHooks(hooks)
	if err == nil {
		t.Fatal("expected cycle error")
	}
	if !strings.Contains(err.Error(), "cycle") {
		t.Errorf("expected cycle error, got: %v", err)
	}
}

func TestSortHooks_UnknownDepSkipped(t *testing.T) {
	// restart_mattermost depends on "systemd-sync:reload_systemd" which is not in the list
	hooks := []HookDef{
		{Name: "restart_mattermost", Depends: []string{"systemd-sync:reload_systemd"}},
	}
	sorted, err := SortHooks(hooks)
	if err != nil {
		t.Fatal(err)
	}
	if len(sorted) != 1 {
		t.Fatalf("expected 1 hook, got %d", len(sorted))
	}
}

func TestSortHooks_NoDeps(t *testing.T) {
	hooks := []HookDef{
		{Name: "hook_a"},
		{Name: "hook_b"},
		{Name: "hook_c"},
	}
	sorted, err := SortHooks(hooks)
	if err != nil {
		t.Fatal(err)
	}
	if len(sorted) != 3 {
		t.Fatalf("expected 3, got %d", len(sorted))
	}
}

func TestSortHooks_ThreeLevelChain(t *testing.T) {
	// C → B → A (A runs first)
	hooks := []HookDef{
		{Name: "C", Depends: []string{"B"}},
		{Name: "A"},
		{Name: "B", Depends: []string{"A"}},
	}
	sorted, err := SortHooks(hooks)
	if err != nil {
		t.Fatal(err)
	}
	idx := map[string]int{}
	for i, h := range sorted {
		idx[h.Name] = i
	}
	if idx["A"] >= idx["B"] {
		t.Errorf("A must come before B")
	}
	if idx["B"] >= idx["C"] {
		t.Errorf("B must come before C")
	}
}
