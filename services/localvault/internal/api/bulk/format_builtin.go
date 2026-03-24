package bulk

import (
	"encoding/json"
	"fmt"
	"os"
)

// ── RawFormat ────────────────────────────────────────────────────────────────

type RawFormat struct{}

func (f *RawFormat) Name() string { return "raw" }

func (f *RawFormat) Validate(content string) error {
	if content == "" {
		return fmt.Errorf("content is empty")
	}
	return nil
}

func (f *RawFormat) Apply(targetPath string, content string) error {
	return writeAtomically(targetPath, []byte(content))
}

func (f *RawFormat) Postchecks() []string { return []string{"file_written"} }

// ── EnvFormat ────────────────────────────────────────────────────────────────

type EnvFormat struct{}

func (f *EnvFormat) Name() string { return "env" }

func (f *EnvFormat) Validate(content string) error {
	if content == "" {
		return fmt.Errorf("content is empty")
	}
	return nil
}

func (f *EnvFormat) Apply(targetPath string, content string) error {
	return writeAtomically(targetPath, []byte(content))
}

func (f *EnvFormat) Postchecks() []string { return []string{"file_written"} }

// ── JSONFormat ───────────────────────────────────────────────────────────────

type JSONFormat struct{}

func (f *JSONFormat) Name() string { return "json" }

func (f *JSONFormat) Validate(content string) error {
	var payload map[string]any
	if err := json.Unmarshal([]byte(content), &payload); err != nil {
		return fmt.Errorf("invalid json content: %w", err)
	}
	return nil
}

func (f *JSONFormat) Apply(targetPath string, content string) error {
	return writeAtomically(targetPath, []byte(content))
}

func (f *JSONFormat) Postchecks() []string { return []string{"json_parse"} }

// ── JSONMergeFormat ──────────────────────────────────────────────────────────

type JSONMergeFormat struct{}

func (f *JSONMergeFormat) Name() string { return "json_merge" }

func (f *JSONMergeFormat) Validate(content string) error {
	var payload map[string]any
	if err := json.Unmarshal([]byte(content), &payload); err != nil {
		return fmt.Errorf("invalid json content: %w", err)
	}
	return nil
}

func (f *JSONMergeFormat) Apply(targetPath string, content string) error {
	var current map[string]any
	if raw, err := os.ReadFile(targetPath); err == nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, &current); err != nil {
			return fmt.Errorf("failed to parse existing json: %w", err)
		}
	}
	if current == nil {
		current = map[string]any{}
	}
	var patch map[string]any
	if err := json.Unmarshal([]byte(content), &patch); err != nil {
		return fmt.Errorf("invalid merge json: %w", err)
	}
	merged := recursiveJSONMerge(current, patch)
	rendered, err := json.MarshalIndent(merged, "", "    ")
	if err != nil {
		return err
	}
	rendered = append(rendered, '\n')
	return writeAtomically(targetPath, rendered)
}

func (f *JSONMergeFormat) Postchecks() []string {
	return []string{"json_parse", "json_merge_verify"}
}
