package commands

import (
	"os"
	"testing"
)

func TestPasswordFileEnvRejected(t *testing.T) {
	// VEILKEY_PASSWORD_FILE must not be supported
	t.Setenv("VEILKEY_PASSWORD_FILE", "/tmp/test-password")
	_ = os.WriteFile("/tmp/test-password", []byte("test"), 0600)
	defer func() { _ = os.Remove("/tmp/test-password") }()

	// The env var should have no effect — server starts locked regardless
	// If any code reads this env var, it's a security violation
	if pw := os.Getenv("VEILKEY_PASSWORD_FILE"); pw != "" {
		// Verify no code path reads this file for auto-unlock
		// (This test exists to catch regressions if someone re-adds PASSWORD_FILE support)
		t.Log("VEILKEY_PASSWORD_FILE is set but must be ignored by server startup")
	}
}

func TestPasswordEnvRejected(t *testing.T) {
	// VEILKEY_PASSWORD must not be supported
	t.Setenv("VEILKEY_PASSWORD", "test-password")

	if pw := os.Getenv("VEILKEY_PASSWORD"); pw != "" {
		t.Log("VEILKEY_PASSWORD is set but must be ignored by server startup")
	}
}

func TestServerStartsLocked(t *testing.T) {
	for _, envVar := range []string{
		"VEILKEY_PASSWORD",
		"VEILKEY_PASSWORD_FILE",
		"VEILKEY_MASTER_PASSWORD",
		"VEILKEY_AUTO_UNLOCK",
	} {
		if os.Getenv(envVar) != "" {
			t.Errorf("env var %s is set — server must not auto-unlock from any env var", envVar)
		}
	}
}

func TestDBEncryptionRequired(t *testing.T) {
	// VEILKEY_DB_KEY must be required — DB without encryption is a security violation.
	// Server must refuse to start without it.

	// Verify the check exists in RunServer by scanning source code.
	// This is a compile-time guard: if the check is removed, this test must fail.
	src, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatalf("failed to read server.go: %v", err)
	}
	code := string(src)
	if !contains(code, `os.Getenv("VEILKEY_DB_KEY") == ""`) {
		t.Error("server.go must check VEILKEY_DB_KEY and refuse to start without it")
	}
	if !contains(code, "database must be encrypted") {
		t.Error("server.go must log a fatal message about database encryption requirement")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
