package commands

import (
	"os"
	"path/filepath"
	"strings"
)

func readDataDirPassword(dataDir string) string {
	path := filepath.Join(dataDir, "password")
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}
