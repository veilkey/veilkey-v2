package commands

import (
	"time"

	"github.com/veilkey/veilkey-go-package/cmdutil"
)

func readPasswordFromFileEnv() string {
	return cmdutil.ReadPasswordFromFileEnv()
}

func readPassword(prompt string) string {
	return cmdutil.ReadPassword(prompt)
}

func parseDurationEnv(key string, defaultVal time.Duration) time.Duration {
	return cmdutil.ParseDurationEnv(key, defaultVal)
}

func generateInitRef(length int) (string, error) {
	return cmdutil.GenerateHexRef(length)
}
