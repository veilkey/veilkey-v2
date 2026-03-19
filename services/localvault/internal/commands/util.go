package commands

import (
	"os"
	"strings"

	"github.com/veilkey/veilkey-go-package/cmdutil"
	"veilkey-localvault/internal/db"
)

func readPasswordFromFileEnv() string {
	return cmdutil.ReadPasswordFromFileEnv()
}

func readPassword(prompt string) string {
	return cmdutil.ReadPassword(prompt)
}

func ensureVaultIdentity(database *db.DB, nodeID string) (string, string, error) {
	vaultHash := ""
	if cfg, err := database.GetConfig("VAULT_HASH"); err == nil {
		vaultHash = strings.TrimSpace(cfg.Value)
	}
	if vaultHash == "" {
		vaultHash = defaultVaultHash(nodeID)
		if err := database.SaveConfig("VAULT_HASH", vaultHash); err != nil {
			return "", "", err
		}
	}

	vaultName := ""
	if cfg, err := database.GetConfig("VAULT_NAME"); err == nil {
		vaultName = strings.TrimSpace(cfg.Value)
	}
	if vaultName == "" {
		vaultName = strings.TrimSpace(os.Getenv("VEILKEY_VAULT_NAME"))
		if vaultName == "" {
			vaultName, _ = os.Hostname()
		}
		if vaultName == "" {
			vaultName = "localvault"
		}
		if err := database.SaveConfig("VAULT_NAME", vaultName); err != nil {
			return "", "", err
		}
	}

	return vaultHash, vaultName, nil
}

func defaultVaultHash(nodeID string) string {
	normalized := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(nodeID)), "-", "")
	if len(normalized) >= 8 {
		return normalized[:8]
	}
	if normalized != "" {
		return normalized
	}
	return "unknown"
}
