package hkm

import (
	"fmt"
	"net/http"
	"time"
	"veilkey-vaultcenter/internal/db"
	"veilkey-vaultcenter/internal/httputil"
)

func (h *Handler) handleAgentList(w http.ResponseWriter, r *http.Request) {
	h.advancePendingRotationsBestEffort()

	var agents []db.Agent
	var err error
	if r.URL.Query().Get("include_archived") == "true" {
		agents, err = h.deps.DB().ListAgentsIncludeArchived()
	} else {
		agents, err = h.deps.DB().ListAgents()
	}
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to list agents")
		return
	}

	type agentResp struct {
		NodeID           string   `json:"node_id"`
		VaultNodeUUID    string   `json:"vault_node_uuid"`
		Label            string   `json:"label"`
		VaultRuntimeHash string   `json:"vault_runtime_hash"`
		AgentHash        string   `json:"agent_hash"`
		VaultHash        string   `json:"vault_hash"`
		VaultName        string   `json:"vault_name"`
		VaultID          string   `json:"vault_id"`
		ManagedPaths     []string `json:"managed_paths"`
		KeyVersion       int      `json:"key_version"`
		Status           string   `json:"status"`
		Health           string   `json:"health"`
		LastSeenAgo      string   `json:"last_seen_ago"`
		RotationRequired bool     `json:"rotation_required"`
		RebindRequired   bool     `json:"rebind_required"`
		RetryStage       int      `json:"retry_stage"`
		NextRetryAt      string   `json:"next_retry_at,omitempty"`
		Blocked          bool     `json:"blocked"`
		BlockReason      string   `json:"block_reason,omitempty"`
		Archived         bool     `json:"archived"`
		IP               string   `json:"ip"`
		Port             int      `json:"port"`
		SecretsCount     int      `json:"secrets_count"`
		ConfigsCount     int      `json:"configs_count"`
		Version          int      `json:"version"`
		HasDEK           bool     `json:"has_dek"`
		LastSeen         string   `json:"last_seen"`
	}

	now := time.Now().UTC()
	var result []agentResp
	for _, a := range agents {
		status := "ok"
		if a.BlockedAt != nil {
			status = "blocked"
		} else if a.RotationRequired {
			status = "rotation_required"
		} else if a.RebindRequired {
			status = "rebind_required"
		}

		// Health based on last_seen
		health := "healthy"
		sinceLastSeen := now.Sub(a.LastSeen)
		if a.ArchivedAt != nil {
			health = "archived"
		} else if sinceLastSeen > 7*24*time.Hour {
			health = "unreachable"
		} else if sinceLastSeen > 10*time.Minute {
			health = "stale"
		}

		lastSeenAgo := formatDuration(sinceLastSeen)

		nextRetryAt := ""
		if a.NextRetryAt != nil {
			nextRetryAt = a.NextRetryAt.UTC().Format(time.RFC3339)
		}
		result = append(result, agentResp{
			NodeID:           a.NodeID,
			VaultNodeUUID:    a.NodeID,
			Label:            a.Label,
			VaultRuntimeHash: a.AgentHash,
			AgentHash:        a.AgentHash,
			VaultHash:        a.VaultHash,
			VaultName:        a.VaultName,
			VaultID:          httputil.FormatVaultID(a.VaultName, a.VaultHash),
			ManagedPaths:     db.DecodeManagedPaths(a.ManagedPaths),
			KeyVersion:       a.KeyVersion,
			Status:           status,
			Health:           health,
			LastSeenAgo:      lastSeenAgo,
			RotationRequired: a.RotationRequired,
			RebindRequired:   a.RebindRequired,
			RetryStage:       a.RetryStage,
			NextRetryAt:      nextRetryAt,
			Blocked:          a.BlockedAt != nil,
			BlockReason:      a.BlockReason,
			Archived:         a.ArchivedAt != nil,
			IP:               a.IP,
			Port:             a.Port,
			SecretsCount:     a.SecretsCount,
			ConfigsCount:     a.ConfigsCount,
			Version:          a.Version,
			HasDEK:           len(a.DEK) > 0,
			LastSeen:         a.LastSeen.Format("2006-01-02 15:04:05"),
		})
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"agents": result,
		"count":  len(result),
	})
}

func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
	return fmt.Sprintf("%dd", int(d.Hours()/24))
}
