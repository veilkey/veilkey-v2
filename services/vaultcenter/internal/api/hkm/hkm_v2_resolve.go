package hkm

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	chain "github.com/veilkey/veilkey-chain"
	"github.com/veilkey/veilkey-go-package/crypto"
)

// resolveV2PathRef handles v2 path-based ref resolution.
// Ref format: "VK:{vault}/{group}/{key}" or "{vault}/{group}/{key}"
// Flow: parse path -> find agent by vault_name -> fetch ciphertext from LocalVault -> decrypt -> return plaintext
func (h *Handler) resolveV2PathRef(w http.ResponseWriter, r *http.Request, ref string) {
	if strings.Contains(ref, "..") || strings.ContainsAny(ref, "\x00\n\r") {
		respondError(w, http.StatusBadRequest, "invalid ref format")
		return
	}

	// Strip VK: prefix if present
	pathPart := ref
	if strings.HasPrefix(ref, "VK:") {
		pathPart = ref[3:]
	}

	parsed, err := parseV2Path(pathPart)
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid v2 path: "+err.Error())
		return
	}

	// Check TokenRef table for a tracked ref matching this path
	if tracked, err := h.deps.DB().GetRefByPath(parsed.groupKeyPath()); err == nil && tracked != nil {
		if h.resolveTrackedRef(w, ref, tracked) {
			return
		}
	}

	// Look up agent by vault_name
	agent, err := h.deps.DB().GetAgentByVaultName(parsed.Vault)
	if err != nil {
		respondError(w, http.StatusNotFound, "vault not found: "+parsed.Vault)
		return
	}
	if err := validateAgentAvailability(agent); err != nil {
		h.respondAgentLookupError(w, err)
		return
	}

	if len(agent.DEK) == 0 {
		respondError(w, http.StatusInternalServerError, "agent has no encryption key")
		return
	}

	agentDEK, err := h.decryptAgentDEK(agent.DEK, agent.DEKNonce)
	if err != nil {
		log.Printf("v2 resolve: failed to decrypt agent DEK for vault %s: %v", parsed.Vault, err)
		respondError(w, http.StatusInternalServerError, "failed to decrypt agent key")
		return
	}

	// Fetch ciphertext from LocalVault using {group}/{key} path
	ai := agentToInfo(agent)
	cipherSecret, err := h.fetchAgentCiphertext(ai, parsed.groupKeyPath())
	if err != nil {
		respondError(w, http.StatusNotFound, "secret not found: "+parsed.groupKeyPath())
		return
	}

	plaintext, err := crypto.Decrypt(agentDEK, cipherSecret.Ciphertext, cipherSecret.Nonce)
	if err != nil {
		log.Printf("v2 resolve: decryption failed for %s: %v", ref, err)
		respondError(w, http.StatusInternalServerError, "decryption failed")
		return
	}

	resp := map[string]interface{}{
		"ref":   ref,
		"vault": agent.Label,
		"name":  cipherSecret.Name,
		"value": string(plaintext),
		"path":  parsed.groupKeyPath(),
		"group": parsed.Group,
		"key":   parsed.Key,
	}
	setRuntimeHashAliases(resp, agent.AgentHash)
	respondJSON(w, http.StatusOK, resp)

	// Audit trail
	now := time.Now().UTC()
	_ = h.deps.DB().MarkSecretCatalogRevealed(ref, now)
	afterJSON, _ := json.Marshal(map[string]any{
		"ref":                ref,
		"vault":              parsed.Vault,
		"path":               parsed.groupKeyPath(),
		"vault_runtime_hash": agent.AgentHash,
		"resolved_at":        now.Format(time.RFC3339),
	})
	_ = h.deps.SubmitTxAsync(context.Background(), chain.TxRecordAuditEvent, chain.RecordAuditEventPayload{
		EventID:    crypto.GenerateUUID(),
		EntityType: "secret",
		EntityID:   ref,
		Action:     "resolve_v2",
		ActorType:  "api",
		ActorID:    agent.AgentHash,
		Source:     "resolve",
		AfterJSON:  string(afterJSON),
	})
}
