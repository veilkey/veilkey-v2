package hkm

import (
	"net/http"
	"strings"

	"github.com/veilkey/veilkey-go-package/crypto"
)

func (h *Handler) handleAgentResolve(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	if token == "" {
		respondError(w, http.StatusBadRequest, "token is required")
		return
	}

	// v2 path-based resolution: token contains "/" (e.g. "host-lv/owner/password")
	if strings.Contains(token, "/") {
		h.handleAgentResolveV2(w, token)
		return
	}

	// v1 hash-based resolution: first 8 chars = agentHash, rest = secretRef
	h.handleAgentResolveV1(w, token)
}

// handleAgentResolveV1 resolves a secret using the v1 hash-based token format.
// Token format: {8-char agentHash}{secretRef}
func (h *Handler) handleAgentResolveV1(w http.ResponseWriter, token string) {
	if len(token) <= 8 {
		respondError(w, http.StatusBadRequest, "invalid token format: too short")
		return
	}

	agentHash := token[:8]
	secretRef := token[8:]

	agent, err := h.deps.DB().GetAgentByHash(agentHash)
	if err != nil {
		respondError(w, http.StatusNotFound, "agent not found for hash: "+agentHash)
		return
	}
	if err := validateAgentAvailability(agent); err != nil {
		h.respondAgentLookupError(w, err)
		return
	}

	agentDEK, err := h.decryptAgentDEK(agent.DEK, agent.DEKNonce)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to decrypt agent DEK")
		return
	}

	ai := agentToInfo(agent)
	cipherSecret, err := h.fetchAgentCiphertext(ai, secretRef)
	if err != nil {
		respondError(w, http.StatusNotFound, "failed to fetch secret from agent")
		return
	}

	plaintext, err := crypto.Decrypt(agentDEK, cipherSecret.Ciphertext, cipherSecret.Nonce)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "decryption failed")
		return
	}

	resp := map[string]any{
		"ref":   secretRef,
		"vault": agent.Label,
		"name":  cipherSecret.Name,
		"value": string(plaintext),
	}
	setRuntimeHashAliases(resp, agentHash)
	respondJSON(w, http.StatusOK, resp)
}

// handleAgentResolveV2 resolves a secret using the v2 path-based token format.
// Token format: {vault}/{group}/{key} (e.g. "host-lv/owner/password")
// TODO: This shares the vault lookup → DEK decrypt → cipher fetch → decrypt flow
// with resolveTrackedRef in hkm_resolve_secret.go. Consider extracting a shared
// helper if either path changes.
func (h *Handler) handleAgentResolveV2(w http.ResponseWriter, token string) {
	parsed, err := parseV2Path(token)
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	agent, err := h.deps.DB().GetAgentByVaultName(parsed.Vault)
	if err != nil {
		respondError(w, http.StatusNotFound, "vault not found: "+parsed.Vault)
		return
	}
	if err := validateAgentAvailability(agent); err != nil {
		h.respondAgentLookupError(w, err)
		return
	}

	agentDEK, err := h.decryptAgentDEK(agent.DEK, agent.DEKNonce)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to decrypt agent DEK")
		return
	}

	ai := agentToInfo(agent)
	cipherSecret, err := h.fetchAgentCiphertext(ai, parsed.groupKeyPath())
	if err != nil {
		respondError(w, http.StatusNotFound, "secret not found: "+parsed.groupKeyPath())
		return
	}

	plaintext, err := crypto.Decrypt(agentDEK, cipherSecret.Ciphertext, cipherSecret.Nonce)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "decryption failed")
		return
	}

	resp := map[string]any{
		"ref":   token,
		"vault": parsed.Vault,
		"group": parsed.Group,
		"key":   parsed.Key,
		"path":  parsed.groupKeyPath(),
		"name":  cipherSecret.Name,
		"value": string(plaintext),
	}
	setRuntimeHashAliases(resp, agent.AgentHash)
	respondJSON(w, http.StatusOK, resp)
}
