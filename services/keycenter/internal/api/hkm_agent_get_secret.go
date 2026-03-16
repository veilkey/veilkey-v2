package api

import (
	"net/http"
	"veilkey-keycenter/internal/crypto"
)

func (s *Server) handleAgentGetSecret(w http.ResponseWriter, r *http.Request) {
	hashOrLabel := r.PathValue("agent")
	name := r.PathValue("name")

	agent, err := s.findAgent(hashOrLabel)
	if err != nil {
		s.respondAgentLookupError(w, err)
		return
	}

	agentDEK, err := s.decryptAgentDEK(agent.DEK, agent.DEKNonce)
	if err != nil {
		s.respondError(w, http.StatusInternalServerError, "failed to decrypt agent DEK")
		return
	}

	agentURL := agent.URL()
	meta, status, body, err := s.fetchAgentSecretMeta(agentURL, name)
	if err != nil {
		s.respondError(w, http.StatusBadGateway, "agent unreachable: "+err.Error())
		return
	}
	if status != http.StatusOK {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		w.Write(body)
		return
	}
	if meta == nil || meta.Ref == "" {
		s.respondError(w, http.StatusInternalServerError, "secret has no ref")
		return
	}
	if err := normalizeMeta(meta); err != nil {
		s.respondError(w, http.StatusBadGateway, "agent returned unsupported secret scope: "+err.Error())
		return
	}
	_ = s.upsertTrackedRef(meta.Token, agent.KeyVersion, meta.Status, agent.AgentHash)

	plaintextValue := ""
	cipher, err := s.fetchAgentCiphertext(agentURL, meta.Ref)
	if err == nil {
		plaintext, decErr := crypto.Decrypt(agentDEK, cipher.Ciphertext, cipher.Nonce)
		if decErr != nil {
			s.respondError(w, http.StatusInternalServerError, "decryption failed")
			return
		}
		plaintextValue = string(plaintext)
	} else {
		resolved, resolveErr := s.fetchAgentResolvedValue(agentURL, meta.Token)
		if resolveErr != nil {
			s.respondError(w, http.StatusBadGateway, "upstream unavailable")
			return
		}
		plaintextValue = resolved.Value
	}

	payload := map[string]interface{}{
		"name":         name,
		"value":        plaintextValue,
		"ref":          meta.Ref,
		"token":        meta.Token,
		"scope":        meta.Scope,
		"status":       meta.Status,
		"vault":        agent.Label,
		"fields":       meta.Fields,
		"fields_count": meta.FieldsCount,
	}
	setRuntimeHashAliases(payload, agent.AgentHash)
	s.respondJSON(w, http.StatusOK, payload)
}
