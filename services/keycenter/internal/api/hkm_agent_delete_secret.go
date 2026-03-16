package api

import (
	"io"
	"net/http"
	"strings"
)

func (s *Server) handleAgentDeleteSecret(w http.ResponseWriter, r *http.Request) {
	hashOrLabel := r.PathValue("agent")
	name := r.PathValue("name")

	agent, err := s.findAgent(hashOrLabel)
	if err != nil {
		s.respondAgentLookupError(w, err)
		return
	}

	var trackedRef string
	meta, status, _, err := s.fetchAgentSecretMeta(agent.URL(), name)
	if err == nil && status == http.StatusOK && meta != nil && meta.Ref != "" {
		if err := normalizeMeta(meta); err == nil {
			trackedRef = meta.Token
		}
	}

	req, _ := http.NewRequest("DELETE", agent.URL()+"/api/secrets/"+name, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		s.respondError(w, http.StatusBadGateway, "agent unreachable: "+err.Error())
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusOK && trackedRef != "" {
		_ = s.deleteTrackedRef(trackedRef)
		if metaRefParts := strings.Split(trackedRef, ":"); len(metaRefParts) == 3 {
			_ = s.deleteTrackedRef("VK:TEMP:" + metaRefParts[2])
		}
		s.saveAuditEvent(
			"secret",
			trackedRef,
			"delete",
			"agent",
			agent.AgentHash,
			"",
			"agent_delete_secret",
			map[string]any{
				"name": trackedRef,
				"ref":  trackedRef,
			},
			map[string]any{
				"name": name,
			},
		)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	w.Write(body)
}
