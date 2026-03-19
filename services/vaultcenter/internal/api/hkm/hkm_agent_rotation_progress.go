package hkm

import (
	"context"
	"net/http"
	"time"

	chain "github.com/veilkey/veilkey-chain"
)

func (h *Handler) advancePendingRotationsBestEffort() {
	h.advancePendingRotationsViaChain(nil)
}

// advancePendingRotationsViaChain iterates agents and submits individual
// TxUpdateAgentState for each agent needing retry advancement.
func (h *Handler) advancePendingRotationsViaChain(r *http.Request) {
	now := time.Now().UTC()
	agents, err := h.deps.DB().ListAgents()
	if err != nil {
		return
	}
	var ctx context.Context
	if r != nil {
		ctx = r.Context()
	} else {
		ctx = context.Background()
	}
	for _, agent := range agents {
		if !agent.RotationRequired || agent.BlockedAt != nil {
			continue
		}
		if agent.NextRetryAt != nil && agent.NextRetryAt.After(now) {
			continue
		}
		payload := advancePendingRotationPayload(agent.NodeID, agent.RetryStage, now)
		_, _ = h.deps.SubmitTx(ctx, chain.TxUpdateAgentState, payload)
	}
}
