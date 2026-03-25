package hkm

import (
	"net/http"

	"veilkey-vaultcenter/internal/db"
)

func (h *Handler) handleSSHKeys(w http.ResponseWriter, r *http.Request) {
	refs, err := h.deps.DB().ListRefsByScope(db.RefScopeSSH)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to list SSH keys")
		return
	}

	type sshKeyEntry struct {
		Ref       string `json:"ref"`
		Status    string `json:"status"`
		CreatedAt string `json:"created_at"`
	}

	entries := make([]sshKeyEntry, 0, len(refs))
	for _, ref := range refs {
		if string(ref.Status) != string(db.RefStatusActive) {
			continue
		}
		entries = append(entries, sshKeyEntry{
			Ref:       ref.RefCanonical,
			Status:    string(ref.Status),
			CreatedAt: ref.CreatedAt.Format("2006-01-02 15:04:05"),
		})
	}

	respondJSON(w, http.StatusOK, map[string]any{
		"ssh_keys": entries,
		"count":    len(entries),
	})
}

func (h *Handler) handleSSHKeyDelete(w http.ResponseWriter, r *http.Request) {
	ref := r.PathValue("ref")
	if ref == "" {
		respondError(w, http.StatusBadRequest, "ref is required")
		return
	}

	existing, err := h.deps.DB().GetRef(ref)
	if err != nil {
		respondError(w, http.StatusNotFound, "SSH key not found")
		return
	}
	if existing.RefScope != db.RefScopeSSH {
		respondError(w, http.StatusBadRequest, "ref is not an SSH key")
		return
	}

	if err := h.deps.DB().DeleteRef(ref); err != nil {
		respondError(w, http.StatusInternalServerError, "failed to delete SSH key")
		return
	}

	respondJSON(w, http.StatusOK, map[string]any{
		"deleted": ref,
	})
}
