package api

import (
	_ "embed"
	"net/http"
)

//go:embed admin_vue_preview.html
var adminVuePreviewHTML string

func (s *Server) handleAdminVuePreview(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if body, ok := devUIIndex(); ok {
		_, _ = w.Write(body)
		return
	}
	if body, ok := embeddedUIIndex(); ok {
		_, _ = w.Write(body)
		return
	}
	_, _ = w.Write([]byte(adminVuePreviewHTML))
}
