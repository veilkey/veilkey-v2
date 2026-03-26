package api

import (
	"os"
	"strings"
	"testing"
)

// ── Bug 6: Promote must reject deleted agents ────────────────────────────────

func TestPromoteRejectsDeletedAgent(t *testing.T) {
	src, err := os.ReadFile("handle_keycenter.go")
	if err != nil {
		t.Fatalf("failed to read handle_keycenter.go: %v", err)
	}
	content := string(src)

	fnBody := extractFn(content, "func (s *Server) handleKeycenterPromoteToVault(")
	if fnBody == "" {
		t.Fatal("handleKeycenterPromoteToVault must exist")
	}

	// After FindAgentRecord, must check if agent is deleted
	findIdx := strings.Index(fnBody, "FindAgentRecord")
	if findIdx < 0 {
		t.Fatal("handleKeycenterPromoteToVault must call FindAgentRecord")
	}
	afterFind := fnBody[findIdx:]

	if !strings.Contains(afterFind, "DeletedAt") {
		t.Error("handleKeycenterPromoteToVault must check agent.DeletedAt after FindAgentRecord")
	}

	// Must reject deleted agents
	if !strings.Contains(afterFind, "deleted") || !strings.Contains(afterFind, "agent") {
		t.Error("handleKeycenterPromoteToVault must reject promoting to a deleted agent")
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// Bug 7: Promote must send agent_secret Bearer token to LocalVault
//
// Root cause: handleKeycenterPromoteToVault used httpClient.Post() which cannot
// set Authorization headers. LocalVault's POST /api/cipher requires agent_secret
// Bearer token via requireAgentSecret middleware.
//
// Fix: Use http.NewRequest + decryptAgentSecret + httpClient.Do, matching the
// pattern used by HKM handlers (hkm_agent_save_secret.go).
// ══════════════════════════════════════════════════════════════════════════════

// ── Regression: httpClient.Post must never be used for LV cipher calls ───────

func TestPromote_Regression_NoRawHttpClientPost(t *testing.T) {
	src, err := os.ReadFile("handle_keycenter.go")
	if err != nil {
		t.Fatalf("failed to read handle_keycenter.go: %v", err)
	}

	fnBody := extractFn(string(src), "func (s *Server) handleKeycenterPromoteToVault(")
	if fnBody == "" {
		t.Fatal("handleKeycenterPromoteToVault must exist")
	}

	// httpClient.Post cannot set custom headers — must never appear in promote
	if strings.Contains(fnBody, "httpClient.Post(") {
		t.Error("REGRESSION: promote must not use httpClient.Post — it cannot set Authorization header; use http.NewRequest + httpClient.Do instead")
	}

	// Also guard against http.Post (global function)
	if strings.Contains(fnBody, "http.Post(") {
		t.Error("REGRESSION: promote must not use http.Post — it cannot set Authorization header")
	}
}

// ── Request construction ─────────────────────────────────────────────────────

func TestPromote_UsesNewRequest(t *testing.T) {
	src, err := os.ReadFile("handle_keycenter.go")
	if err != nil {
		t.Fatalf("failed to read handle_keycenter.go: %v", err)
	}

	fnBody := extractFn(string(src), "func (s *Server) handleKeycenterPromoteToVault(")
	if fnBody == "" {
		t.Fatal("handleKeycenterPromoteToVault must exist")
	}

	if !strings.Contains(fnBody, "http.NewRequest") {
		t.Error("promote must use http.NewRequest to build the LV request")
	}

	if !strings.Contains(fnBody, "httpClient.Do(") {
		t.Error("promote must use httpClient.Do to execute the constructed request")
	}
}

func TestPromote_UsesMethodPost(t *testing.T) {
	src, err := os.ReadFile("handle_keycenter.go")
	if err != nil {
		t.Fatalf("failed to read handle_keycenter.go: %v", err)
	}

	fnBody := extractFn(string(src), "func (s *Server) handleKeycenterPromoteToVault(")
	if fnBody == "" {
		t.Fatal("handleKeycenterPromoteToVault must exist")
	}

	if !strings.Contains(fnBody, "http.MethodPost") {
		t.Error("promote must use http.MethodPost for the LV cipher request")
	}
}

func TestPromote_TargetsCipherEndpoint(t *testing.T) {
	src, err := os.ReadFile("handle_keycenter.go")
	if err != nil {
		t.Fatalf("failed to read handle_keycenter.go: %v", err)
	}

	fnBody := extractFn(string(src), "func (s *Server) handleKeycenterPromoteToVault(")
	if fnBody == "" {
		t.Fatal("handleKeycenterPromoteToVault must exist")
	}

	if !strings.Contains(fnBody, "/api/cipher") {
		t.Error("promote must target /api/cipher endpoint on LocalVault")
	}
}

// ── Authentication header ────────────────────────────────────────────────────

func TestPromote_SetsAuthorizationBearerHeader(t *testing.T) {
	src, err := os.ReadFile("handle_keycenter.go")
	if err != nil {
		t.Fatalf("failed to read handle_keycenter.go: %v", err)
	}

	fnBody := extractFn(string(src), "func (s *Server) handleKeycenterPromoteToVault(")
	if fnBody == "" {
		t.Fatal("handleKeycenterPromoteToVault must exist")
	}

	if !strings.Contains(fnBody, `"Authorization"`) {
		t.Error("promote must set the Authorization header on the LV request")
	}
	if !strings.Contains(fnBody, `"Bearer "`) {
		t.Error("promote must use Bearer scheme for the Authorization header")
	}
}

func TestPromote_DecryptsAgentSecretFromRecord(t *testing.T) {
	src, err := os.ReadFile("handle_keycenter.go")
	if err != nil {
		t.Fatalf("failed to read handle_keycenter.go: %v", err)
	}

	fnBody := extractFn(string(src), "func (s *Server) handleKeycenterPromoteToVault(")
	if fnBody == "" {
		t.Fatal("handleKeycenterPromoteToVault must exist")
	}

	if !strings.Contains(fnBody, "decryptAgentSecret") {
		t.Error("promote must call decryptAgentSecret to obtain the agent's Bearer token")
	}

	if !strings.Contains(fnBody, "AgentSecretEnc") {
		t.Error("promote must pass agent.AgentSecretEnc to decryptAgentSecret")
	}
	if !strings.Contains(fnBody, "AgentSecretNonce") {
		t.Error("promote must pass agent.AgentSecretNonce to decryptAgentSecret")
	}
}

func TestPromote_AuthHeaderSetBeforeDoCall(t *testing.T) {
	src, err := os.ReadFile("handle_keycenter.go")
	if err != nil {
		t.Fatalf("failed to read handle_keycenter.go: %v", err)
	}

	fnBody := extractFn(string(src), "func (s *Server) handleKeycenterPromoteToVault(")
	if fnBody == "" {
		t.Fatal("handleKeycenterPromoteToVault must exist")
	}

	// Authorization must be set BEFORE httpClient.Do
	authIdx := strings.Index(fnBody, `"Authorization"`)
	doIdx := strings.Index(fnBody, "httpClient.Do(")
	if authIdx < 0 || doIdx < 0 {
		t.Fatal("both Authorization header and httpClient.Do must exist")
	}
	if authIdx > doIdx {
		t.Error("Authorization header must be set BEFORE httpClient.Do is called")
	}
}

func TestPromote_ContentTypeSetBeforeDoCall(t *testing.T) {
	src, err := os.ReadFile("handle_keycenter.go")
	if err != nil {
		t.Fatalf("failed to read handle_keycenter.go: %v", err)
	}

	fnBody := extractFn(string(src), "func (s *Server) handleKeycenterPromoteToVault(")
	if fnBody == "" {
		t.Fatal("handleKeycenterPromoteToVault must exist")
	}

	ctIdx := strings.Index(fnBody, `"Content-Type"`)
	doIdx := strings.Index(fnBody, "httpClient.Do(")
	if ctIdx < 0 || doIdx < 0 {
		t.Fatal("both Content-Type header and httpClient.Do must exist")
	}
	if ctIdx > doIdx {
		t.Error("Content-Type header must be set BEFORE httpClient.Do is called")
	}
}

// ── Security: promote must not leak agent secret ─────────────────────────────

func TestPromote_NoAgentSecretInErrorResponse(t *testing.T) {
	src, err := os.ReadFile("handle_keycenter.go")
	if err != nil {
		t.Fatalf("failed to read handle_keycenter.go: %v", err)
	}

	fnBody := extractFn(string(src), "func (s *Server) handleKeycenterPromoteToVault(")
	if fnBody == "" {
		t.Fatal("handleKeycenterPromoteToVault must exist")
	}

	// respondError must never include agentSecret variable in error message
	for _, line := range strings.Split(fnBody, "\n") {
		if strings.Contains(line, "respondError") && strings.Contains(line, "agentSecret") {
			t.Error("promote must not leak agentSecret value in error responses")
		}
	}
}

func TestPromote_NoAgentSecretInLog(t *testing.T) {
	src, err := os.ReadFile("handle_keycenter.go")
	if err != nil {
		t.Fatalf("failed to read handle_keycenter.go: %v", err)
	}

	fnBody := extractFn(string(src), "func (s *Server) handleKeycenterPromoteToVault(")
	if fnBody == "" {
		t.Fatal("handleKeycenterPromoteToVault must exist")
	}

	// log.Printf must never include agentSecret
	for _, line := range strings.Split(fnBody, "\n") {
		if strings.Contains(line, "log.") && strings.Contains(line, "agentSecret") {
			t.Error("promote must not log the agentSecret value")
		}
	}
}

// ── Structural: promote must match HKM handler pattern ───────────────────────

func TestPromote_MatchesHKMSaveSecretPattern(t *testing.T) {
	// The promote handler must follow the same auth pattern as HKM's handleAgentSaveSecret:
	// 1. http.NewRequest(MethodPost, url, body)
	// 2. Header.Set("Content-Type", ...)
	// 3. setAgentAuth / decryptAgentSecret + Header.Set("Authorization", ...)
	// 4. httpClient.Do(req)

	src, err := os.ReadFile("handle_keycenter.go")
	if err != nil {
		t.Fatalf("failed to read handle_keycenter.go: %v", err)
	}

	fnBody := extractFn(string(src), "func (s *Server) handleKeycenterPromoteToVault(")
	if fnBody == "" {
		t.Fatal("handleKeycenterPromoteToVault must exist")
	}

	// Verify correct ordering: NewRequest → Content-Type → Authorization → Do
	newReqIdx := strings.Index(fnBody, "http.NewRequest")
	ctIdx := strings.Index(fnBody, `"Content-Type"`)
	authIdx := strings.Index(fnBody, `"Authorization"`)
	doIdx := strings.Index(fnBody, "httpClient.Do(")

	if newReqIdx < 0 {
		t.Fatal("missing http.NewRequest")
	}
	if ctIdx < 0 {
		t.Fatal("missing Content-Type header set")
	}
	if authIdx < 0 {
		t.Fatal("missing Authorization header set")
	}
	if doIdx < 0 {
		t.Fatal("missing httpClient.Do call")
	}

	if newReqIdx > ctIdx {
		t.Error("http.NewRequest must come before Content-Type header set")
	}
	if ctIdx > authIdx {
		t.Error("Content-Type must be set before Authorization (matching HKM pattern)")
	}
	if authIdx > doIdx {
		t.Error("Authorization must be set before httpClient.Do")
	}
}

// ── Request body content ─────────────────────────────────────────────────────

func TestPromote_CipherBodyIncludesScope(t *testing.T) {
	src, err := os.ReadFile("handle_keycenter.go")
	if err != nil {
		t.Fatalf("failed to read handle_keycenter.go: %v", err)
	}

	fnBody := extractFn(string(src), "func (s *Server) handleKeycenterPromoteToVault(")
	if fnBody == "" {
		t.Fatal("handleKeycenterPromoteToVault must exist")
	}

	// Body sent to LV must include scope field
	if !strings.Contains(fnBody, `"scope"`) {
		t.Error("cipher body must include scope field")
	}
	if !strings.Contains(fnBody, `"LOCAL"`) {
		t.Error("promote cipher body must set scope to LOCAL")
	}
}

func TestPromote_CipherBodyIncludesRequiredFields(t *testing.T) {
	src, err := os.ReadFile("handle_keycenter.go")
	if err != nil {
		t.Fatalf("failed to read handle_keycenter.go: %v", err)
	}

	fnBody := extractFn(string(src), "func (s *Server) handleKeycenterPromoteToVault(")
	if fnBody == "" {
		t.Fatal("handleKeycenterPromoteToVault must exist")
	}

	for _, field := range []string{`"name"`, `"ciphertext"`, `"nonce"`} {
		if !strings.Contains(fnBody, field) {
			t.Errorf("cipher body must include %s field", field)
		}
	}
}

// ── Error handling ───────────────────────────────────────────────────────────

func TestPromote_HandlesNewRequestError(t *testing.T) {
	src, err := os.ReadFile("handle_keycenter.go")
	if err != nil {
		t.Fatalf("failed to read handle_keycenter.go: %v", err)
	}

	fnBody := extractFn(string(src), "func (s *Server) handleKeycenterPromoteToVault(")
	if fnBody == "" {
		t.Fatal("handleKeycenterPromoteToVault must exist")
	}

	// After http.NewRequest, must check and handle error
	reqIdx := strings.Index(fnBody, "http.NewRequest")
	if reqIdx < 0 {
		t.Fatal("missing http.NewRequest")
	}
	after := fnBody[reqIdx:]
	// Must have error check before Do call
	errIdx := strings.Index(after, "err != nil")
	doIdx := strings.Index(after, "httpClient.Do(")
	if errIdx < 0 || doIdx < 0 {
		t.Fatal("must have error check and Do call after NewRequest")
	}
	if errIdx > doIdx {
		t.Error("must check http.NewRequest error before calling httpClient.Do")
	}
}

func TestPromote_ClosesResponseBody(t *testing.T) {
	src, err := os.ReadFile("handle_keycenter.go")
	if err != nil {
		t.Fatalf("failed to read handle_keycenter.go: %v", err)
	}

	fnBody := extractFn(string(src), "func (s *Server) handleKeycenterPromoteToVault(")
	if fnBody == "" {
		t.Fatal("handleKeycenterPromoteToVault must exist")
	}

	if !strings.Contains(fnBody, "defer resp.Body.Close()") {
		t.Error("promote must defer resp.Body.Close() to avoid resource leak")
	}
}

// ── decryptAgentSecret helper on Server ──────────────────────────────────────

func TestServerHasDecryptAgentSecret(t *testing.T) {
	src, err := os.ReadFile("api.go")
	if err != nil {
		t.Fatalf("failed to read api.go: %v", err)
	}
	content := string(src)

	fnBody := extractFn(content, "func (s *Server) decryptAgentSecret(")
	if fnBody == "" {
		t.Fatal("Server must have a decryptAgentSecret method")
	}

	if !strings.Contains(fnBody, "GetKEK()") {
		t.Error("decryptAgentSecret must use GetKEK() to obtain the KEK")
	}

	if !strings.Contains(fnBody, "crypto.Decrypt") {
		t.Error("decryptAgentSecret must call crypto.Decrypt")
	}

	if !strings.Contains(fnBody, `return ""`) {
		t.Error("decryptAgentSecret must return empty string when encSecret is empty or on error")
	}
}

func TestDecryptAgentSecret_GuardsEmptyInput(t *testing.T) {
	src, err := os.ReadFile("api.go")
	if err != nil {
		t.Fatalf("failed to read api.go: %v", err)
	}

	fnBody := extractFn(string(src), "func (s *Server) decryptAgentSecret(")
	if fnBody == "" {
		t.Fatal("decryptAgentSecret must exist")
	}

	// Must check len(encSecret) == 0 before attempting decryption
	lenIdx := strings.Index(fnBody, "len(encSecret)")
	decryptIdx := strings.Index(fnBody, "crypto.Decrypt")
	if lenIdx < 0 {
		t.Error("decryptAgentSecret must check len(encSecret) for empty input")
	}
	if decryptIdx < 0 {
		t.Fatal("decryptAgentSecret must call crypto.Decrypt")
	}
	if lenIdx > decryptIdx {
		t.Error("empty input check must come BEFORE crypto.Decrypt call")
	}
}

func TestDecryptAgentSecret_ReturnsStringNotBytes(t *testing.T) {
	src, err := os.ReadFile("api.go")
	if err != nil {
		t.Fatalf("failed to read api.go: %v", err)
	}

	fnBody := extractFn(string(src), "func (s *Server) decryptAgentSecret(")
	if fnBody == "" {
		t.Fatal("decryptAgentSecret must exist")
	}

	// Must convert decrypted bytes to string for use in Bearer header
	if !strings.Contains(fnBody, "string(plaintext)") && !strings.Contains(fnBody, "string(decrypted)") {
		t.Error("decryptAgentSecret must convert decrypted bytes to string")
	}
}

func TestDecryptAgentSecret_ConsistentWithHKMHandler(t *testing.T) {
	// Server.decryptAgentSecret must be semantically identical to hkm.Handler.decryptAgentSecret
	serverSrc, err := os.ReadFile("api.go")
	if err != nil {
		t.Fatalf("failed to read api.go: %v", err)
	}
	hkmSrc, err := os.ReadFile("hkm/hkm_agent_common.go")
	if err != nil {
		t.Fatalf("failed to read hkm/hkm_agent_common.go: %v", err)
	}

	serverFn := extractFn(string(serverSrc), "func (s *Server) decryptAgentSecret(")
	hkmFn := extractFn(string(hkmSrc), "func (h *Handler) decryptAgentSecret(")

	if serverFn == "" {
		t.Fatal("Server.decryptAgentSecret must exist")
	}
	if hkmFn == "" {
		t.Fatal("hkm.Handler.decryptAgentSecret must exist")
	}

	// Both must use crypto.Decrypt
	if !strings.Contains(serverFn, "crypto.Decrypt") {
		t.Error("Server.decryptAgentSecret must use crypto.Decrypt")
	}
	if !strings.Contains(hkmFn, "crypto.Decrypt") {
		t.Error("hkm.Handler.decryptAgentSecret must use crypto.Decrypt")
	}

	// Both must guard empty input
	if !strings.Contains(serverFn, "len(encSecret)") {
		t.Error("Server.decryptAgentSecret must guard empty encSecret")
	}
	if !strings.Contains(hkmFn, "len(encSecret)") {
		t.Error("hkm.Handler.decryptAgentSecret must guard empty encSecret")
	}

	// Both must return empty string on failure
	serverReturns := strings.Count(serverFn, `return ""`)
	hkmReturns := strings.Count(hkmFn, `return ""`)
	if serverReturns < 2 {
		t.Errorf("Server.decryptAgentSecret must return empty string on both empty input and error (found %d)", serverReturns)
	}
	if hkmReturns < 2 {
		t.Errorf("hkm.Handler.decryptAgentSecret must return empty string on both empty input and error (found %d)", hkmReturns)
	}
}
