package hkm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"veilkey-vaultcenter/internal/db"

	chain "github.com/veilkey/veilkey-chain"
	"github.com/veilkey/veilkey-go-package/crypto"
)

// redirectTransport rewrites all outgoing requests to the test server URL,
// preserving the original path and query. This is needed because the handler
// constructs URLs like http://127.0.0.1:{agentPort}/cipher/... but we need
// them routed to the httptest server.
type redirectTransport struct {
	target *url.URL
	inner  http.RoundTripper
}

func (t *redirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req2 := req.Clone(req.Context())
	req2.URL.Scheme = t.target.Scheme
	req2.URL.Host = t.target.Host
	return t.inner.RoundTrip(req2)
}

// ── Test infrastructure ─────────────────────────────────────────────────────

type stubDeps struct {
	database   *db.DB
	kek        []byte
	httpClient *http.Client
}

func (s *stubDeps) DB() *db.DB                          { return s.database }
func (s *stubDeps) HTTPClient() *http.Client             { return s.httpClient }
func (s *stubDeps) GetKEK() []byte                       { return s.kek }
func (s *stubDeps) GetLocalDEK() ([]byte, error)         { return nil, nil }
func (s *stubDeps) CascadeResolveTimeout() time.Duration { return 5 * time.Second }
func (s *stubDeps) ParentForwardTimeout() time.Duration  { return 5 * time.Second }
func (s *stubDeps) DeployTimeout() time.Duration         { return 5 * time.Second }
func (s *stubDeps) IsTrustedIPString(ip string) bool     { return true }
func (s *stubDeps) SubmitTx(_ context.Context, _ chain.TxType, _ any) (string, error) {
	return "", nil
}
func (s *stubDeps) SubmitTxAsync(_ context.Context, _ chain.TxType, _ any) error { return nil }
func (s *stubDeps) ChainInfo() ([]byte, string)                                  { return nil, "" }
func (s *stubDeps) MaskMapVersion() uint64                                       { return 0 }
func (s *stubDeps) MaskMapWait() <-chan struct{}                                 { return nil }
func (s *stubDeps) InvalidateMaskCache()                                         {}
func (s *stubDeps) SetMaskCacheData(_ []byte)                                    {}
func (s *stubDeps) GetMaskCacheData() []byte                                     { return nil }
func (s *stubDeps) BumpMaskMapVersion()                                          {}

type testHarness struct {
	handler  *Handler
	kek      []byte
	agentDEK []byte
	agentSrv *httptest.Server
	database *db.DB
}

func newTestHarness(t *testing.T) *testHarness {
	t.Helper()
	t.Setenv("VEILKEY_AGENT_SCHEME", "http")

	database, err := db.New(":memory:")
	if err != nil {
		t.Fatalf("new db: %v", err)
	}
	kek, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate KEK: %v", err)
	}
	agentDEK, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("generate agent DEK: %v", err)
	}
	return &testHarness{kek: kek, agentDEK: agentDEK, database: database}
}

func (th *testHarness) encryptDEK(t *testing.T) ([]byte, []byte) {
	t.Helper()
	enc, nonce, err := crypto.Encrypt(th.kek, th.agentDEK)
	if err != nil {
		t.Fatalf("encrypt DEK: %v", err)
	}
	return enc, nonce
}

func (th *testHarness) encryptSecret(t *testing.T, plaintext string) ([]byte, []byte) {
	t.Helper()
	enc, nonce, err := crypto.Encrypt(th.agentDEK, []byte(plaintext))
	if err != nil {
		t.Fatalf("encrypt secret: %v", err)
	}
	return enc, nonce
}

func (th *testHarness) startAgentServer(t *testing.T, secretMap map[string]string) {
	t.Helper()
	th.agentSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		const prefix = "/api/cipher/"
		if len(path) <= len(prefix) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		ref := path[len(prefix):]
		plaintext, ok := secretMap[ref]
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		ct, nonce := th.encryptSecret(t, plaintext)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"name":       "secret-" + ref,
			"ciphertext": ct,
			"nonce":      nonce,
		})
	}))
	t.Cleanup(th.agentSrv.Close)
}

func (th *testHarness) finalize(t *testing.T) {
	t.Helper()
	deps := &stubDeps{
		database:   th.database,
		kek:        th.kek,
		httpClient: http.DefaultClient,
	}
	if th.agentSrv != nil {
		target, _ := url.Parse(th.agentSrv.URL)
		deps.httpClient = &http.Client{
			Transport: &redirectTransport{
				target: target,
				inner:  th.agentSrv.Client().Transport,
			},
		}
	}
	th.handler = NewHandler(deps)
}

func (th *testHarness) insertAgent(t *testing.T, hash, vaultName, label string, blocked bool, rebind bool) {
	t.Helper()
	ip := "127.0.0.1"
	port := 0
	if th.agentSrv != nil {
		u := th.agentSrv.URL
		for i := len(u) - 1; i >= 0; i-- {
			if u[i] == ':' {
				fmt.Sscanf(u[i+1:], "%d", &port)
				break
			}
		}
	}
	nodeID := "node-" + hash
	if err := th.database.UpsertAgent(nodeID, label, "vh-"+hash, vaultName, ip, port, 0, 0, 1, 1, ""); err != nil {
		t.Fatalf("upsert agent: %v", err)
	}
	encDEK, encNonce := th.encryptDEK(t)
	if err := th.database.UpdateAgentDEK(nodeID, hash, encDEK, encNonce); err != nil {
		t.Fatalf("update agent DEK: %v", err)
	}
	if blocked || rebind {
		now := time.Now()
		rebindTrue := true
		reason := "test-reason"
		u := &db.AgentStatePartialUpdate{}
		if rebind {
			u.RebindRequired = &rebindTrue
			u.RebindReason = &reason
		}
		if blocked {
			u.SetBlockedAt = true
			u.BlockedAt = &now
			u.BlockReason = &reason
		}
		if err := th.database.UpdateAgentStatePartial(nodeID, u); err != nil {
			t.Fatalf("update agent state: %v", err)
		}
	}
}

func (th *testHarness) callResolve(t *testing.T, token string) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	noop := func(h http.HandlerFunc) http.HandlerFunc { return h }
	th.handler.Register(mux, noop, noop, noop)
	req := httptest.NewRequest(http.MethodGet, "/api/resolve-agent/"+token, nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func parseResp(t *testing.T, rec *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	var data map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&data); err != nil {
		t.Fatalf("decode response: %v (body: %s)", err, rec.Body.String())
	}
	return data
}

// ── V1: hash-based resolve ──────────────────────────────────────────────────

func TestV1Resolve_HappyPath(t *testing.T) {
	th := newTestHarness(t)
	th.startAgentServer(t, map[string]string{"secret123": "my-password-42"})
	th.finalize(t)
	th.insertAgent(t, "abcd1234", "test-vault", "Test Vault", false, false)

	rec := th.callResolve(t, "abcd1234secret123")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	data := parseResp(t, rec)
	if data["ref"] != "secret123" {
		t.Errorf("ref = %v, want secret123", data["ref"])
	}
	if data["value"] != "my-password-42" {
		t.Errorf("value = %v, want my-password-42", data["value"])
	}
	if data["vault"] != "Test Vault" {
		t.Errorf("vault = %v, want Test Vault", data["vault"])
	}
	if data["vault_runtime_hash"] != "abcd1234" {
		t.Errorf("vault_runtime_hash = %v, want abcd1234", data["vault_runtime_hash"])
	}
	if data["agent_hash"] != "abcd1234" {
		t.Errorf("agent_hash = %v, want abcd1234", data["agent_hash"])
	}
}

func TestV1Resolve_TokenTooShort(t *testing.T) {
	th := newTestHarness(t)
	th.finalize(t)
	rec := th.callResolve(t, "abc")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestV1Resolve_TokenExactly8Chars(t *testing.T) {
	th := newTestHarness(t)
	th.finalize(t)
	rec := th.callResolve(t, "abcd1234")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestV1Resolve_AgentNotFound(t *testing.T) {
	th := newTestHarness(t)
	th.finalize(t)
	rec := th.callResolve(t, "deadbeefmyref123")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestV1Resolve_AgentBlocked(t *testing.T) {
	th := newTestHarness(t)
	th.startAgentServer(t, nil)
	th.finalize(t)
	th.insertAgent(t, "abcd1234", "test-vault", "Test Vault", true, false)
	rec := th.callResolve(t, "abcd1234secret123")
	if rec.Code != http.StatusLocked {
		t.Fatalf("expected 423, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestV1Resolve_AgentRebindRequired(t *testing.T) {
	th := newTestHarness(t)
	th.startAgentServer(t, nil)
	th.finalize(t)
	th.insertAgent(t, "abcd1234", "test-vault", "Test Vault", false, true)
	rec := th.callResolve(t, "abcd1234secret123")
	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestV1Resolve_SecretNotFoundOnAgent(t *testing.T) {
	th := newTestHarness(t)
	th.startAgentServer(t, map[string]string{})
	th.finalize(t)
	th.insertAgent(t, "abcd1234", "test-vault", "Test Vault", false, false)
	rec := th.callResolve(t, "abcd1234nonexistent")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestV1Resolve_DEKDecryptionFailure(t *testing.T) {
	th := newTestHarness(t)
	th.startAgentServer(t, map[string]string{"ref1": "val"})
	th.finalize(t)
	th.insertAgent(t, "abcd1234", "test-vault", "Test Vault", false, false)
	badKEK, _ := crypto.GenerateKey()
	badEncDEK, badNonce, _ := crypto.Encrypt(badKEK, th.agentDEK)
	if err := th.database.UpdateAgentDEK("node-abcd1234", "abcd1234", badEncDEK, badNonce); err != nil {
		t.Fatal(err)
	}
	rec := th.callResolve(t, "abcd1234ref1")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", rec.Code, rec.Body.String())
	}
}

// ── V2: path-based resolve ──────────────────────────────────────────────────

func TestV2Resolve_HappyPath(t *testing.T) {
	th := newTestHarness(t)
	th.startAgentServer(t, map[string]string{"owner/api-key": "super-secret-value"})
	th.finalize(t)
	th.insertAgent(t, "abcd1234", "host-lv", "Host LV", false, false)

	rec := th.callResolve(t, "host-lv/owner/api-key")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	data := parseResp(t, rec)
	if data["vault"] != "host-lv" {
		t.Errorf("vault = %v, want host-lv", data["vault"])
	}
	if data["group"] != "owner" {
		t.Errorf("group = %v, want owner", data["group"])
	}
	if data["key"] != "api-key" {
		t.Errorf("key = %v, want api-key", data["key"])
	}
	if data["path"] != "owner/api-key" {
		t.Errorf("path = %v, want owner/api-key", data["path"])
	}
	if data["value"] != "super-secret-value" {
		t.Errorf("value = %v, want super-secret-value", data["value"])
	}
	if data["vault_runtime_hash"] != "abcd1234" {
		t.Errorf("vault_runtime_hash = %v, want abcd1234", data["vault_runtime_hash"])
	}
}

func TestV2Resolve_VaultNotFound(t *testing.T) {
	th := newTestHarness(t)
	th.startAgentServer(t, nil)
	th.finalize(t)
	rec := th.callResolve(t, "nonexistent/group/key")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestV2Resolve_AgentBlocked(t *testing.T) {
	th := newTestHarness(t)
	th.startAgentServer(t, nil)
	th.finalize(t)
	th.insertAgent(t, "abcd1234", "host-lv", "Host LV", true, false)
	rec := th.callResolve(t, "host-lv/owner/api-key")
	if rec.Code != http.StatusLocked {
		t.Fatalf("expected 423, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestV2Resolve_AgentRebindRequired(t *testing.T) {
	th := newTestHarness(t)
	th.startAgentServer(t, nil)
	th.finalize(t)
	th.insertAgent(t, "abcd1234", "host-lv", "Host LV", false, true)
	rec := th.callResolve(t, "host-lv/owner/api-key")
	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestV2Resolve_SecretNotFound(t *testing.T) {
	th := newTestHarness(t)
	th.startAgentServer(t, map[string]string{})
	th.finalize(t)
	th.insertAgent(t, "abcd1234", "host-lv", "Host LV", false, false)
	rec := th.callResolve(t, "host-lv/owner/missing-key")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestV2Resolve_DEKDecryptionFailure(t *testing.T) {
	th := newTestHarness(t)
	th.startAgentServer(t, map[string]string{"g/k": "val"})
	th.finalize(t)
	th.insertAgent(t, "abcd1234", "host-lv", "Host LV", false, false)
	badKEK, _ := crypto.GenerateKey()
	badEnc, badNonce, _ := crypto.Encrypt(badKEK, th.agentDEK)
	th.database.UpdateAgentDEK("node-abcd1234", "abcd1234", badEnc, badNonce)
	rec := th.callResolve(t, "host-lv/g/k")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestV2Resolve_InvalidPathTooFewSegments(t *testing.T) {
	th := newTestHarness(t)
	th.finalize(t)
	rec := th.callResolve(t, "only-two/segments")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestV2Resolve_InvalidPathBadSegmentChars(t *testing.T) {
	th := newTestHarness(t)
	th.finalize(t)
	// Segment with leading hyphen is rejected by v2PathSegmentPattern
	rec := th.callResolve(t, "vault/-group/key")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

// ── Security ────────────────────────────────────────────────────────────────

func TestSecurity_V2PathTraversal(t *testing.T) {
	th := newTestHarness(t)
	th.finalize(t)
	cases := []string{"../etc/passwd", "vault/../secret/key", "vault/group/..%2f..%2fetc"}
	for _, token := range cases {
		rec := th.callResolve(t, token)
		if rec.Code == http.StatusOK {
			t.Errorf("path traversal token %q should not return 200", token)
		}
	}
}

func TestSecurity_V2UppercaseSegmentsRejected(t *testing.T) {
	th := newTestHarness(t)
	th.finalize(t)
	rec := th.callResolve(t, "Vault/Group/Key")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestSecurity_V2SpecialCharsRejected(t *testing.T) {
	th := newTestHarness(t)
	th.finalize(t)
	for _, token := range []string{"vault/group/key$HOME", "vault/group/key{test}", "vault/group/key<script>"} {
		rec := th.callResolve(t, token)
		if rec.Code == http.StatusOK {
			t.Errorf("special char token %q should not return 200", token)
		}
	}
}

func TestSecurity_V1TamperedCiphertext(t *testing.T) {
	th := newTestHarness(t)
	wrongDEK, _ := crypto.GenerateKey()
	th.agentSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ct, nonce, _ := crypto.Encrypt(wrongDEK, []byte("tampered"))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"name": "tampered", "ciphertext": ct, "nonce": nonce})
	}))
	t.Cleanup(th.agentSrv.Close)
	th.finalize(t)
	th.insertAgent(t, "abcd1234", "test-vault", "Test Vault", false, false)
	rec := th.callResolve(t, "abcd1234myref")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 for tampered ciphertext, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestSecurity_V2TamperedCiphertext(t *testing.T) {
	th := newTestHarness(t)
	wrongDEK, _ := crypto.GenerateKey()
	th.agentSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ct, nonce, _ := crypto.Encrypt(wrongDEK, []byte("tampered"))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"name": "tampered", "ciphertext": ct, "nonce": nonce})
	}))
	t.Cleanup(th.agentSrv.Close)
	th.finalize(t)
	th.insertAgent(t, "abcd1234", "host-lv", "Host LV", false, false)
	rec := th.callResolve(t, "host-lv/owner/api-key")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 for tampered ciphertext, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestSecurity_AgentUnreachable(t *testing.T) {
	th := newTestHarness(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	th.agentSrv = srv
	th.finalize(t)
	th.insertAgent(t, "abcd1234", "test-vault", "Test Vault", false, false)
	srv.Close()
	rec := th.callResolve(t, "abcd1234myref")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unreachable agent, got %d: %s", rec.Code, rec.Body.String())
	}
}

// ── Dispatch ────────────────────────────────────────────────────────────────

func TestResolve_DispatchV1VsV2(t *testing.T) {
	th := newTestHarness(t)
	th.startAgentServer(t, map[string]string{"secret123": "v1-value", "owner/api-key": "v2-value"})
	th.finalize(t)
	th.insertAgent(t, "abcd1234", "host-lv", "Host LV", false, false)

	recV1 := th.callResolve(t, "abcd1234secret123")
	if recV1.Code != http.StatusOK {
		t.Fatalf("V1: expected 200, got %d: %s", recV1.Code, recV1.Body.String())
	}
	if parseResp(t, recV1)["value"] != "v1-value" {
		t.Errorf("V1 value mismatch")
	}

	recV2 := th.callResolve(t, "host-lv/owner/api-key")
	if recV2.Code != http.StatusOK {
		t.Fatalf("V2: expected 200, got %d: %s", recV2.Code, recV2.Body.String())
	}
	if parseResp(t, recV2)["value"] != "v2-value" {
		t.Errorf("V2 value mismatch")
	}
}
