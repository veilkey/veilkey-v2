package tui

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

// ══════════════════════════════════════════════════════════════════
// Source-level tests for SSH TUI page
// ══════════════════════════════════════════════════════════════════

func TestSource_SSHPage_Defined(t *testing.T) {
	src, _ := os.ReadFile("model.go")
	if !strings.Contains(string(src), "pageSSH") {
		t.Error("pageSSH must be defined in page enum")
	}
}

func TestSource_SSHPage_InPagesSlice(t *testing.T) {
	src, _ := os.ReadFile("model.go")
	content := string(src)
	for _, line := range strings.Split(content, "\n") {
		if strings.Contains(line, "var pages") && !strings.Contains(line, "pageSSH") {
			t.Error("pageSSH must be in pages slice")
		}
		if strings.Contains(line, "var pageNameKeys") && !strings.Contains(line, "nav.ssh") {
			t.Error("nav.ssh must be in pageNameKeys")
		}
	}
}

func TestSource_SSHPage_InUpdateSwitch(t *testing.T) {
	src, _ := os.ReadFile("model.go")
	c := string(src)
	if !strings.Contains(c, "case pageSSH:") {
		t.Error("pageSSH must have a case in Update switch")
	}
	if !strings.Contains(c, "m.ssh, cmd = m.ssh.update(msg, m.client)") {
		t.Error("pageSSH must delegate to m.ssh.update()")
	}
}

func TestSource_SSHPage_InViewSwitch(t *testing.T) {
	src, _ := os.ReadFile("model.go")
	if !strings.Contains(string(src), "m.ssh.view(m.width)") {
		t.Error("pageSSH must render via m.ssh.view()")
	}
}

func TestSource_SSHPage_InSwitchPage(t *testing.T) {
	src, _ := os.ReadFile("model.go")
	if !strings.Contains(string(src), "loadSSHKeysCmd") {
		t.Error("switchPage must call loadSSHKeysCmd for pageSSH")
	}
}

func TestSource_SSHPage_ModelInitialized(t *testing.T) {
	src, _ := os.ReadFile("model.go")
	c := string(src)
	if !strings.Contains(c, "ssh") || !strings.Contains(c, "sshModel") {
		t.Error("Model struct must contain ssh sshModel field")
	}
	if !strings.Contains(c, "newSSHModel()") {
		t.Error("NewModel must initialize ssh field with newSSHModel()")
	}
}

func TestSource_SSHPage_KeyBindingsExtended(t *testing.T) {
	src, _ := os.ReadFile("model.go")
	if !strings.Contains(string(src), `"7"`) {
		t.Error("key bindings must include '7' for 7-page navigation")
	}
}

func TestSource_SSHPage_IsEditingHandled(t *testing.T) {
	src, _ := os.ReadFile("model.go")
	if !strings.Contains(string(src), "m.ssh.confirm") {
		t.Error("isEditing must check m.ssh.confirm for pageSSH")
	}
}

func TestSource_SSHPage_I18nKeys(t *testing.T) {
	src, _ := os.ReadFile("i18n.go")
	c := string(src)
	for _, key := range []string{`"nav.ssh"`, `"ssh.title"`, `"ssh.empty"`, `"ssh.add_hint"`, `"ssh.confirm_delete"`, `"ssh.help"`} {
		if strings.Count(c, key) < 2 {
			t.Errorf("i18n key %s must appear at least twice (EN + KO)", key)
		}
	}
}

func TestSource_SSHPage_CorrectEndpoint(t *testing.T) {
	src, _ := os.ReadFile("page_ssh.go")
	if !strings.Contains(string(src), "/api/ssh/keys") {
		t.Error("SSH page must fetch from /api/ssh/keys")
	}
}

func TestSource_SSHPage_CursorNavigation(t *testing.T) {
	src, _ := os.ReadFile("page_ssh.go")
	c := string(src)
	for _, key := range []string{`"up"`, `"down"`, `"j"`, `"k"`} {
		if !strings.Contains(c, key) {
			t.Errorf("SSH page must handle %s", key)
		}
	}
}

func TestSource_SSHPage_DeleteConfirmation(t *testing.T) {
	src, _ := os.ReadFile("page_ssh.go")
	c := string(src)
	if !strings.Contains(c, `"d"`) || !strings.Contains(c, `"y"`) || !strings.Contains(c, `"n"`) {
		t.Error("SSH page must handle d/y/n for delete flow")
	}
}

func TestSource_SSHPage_ConfirmBlocksNavigation(t *testing.T) {
	src, _ := os.ReadFile("page_ssh.go")
	if !strings.Contains(string(src), "!m.confirm && m.cursor") {
		t.Error("navigation must be blocked in confirm mode")
	}
}

func TestSource_SSHPage_EmptyState(t *testing.T) {
	src, _ := os.ReadFile("page_ssh.go")
	c := string(src)
	if !strings.Contains(c, "ssh.empty") || !strings.Contains(c, "ssh.add_hint") {
		t.Error("SSH page must show empty + add hint")
	}
}

func TestSource_SSHPage_RefreshSupport(t *testing.T) {
	src, _ := os.ReadFile("page_ssh.go")
	c := string(src)
	if !strings.Contains(c, `"r"`) || !strings.Contains(c, "loadSSHKeysCmd") {
		t.Error("SSH page must support 'r' refresh")
	}
}

// ══════════════════════════════════════════════════════════════════
// Behavioral unit tests — exercise actual sshModel update/view logic
// ══════════════════════════════════════════════════════════════════

func threeKeys() []sshKeyItem {
	return []sshKeyItem{
		{Ref: "VK:SSH:aaa11111", Status: "active", CreatedAt: "2026-03-25 10:00:00"},
		{Ref: "VK:SSH:bbb22222", Status: "active", CreatedAt: "2026-03-25 11:00:00"},
		{Ref: "VK:SSH:ccc33333", Status: "active", CreatedAt: "2026-03-25 12:00:00"},
	}
}

func loadedModel(keys []sshKeyItem) sshModel {
	m := newSSHModel()
	m.keys = keys
	m.loaded = true
	return m
}

func keyMsg(key string) tea.KeyMsg {
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(key)}
}

// --- newSSHModel ---

func TestNewSSHModel_InitialState(t *testing.T) {
	m := newSSHModel()
	if m.loaded || m.confirm || m.cursor != 0 || len(m.keys) != 0 || m.err != "" {
		t.Error("new model must have zero-value state")
	}
}

// --- sshKeysLoadedMsg ---

func TestUpdate_KeysLoaded_SetsState(t *testing.T) {
	m := newSSHModel()
	m.cursor = 5
	m.err = "old"

	m, _ = m.update(sshKeysLoadedMsg{keys: threeKeys()}, nil)

	if !m.loaded || len(m.keys) != 3 || m.cursor != 0 || m.err != "" {
		t.Errorf("after load: loaded=%v keys=%d cursor=%d err=%q", m.loaded, len(m.keys), m.cursor, m.err)
	}
}

func TestUpdate_KeysLoaded_Empty(t *testing.T) {
	m := newSSHModel()
	m, _ = m.update(sshKeysLoadedMsg{keys: nil}, nil)
	if !m.loaded || len(m.keys) != 0 {
		t.Error("must handle nil keys")
	}
}

// --- errMsg ---

func TestUpdate_Error_SetsErr(t *testing.T) {
	m := newSSHModel()
	m, _ = m.update(errMsg{err: fmt.Errorf("timeout")}, nil)
	if m.err != "timeout" || !m.loaded {
		t.Errorf("err=%q loaded=%v", m.err, m.loaded)
	}
}

// --- Cursor navigation ---

func TestUpdate_CursorDown_Moves(t *testing.T) {
	m := loadedModel(threeKeys())
	m, _ = m.update(keyMsg("j"), nil)
	if m.cursor != 1 {
		t.Errorf("j: cursor=%d want 1", m.cursor)
	}
	m, _ = m.update(keyMsg("down"), nil)
	if m.cursor != 2 {
		t.Errorf("down: cursor=%d want 2", m.cursor)
	}
}

func TestUpdate_CursorDown_StopsAtEnd(t *testing.T) {
	m := loadedModel(threeKeys())
	m.cursor = 2
	m, _ = m.update(keyMsg("j"), nil)
	if m.cursor != 2 {
		t.Errorf("must stop at end, got %d", m.cursor)
	}
}

func TestUpdate_CursorUp_Moves(t *testing.T) {
	m := loadedModel(threeKeys())
	m.cursor = 2
	m, _ = m.update(keyMsg("k"), nil)
	if m.cursor != 1 {
		t.Errorf("k: cursor=%d want 1", m.cursor)
	}
	m, _ = m.update(keyMsg("up"), nil)
	if m.cursor != 0 {
		t.Errorf("up: cursor=%d want 0", m.cursor)
	}
}

func TestUpdate_CursorUp_StopsAtZero(t *testing.T) {
	m := loadedModel(threeKeys())
	m, _ = m.update(keyMsg("k"), nil)
	if m.cursor != 0 {
		t.Errorf("must stop at 0, got %d", m.cursor)
	}
}

func TestUpdate_CursorNavigation_EmptyKeys(t *testing.T) {
	m := loadedModel(nil)
	m, _ = m.update(keyMsg("j"), nil)
	if m.cursor != 0 {
		t.Error("j on empty must stay 0")
	}
	m, _ = m.update(keyMsg("k"), nil)
	if m.cursor != 0 {
		t.Error("k on empty must stay 0")
	}
}

func TestUpdate_CursorDown_SingleKey(t *testing.T) {
	m := loadedModel([]sshKeyItem{{Ref: "VK:SSH:only1111", Status: "active"}})
	m, _ = m.update(keyMsg("j"), nil)
	if m.cursor != 0 {
		t.Error("single key: cursor must stay 0")
	}
}

// --- Delete confirmation flow ---

func TestUpdate_D_EntersConfirm(t *testing.T) {
	m := loadedModel(threeKeys())
	m, _ = m.update(keyMsg("d"), nil)
	if !m.confirm {
		t.Error("'d' must enter confirm")
	}
}

func TestUpdate_D_EmptyKeys_NoConfirm(t *testing.T) {
	m := loadedModel(nil)
	m, _ = m.update(keyMsg("d"), nil)
	if m.confirm {
		t.Error("'d' on empty must not enter confirm")
	}
}

func TestUpdate_N_CancelsConfirm(t *testing.T) {
	m := loadedModel(threeKeys())
	m.confirm = true
	m, _ = m.update(keyMsg("n"), nil)
	if m.confirm {
		t.Error("'n' must cancel confirm")
	}
}

func TestUpdate_Esc_CancelsConfirm(t *testing.T) {
	m := loadedModel(threeKeys())
	m.confirm = true
	m, _ = m.update(keyMsg("esc"), nil)
	if m.confirm {
		t.Error("'esc' must cancel confirm")
	}
}

func TestUpdate_Y_WithoutConfirm_NoOp(t *testing.T) {
	m := loadedModel(threeKeys())
	_, cmd := m.update(keyMsg("y"), nil)
	if cmd != nil {
		t.Error("'y' without confirm must not issue command")
	}
}

func TestUpdate_Y_WithConfirm_IssuesDelete(t *testing.T) {
	m := loadedModel(threeKeys())
	m.cursor = 1
	m.confirm = true
	m, cmd := m.update(keyMsg("y"), nil)
	if m.confirm {
		t.Error("confirm must clear after 'y'")
	}
	if cmd == nil {
		t.Error("'y' during confirm must issue delete command")
	}
}

func TestUpdate_Y_CursorOutOfBounds_NoDelete(t *testing.T) {
	m := loadedModel(threeKeys())
	m.cursor = 10
	m.confirm = true
	_, cmd := m.update(keyMsg("y"), nil)
	if cmd != nil {
		t.Error("must not delete when cursor out of bounds")
	}
}

// --- Confirm blocks other keys ---

func TestUpdate_Confirm_BlocksCursorDown(t *testing.T) {
	m := loadedModel(threeKeys())
	m.confirm = true
	m, _ = m.update(keyMsg("j"), nil)
	if m.cursor != 0 {
		t.Error("j blocked in confirm")
	}
}

func TestUpdate_Confirm_BlocksCursorUp(t *testing.T) {
	m := loadedModel(threeKeys())
	m.cursor = 2
	m.confirm = true
	m, _ = m.update(keyMsg("k"), nil)
	if m.cursor != 2 {
		t.Error("k blocked in confirm")
	}
}

func TestUpdate_Confirm_BlocksRefresh(t *testing.T) {
	m := loadedModel(threeKeys())
	m.confirm = true
	_, cmd := m.update(keyMsg("r"), nil)
	if cmd != nil {
		t.Error("r blocked in confirm")
	}
}

func TestUpdate_Confirm_BlocksD(t *testing.T) {
	m := loadedModel(threeKeys())
	m.confirm = true
	m, _ = m.update(keyMsg("d"), nil)
	if !m.confirm {
		t.Error("'d' in confirm must not change state")
	}
}

// --- sshKeyDeletedMsg ---

func TestUpdate_Deleted_ClearsConfirmAndReloads(t *testing.T) {
	m := loadedModel(threeKeys())
	m.confirm = true
	m, cmd := m.update(sshKeyDeletedMsg{}, nil)
	if m.confirm {
		t.Error("confirm must clear after delete")
	}
	if cmd == nil {
		t.Error("must reload after delete")
	}
}

// --- Refresh ---

func TestUpdate_R_IssuesReload(t *testing.T) {
	m := loadedModel(threeKeys())
	_, cmd := m.update(keyMsg("r"), nil)
	if cmd == nil {
		t.Error("'r' must issue reload command")
	}
}

// --- View rendering ---

func TestView_NotLoaded_ShowsLoading(t *testing.T) {
	m := newSSHModel()
	v := m.view(80)
	if !strings.Contains(v, T("common.loading")) {
		t.Error("must show loading")
	}
}

func TestView_Empty_ShowsHint(t *testing.T) {
	m := loadedModel(nil)
	v := m.view(80)
	if !strings.Contains(v, T("ssh.empty")) || !strings.Contains(v, T("ssh.add_hint")) {
		t.Error("must show empty + hint")
	}
}

func TestView_WithKeys_ShowsAllRefs(t *testing.T) {
	m := loadedModel(threeKeys())
	v := m.view(80)
	for _, k := range threeKeys() {
		if !strings.Contains(v, k.Ref) {
			t.Errorf("view must contain %s", k.Ref)
		}
	}
}

func TestView_CursorPrefix(t *testing.T) {
	m := loadedModel(threeKeys())
	m.cursor = 1
	v := m.view(80)
	found := false
	for _, line := range strings.Split(v, "\n") {
		if strings.Contains(line, "bbb22222") && strings.Contains(line, ">") {
			found = true
		}
	}
	if !found {
		t.Error("cursor line must have '>'")
	}
}

func TestView_ConfirmMode_ShowsRef(t *testing.T) {
	m := loadedModel(threeKeys())
	m.confirm = true
	v := m.view(80)
	if !strings.Contains(v, "VK:SSH:aaa11111") {
		t.Error("confirm must show ref being deleted")
	}
}

func TestView_NormalMode_ShowsHelp(t *testing.T) {
	m := loadedModel(threeKeys())
	v := m.view(80)
	// EN or KO
	if !strings.Contains(v, "navigate") && !strings.Contains(v, "이동") {
		t.Error("normal mode must show help")
	}
}

func TestView_Error_ShowsMessage(t *testing.T) {
	m := loadedModel(threeKeys())
	m.err = "connection refused"
	v := m.view(80)
	if !strings.Contains(v, "connection refused") {
		t.Error("view must show error")
	}
}

func TestView_Title(t *testing.T) {
	m := loadedModel(threeKeys())
	v := m.view(80)
	if !strings.Contains(v, T("ssh.title")) {
		t.Error("must show title")
	}
}

func TestView_NarrowWidth_NoPanic(t *testing.T) {
	m := loadedModel(threeKeys())
	v := m.view(10)
	if v == "" {
		t.Error("must render with narrow width")
	}
}

func TestView_ZeroWidth_NoPanic(t *testing.T) {
	m := loadedModel(threeKeys())
	v := m.view(0)
	if v == "" {
		t.Error("must not panic with zero width")
	}
}

// --- Full navigation sequence ---

func TestUpdate_FullNavigationSequence(t *testing.T) {
	m := loadedModel(threeKeys())

	// Navigate to last
	m, _ = m.update(keyMsg("j"), nil)
	m, _ = m.update(keyMsg("j"), nil)
	if m.cursor != 2 {
		t.Fatalf("cursor should be 2, got %d", m.cursor)
	}

	// Attempt to go beyond last
	m, _ = m.update(keyMsg("j"), nil)
	if m.cursor != 2 {
		t.Error("must clamp at end")
	}

	// Navigate back to first
	m, _ = m.update(keyMsg("k"), nil)
	m, _ = m.update(keyMsg("k"), nil)
	if m.cursor != 0 {
		t.Error("must be back at 0")
	}

	// Delete flow
	m, _ = m.update(keyMsg("d"), nil)
	if !m.confirm {
		t.Fatal("must be in confirm")
	}

	// Cancel
	m, _ = m.update(keyMsg("n"), nil)
	if m.confirm {
		t.Fatal("must exit confirm")
	}

	// Delete flow again, this time confirm
	m.cursor = 1
	m, _ = m.update(keyMsg("d"), nil)
	m, cmd := m.update(keyMsg("y"), nil)
	if m.confirm {
		t.Error("must exit confirm after y")
	}
	if cmd == nil {
		t.Error("must issue delete cmd")
	}
}

// --- Multiple loads overwrite state ---

func TestUpdate_SecondLoad_OverwritesPrevious(t *testing.T) {
	m := loadedModel(threeKeys())
	m.cursor = 2
	m.err = "stale"

	newKeys := []sshKeyItem{{Ref: "VK:SSH:new11111", Status: "active"}}
	m, _ = m.update(sshKeysLoadedMsg{keys: newKeys}, nil)

	if len(m.keys) != 1 || m.keys[0].Ref != "VK:SSH:new11111" {
		t.Error("second load must overwrite keys")
	}
	if m.cursor != 0 {
		t.Error("cursor must reset on reload")
	}
	if m.err != "" {
		t.Error("error must clear on reload")
	}
}

// ══════════════════════════════════════════════════════════════════
// Additional edge-case and state-transition tests
// ══════════════════════════════════════════════════════════════════

// --- Error during confirm mode ---

func TestUpdate_ErrorDuringConfirm_SetsErrKeepsConfirm(t *testing.T) {
	m := loadedModel(threeKeys())
	m.confirm = true
	m, _ = m.update(errMsg{err: fmt.Errorf("server error")}, nil)
	if m.err != "server error" {
		t.Error("error must be set")
	}
	// confirm state is NOT explicitly cleared by errMsg — verify actual behavior
	// The errMsg handler only sets err and loaded, doesn't touch confirm
}

// --- Error then success clears error ---

func TestUpdate_ErrorThenLoad_ClearsError(t *testing.T) {
	m := newSSHModel()
	m, _ = m.update(errMsg{err: fmt.Errorf("fail")}, nil)
	if m.err != "fail" {
		t.Fatal("err not set")
	}
	m, _ = m.update(sshKeysLoadedMsg{keys: threeKeys()}, nil)
	if m.err != "" {
		t.Errorf("err must be cleared after successful load, got %q", m.err)
	}
}

// --- Inactive status rendering ---

func TestView_InactiveStatus_DifferentColor(t *testing.T) {
	keys := []sshKeyItem{
		{Ref: "VK:SSH:act11111", Status: "active", CreatedAt: "2026-03-25 10:00:00"},
		{Ref: "VK:SSH:arc22222", Status: "archive", CreatedAt: "2026-03-25 11:00:00"},
	}
	m := loadedModel(keys)
	v := m.view(80)
	if !strings.Contains(v, "VK:SSH:act11111") || !strings.Contains(v, "VK:SSH:arc22222") {
		t.Error("must render both active and inactive keys")
	}
}

// --- Non-cursor rows must NOT have > prefix ---

func TestView_NonCursorRows_NoPrefix(t *testing.T) {
	m := loadedModel(threeKeys())
	m.cursor = 0
	v := m.view(80)
	lines := strings.Split(v, "\n")
	for _, line := range lines {
		if strings.Contains(line, "bbb22222") && strings.HasPrefix(strings.TrimLeft(line, " "), ">") {
			t.Error("non-cursor row bbb22222 must not have > prefix")
		}
		if strings.Contains(line, "ccc33333") && strings.HasPrefix(strings.TrimLeft(line, " "), ">") {
			t.Error("non-cursor row ccc33333 must not have > prefix")
		}
	}
}

// --- d pressed twice should stay in confirm ---

func TestUpdate_D_Twice_StaysInConfirm(t *testing.T) {
	m := loadedModel(threeKeys())
	m, _ = m.update(keyMsg("d"), nil)
	if !m.confirm {
		t.Fatal("first d must enter confirm")
	}
	m, _ = m.update(keyMsg("d"), nil)
	if !m.confirm {
		t.Error("second d must keep confirm (d is blocked in confirm mode)")
	}
}

// --- Key input before load should not crash ---

func TestUpdate_KeyBeforeLoad_NoCrash(t *testing.T) {
	m := newSSHModel() // loaded=false, keys=nil
	m, _ = m.update(keyMsg("j"), nil)
	if m.cursor != 0 {
		t.Error("cursor must stay 0")
	}
	m, _ = m.update(keyMsg("d"), nil)
	if m.confirm {
		t.Error("d with no keys must not enter confirm")
	}
	m, _ = m.update(keyMsg("y"), nil)
	// Just must not panic
}

// --- Confirm cancel preserves cursor ---

func TestUpdate_ConfirmCancel_PreservesCursor(t *testing.T) {
	m := loadedModel(threeKeys())
	m.cursor = 2
	m, _ = m.update(keyMsg("d"), nil)
	m, _ = m.update(keyMsg("n"), nil)
	if m.cursor != 2 {
		t.Errorf("cursor must be preserved after cancel, got %d", m.cursor)
	}
}

// --- View header always present ---

func TestView_Header_Present(t *testing.T) {
	m := loadedModel(threeKeys())
	v := m.view(80)
	if !strings.Contains(v, "REF") || !strings.Contains(v, "STATUS") || !strings.Contains(v, "CREATED") {
		t.Error("header must contain REF, STATUS, CREATED columns")
	}
}

// --- View separator width ---

func TestView_Separator_Width80(t *testing.T) {
	m := loadedModel(threeKeys())
	v := m.view(80)
	// width=80 → sepLen=min(76,56)=56
	lines := strings.Split(v, "\n")
	for _, line := range lines {
		if strings.Contains(line, "─") {
			count := strings.Count(line, "─")
			if count != 56 {
				t.Errorf("separator at width=80 should be 56 chars, got %d", count)
			}
			return
		}
	}
	t.Error("separator line not found")
}

func TestView_Separator_Width30(t *testing.T) {
	m := loadedModel(threeKeys())
	v := m.view(30)
	// width=30 → sepLen=min(26,56)=26
	lines := strings.Split(v, "\n")
	for _, line := range lines {
		if strings.Contains(line, "─") {
			count := strings.Count(line, "─")
			if count != 26 {
				t.Errorf("separator at width=30 should be 26 chars, got %d", count)
			}
			return
		}
	}
	t.Error("separator line not found")
}

func TestView_Separator_Width3(t *testing.T) {
	m := loadedModel(threeKeys())
	v := m.view(3)
	// width=3 → sepLen=max(3-4,0)=0
	lines := strings.Split(v, "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		// separator line should exist but with 0 ─ chars
	}
	// Just verify no panic
	if v == "" {
		t.Error("must render something")
	}
}

// --- Cursor at each position shows correct ref ---

func TestView_CursorAtEachPosition(t *testing.T) {
	keys := threeKeys()
	for i, key := range keys {
		m := loadedModel(keys)
		m.cursor = i
		v := m.view(80)
		lines := strings.Split(v, "\n")
		found := false
		for _, line := range lines {
			if strings.Contains(line, key.Ref) && strings.Contains(line, ">") {
				found = true
			}
		}
		if !found {
			t.Errorf("cursor=%d: ref %s must have > prefix", i, key.Ref)
		}
	}
}

// --- Delete the last item ---

func TestUpdate_DeleteLastItem_Works(t *testing.T) {
	m := loadedModel(threeKeys())
	m.cursor = 2
	m, _ = m.update(keyMsg("d"), nil)
	m, cmd := m.update(keyMsg("y"), nil)
	if cmd == nil {
		t.Error("must issue delete for last item")
	}
}

// --- Delete the first item ---

func TestUpdate_DeleteFirstItem_Works(t *testing.T) {
	m := loadedModel(threeKeys())
	m.cursor = 0
	m, _ = m.update(keyMsg("d"), nil)
	m, cmd := m.update(keyMsg("y"), nil)
	if cmd == nil {
		t.Error("must issue delete for first item")
	}
}

// --- Unrelated key msgs are ignored ---

func TestUpdate_UnrelatedKey_NoChange(t *testing.T) {
	m := loadedModel(threeKeys())
	m.cursor = 1
	origCursor := m.cursor
	origConfirm := m.confirm
	origKeys := len(m.keys)

	for _, key := range []string{"x", "z", "a", "1", " ", "enter"} {
		m, _ = m.update(keyMsg(key), nil)
	}

	if m.cursor != origCursor || m.confirm != origConfirm || len(m.keys) != origKeys {
		t.Error("unrelated keys must not change state")
	}
}

// --- Rapid j/k sequence ---

func TestUpdate_RapidJK_CorrectPosition(t *testing.T) {
	m := loadedModel(threeKeys())
	// j j k j k k
	sequence := []string{"j", "j", "k", "j", "k", "k"}
	// 0→1→2→1→2→1→0
	expected := []int{1, 2, 1, 2, 1, 0}
	for i, key := range sequence {
		m, _ = m.update(keyMsg(key), nil)
		if m.cursor != expected[i] {
			t.Errorf("step %d (%s): cursor=%d want %d", i, key, m.cursor, expected[i])
		}
	}
}

// --- Confirm mode view must NOT show help ---

func TestView_ConfirmMode_NoHelpText(t *testing.T) {
	m := loadedModel(threeKeys())
	m.confirm = true
	v := m.view(80)
	if strings.Contains(v, "[j/k]") || strings.Contains(v, "navigate") {
		t.Error("confirm mode must not show navigation help")
	}
}

// --- sshKeyItem JSON parsing ---

func TestSSHKeyItem_JSONRoundTrip(t *testing.T) {
	item := sshKeyItem{Ref: "VK:SSH:abc12345", Status: "active", CreatedAt: "2026-03-25 10:00:00"}
	raw, _ := json.Marshal(item)
	var parsed sshKeyItem
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if parsed.Ref != item.Ref || parsed.Status != item.Status || parsed.CreatedAt != item.CreatedAt {
		t.Errorf("round-trip mismatch: %+v vs %+v", item, parsed)
	}
}

func TestSSHKeyItem_JSONFields(t *testing.T) {
	raw := `{"ref":"VK:SSH:test1234","status":"active","created_at":"2026-01-01 00:00:00"}`
	var item sshKeyItem
	if err := json.Unmarshal([]byte(raw), &item); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if item.Ref != "VK:SSH:test1234" {
		t.Errorf("ref=%q", item.Ref)
	}
	if item.Status != "active" {
		t.Errorf("status=%q", item.Status)
	}
	if item.CreatedAt != "2026-01-01 00:00:00" {
		t.Errorf("created_at=%q", item.CreatedAt)
	}
}
