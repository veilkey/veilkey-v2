package tui

import (
	"encoding/json"
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type sshModel struct {
	keys    []sshKeyItem
	cursor  int
	loaded  bool
	err     string
	confirm bool
}

type sshKeyItem struct {
	Ref       string `json:"ref"`
	Status    string `json:"status"`
	CreatedAt string `json:"created_at"`
}

type sshKeysLoadedMsg struct{ keys []sshKeyItem }
type sshKeyDeletedMsg struct{}

func newSSHModel() sshModel { return sshModel{} }

func loadSSHKeysCmd(c *Client) tea.Cmd {
	return func() tea.Msg {
		result, err := c.getJSON("/api/ssh/keys")
		if err != nil {
			return errMsg{err}
		}
		raw, _ := json.Marshal(result["ssh_keys"])
		var keys []sshKeyItem
		json.Unmarshal(raw, &keys)
		return sshKeysLoadedMsg{keys: keys}
	}
}

func deleteSSHKeyCmd(c *Client, ref string) tea.Cmd {
	return func() tea.Msg {
		if err := c.deleteJSON("/api/ssh/keys/" + ref); err != nil {
			return errMsg{err}
		}
		return sshKeyDeletedMsg{}
	}
}

func (m sshModel) update(msg tea.Msg, c *Client) (sshModel, tea.Cmd) {
	switch msg := msg.(type) {
	case errMsg:
		m.err = msg.err.Error()
		m.loaded = true
	case sshKeysLoadedMsg:
		m.keys = msg.keys
		m.loaded = true
		m.err = ""
		m.cursor = 0
	case sshKeyDeletedMsg:
		m.confirm = false
		return m, loadSSHKeysCmd(c)
	case tea.KeyMsg:
		switch msg.String() {
		case "r":
			if !m.confirm {
				return m, loadSSHKeysCmd(c)
			}
		case "up", "k":
			if !m.confirm && m.cursor > 0 {
				m.cursor--
			}
		case "down", "j":
			if !m.confirm && m.cursor < len(m.keys)-1 {
				m.cursor++
			}
		case "d":
			if !m.confirm && len(m.keys) > 0 {
				m.confirm = true
			}
		case "y":
			if m.confirm && len(m.keys) > 0 && m.cursor < len(m.keys) {
				ref := m.keys[m.cursor].Ref
				m.confirm = false
				return m, deleteSSHKeyCmd(c, ref)
			}
		case "n", "esc":
			if m.confirm {
				m.confirm = false
			}
		}
	}
	return m, nil
}

func (m sshModel) view(width int) string {
	var b strings.Builder
	title := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("15")).Render(T("ssh.title"))
	b.WriteString(title + "\n\n")
	if m.err != "" {
		b.WriteString(styleError.Render("Error: "+m.err) + "\n")
	}
	if !m.loaded {
		b.WriteString("  " + T("common.loading") + "\n")
		return b.String()
	}
	if len(m.keys) == 0 {
		b.WriteString("  " + T("ssh.empty") + "\n\n  " + T("ssh.add_hint") + "\n")
		return b.String()
	}
	header := fmt.Sprintf("  %-24s %-10s %-20s", "REF", "STATUS", "CREATED")
	b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("8")).Render(header) + "\n")
	sepLen := width - 4
	if sepLen > 56 { sepLen = 56 }
	if sepLen < 0 { sepLen = 0 }
	b.WriteString("  " + strings.Repeat("\u2500", sepLen) + "\n")
	for i, key := range m.keys {
		prefix := "  "
		if i == m.cursor { prefix = "> " }
		ss := lipgloss.NewStyle().Foreground(lipgloss.Color("2"))
		if key.Status != "active" { ss = lipgloss.NewStyle().Foreground(lipgloss.Color("8")) }
		line := fmt.Sprintf("%s%-24s %s  %-20s", prefix, key.Ref, ss.Render(fmt.Sprintf("%-8s", key.Status)), key.CreatedAt)
		if i == m.cursor { line = lipgloss.NewStyle().Bold(true).Render(line) }
		b.WriteString(line + "\n")
	}
	b.WriteString("\n")
	if m.confirm {
		ref := ""
		if m.cursor < len(m.keys) { ref = m.keys[m.cursor].Ref }
		b.WriteString("  " + styleError.Render(fmt.Sprintf(T("ssh.confirm_delete"), ref)) + "\n")
	} else {
		b.WriteString("  " + lipgloss.NewStyle().Foreground(lipgloss.Color("8")).Render(T("ssh.help")) + "\n")
	}
	return b.String()
}
