package ui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

func (t Theme) helpView() string {
	groups := [][]struct{ keys, desc string }{
		{
			{"q", "Quit (press twice to confirm)"},
			{"Ctrl+C", "Quit immediately"},
		},
		{
			{"Tab / Shift+Tab", "Switch tabs"},
			{"↑/k  ↓/j", "Move up / down"},
			{"g / G", "First / last row"},
			{"PgUp / PgDn", "Page up / down (also Ctrl+B / Ctrl+F)"},
			{"Enter", "Open details for selected connection"},
			{"Esc", "Leave details / clear filter"},
		},
		{
			{"s", "Cycle sort column"},
			{"S", "Reverse sort direction"},
			{"d", "Toggle hostnames / IP addresses"},
			{"i", "Toggle Interfaces tab"},
		},
		{
			{"/", "Enter filter mode (port:, sni:, process:, …)"},
			{"?", "Toggle this help screen"},
		},
	}

	var b strings.Builder
	b.WriteString(t.Title.Render("Keyboard Controls"))
	b.WriteString("\n\n")

	keyStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("39")).Bold(true)
	descStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("250"))

	for gi, group := range groups {
		if gi > 0 {
			b.WriteString("\n")
		}
		for _, item := range group {
			b.WriteString("  ")
			b.WriteString(keyStyle.Render(padRight(item.keys, 20)))
			b.WriteString("  ")
			b.WriteString(descStyle.Render(item.desc))
			b.WriteString("\n")
		}
	}

	b.WriteString("\n")
	b.WriteString(t.TableDim.Render("More features land in later phases"))

	return b.String()
}

func (t Theme) placeholderView(name string) string {
	body := lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render(
		name + " tab is not yet implemented.",
	)
	return t.Title.Render(name) + "\n\n" + body
}
