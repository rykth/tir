package ui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

type statusItem struct {
	key   string
	value string
}

func (t Theme) renderStatusBar(width int, items []statusItem, hints []string, warning string) string {
	var left strings.Builder
	for i, it := range items {
		if i > 0 {
			left.WriteString("  ")
		}
		left.WriteString(t.StatusKey.Render(it.key))
		left.WriteString(" ")
		left.WriteString(t.StatusValue.Render(it.value))
	}

	var right strings.Builder
	if warning != "" {
		right.WriteString(t.StatusWarn.Render(warning))
		right.WriteString("  ")
	}
	for i, h := range hints {
		if i > 0 {
			right.WriteString("  ")
		}
		right.WriteString(t.StatusHint.Render(h))
	}

	leftStr := left.String()
	rightStr := right.String()

	gap := max(1, width-lipgloss.Width(leftStr)-lipgloss.Width(rightStr))
	return t.StatusBar.Width(width).Render(leftStr + strings.Repeat(" ", gap) + rightStr)
}
