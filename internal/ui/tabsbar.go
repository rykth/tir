package ui

import "strings"

func (t Theme) renderTabs(labels []string, active int) string {
	parts := make([]string, 0, len(labels)*2)
	for i, label := range labels {
		style := t.TabInactive
		if i == active {
			style = t.TabActive
		}
		parts = append(parts, style.Render(label))
		if i < len(labels)-1 {
			parts = append(parts, t.TabSeparator.Render("│"))
		}
	}
	return strings.Join(parts, "")
}
