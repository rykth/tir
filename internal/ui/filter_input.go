package ui

import (
	tea "github.com/charmbracelet/bubbletea"
)

type filterInput struct {
	value  string
	active bool
}

// Active reports whether the input has focus
func (i filterInput) Active() bool {
	return i.active
}

// Value returns the current text
func (i filterInput) Value() string {
	return i.value
}

// Activate starts capturing keystrokes
func (i *filterInput) Activate() {
	i.active = true
}

// Deactivate hides the cursor but keeps the value
func (i *filterInput) Deactivate() {
	i.active = false
}

// Clear erases the value and deactivates
func (i *filterInput) Clear() {
	i.value = ""
	i.active = false
}

// HandleKey applies a key event (returns true if the key was consumed and the
// value "potentially" changed)
func (i *filterInput) HandleKey(msg tea.KeyMsg) (changed bool) {
	switch msg.Type {
	case tea.KeyRunes, tea.KeySpace:
		runes := msg.Runes
		if msg.Type == tea.KeySpace {
			runes = []rune{' '}
		}
		i.value += string(runes)
		return true
	case tea.KeyBackspace:
		if i.value != "" {
			// drop the last rune (not byte) to handle utf-8 cleanly
			r := []rune(i.value)
			i.value = string(r[:len(r)-1])
			return true
		}
	case tea.KeyCtrlU:
		if i.value != "" {
			i.value = ""
			return true
		}
	}
	return false
}

// View renders the input bar at the given width
func (i filterInput) View(width int, theme Theme) string {
	cursor := ""
	if i.active {
		cursor = "█"
	}
	body := "/" + i.value + theme.StatusKey.Render(cursor)
	return theme.StatusBar.Width(width).Render(body)
}
