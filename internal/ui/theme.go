package ui

import (
	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
)

// Theme bundles every lipgloss.Style used by the UI
type Theme struct {
	Title lipgloss.Style

	TabActive    lipgloss.Style
	TabInactive  lipgloss.Style
	TabSeparator lipgloss.Style

	StatusBar   lipgloss.Style
	StatusKey   lipgloss.Style
	StatusValue lipgloss.Style
	StatusHint  lipgloss.Style
	StatusWarn  lipgloss.Style

	TableTitle        lipgloss.Style
	TableHeader       lipgloss.Style
	TableHeaderActive lipgloss.Style
	TableRow          lipgloss.Style
	TableRowSelected  lipgloss.Style
	TableDim          lipgloss.Style

	StateActive   lipgloss.Style
	StateStale    lipgloss.Style
	StateCritical lipgloss.Style
	StateClosed   lipgloss.Style

	ProtoTCP lipgloss.Style
	ProtoUDP lipgloss.Style

	Error lipgloss.Style
}

// NewTheme returns the default theme
//
// If forceNoColor is true, all colors are stripped regardless of the terminals
// capabilities. The NO_COLOR environment variable is honored automatically by
// lipgloss/termenv and does not need to be checked here.
func NewTheme(forceNoColor bool) Theme {
	if forceNoColor {
		lipgloss.SetColorProfile(termenv.Ascii)
	}
	return Theme{
		Title: lipgloss.NewStyle().Foreground(lipgloss.Color("39")).Bold(true),

		TabActive:    lipgloss.NewStyle().Foreground(lipgloss.Color("15")).Background(lipgloss.Color("33")).Padding(0, 1).Bold(true),
		TabInactive:  lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Padding(0, 1),
		TabSeparator: lipgloss.NewStyle().Foreground(lipgloss.Color("240")),

		StatusBar:   lipgloss.NewStyle().Foreground(lipgloss.Color("250")).Background(lipgloss.Color("236")),
		StatusKey:   lipgloss.NewStyle().Foreground(lipgloss.Color("39")).Bold(true),
		StatusValue: lipgloss.NewStyle().Foreground(lipgloss.Color("250")),
		StatusHint:  lipgloss.NewStyle().Foreground(lipgloss.Color("245")),
		StatusWarn:  lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Bold(true),

		TableTitle:        lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Italic(true),
		TableHeader:       lipgloss.NewStyle().Foreground(lipgloss.Color("250")).Bold(true),
		TableHeaderActive: lipgloss.NewStyle().Foreground(lipgloss.Color("39")).Bold(true).Underline(true),
		TableRow:          lipgloss.NewStyle(),
		TableRowSelected:  lipgloss.NewStyle().Background(lipgloss.Color("237")).Bold(true),
		TableDim:          lipgloss.NewStyle().Foreground(lipgloss.Color("245")),

		StateActive:   lipgloss.NewStyle().Foreground(lipgloss.Color("250")),
		StateStale:    lipgloss.NewStyle().Foreground(lipgloss.Color("220")),
		StateCritical: lipgloss.NewStyle().Foreground(lipgloss.Color("196")),
		StateClosed:   lipgloss.NewStyle().Foreground(lipgloss.Color("244")),

		ProtoTCP: lipgloss.NewStyle().Foreground(lipgloss.Color("33")),
		ProtoUDP: lipgloss.NewStyle().Foreground(lipgloss.Color("141")),

		Error: lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true),
	}
}
