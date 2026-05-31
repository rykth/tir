package ui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/rykth/tir/internal/conn"
)

type overviewModel struct {
	theme    Theme
	resolver Resolver      // nil-safe (used for hostname display)
	geoip    CountryLookup // nil-safe (used for country code suffix)

	rows     []conn.ConnView // current sorted snapshot
	selected int             // absolute row index
	offset   int             // first visible row index
	visible  int             // rows the viewport can hold

	sortCol  SortColumn
	sortDesc bool

	showHostnames bool

	width  int
	height int // available rows for the table body (header + body, excluding tab/status bars)
}

func newOverviewModel(theme Theme, resolver Resolver, geoip CountryLookup) overviewModel {
	col := SortBandwidth
	return overviewModel{
		theme:         theme,
		resolver:      resolver,
		geoip:         geoip,
		sortCol:       col,
		sortDesc:      col.DefaultDescending(),
		showHostnames: resolver != nil,
	}
}

// SetShowHostnames toggles whether remote addresses render as hostnames
func (m *overviewModel) SetShowHostnames(v bool) {
	m.showHostnames = v
}

// SelectedRow returns the currently highlighted row, if any
func (m *overviewModel) SelectedRow() (conn.ConnView, bool) {
	if len(m.rows) == 0 {
		return conn.ConnView{}, false
	}
	return m.rows[m.selected], true
}

// SetSize updates the viewport dimensions
//
// height is the number of rows available for the entire overview tab (title +
// header + body).
func (m *overviewModel) SetSize(width, height int) {
	m.width = width
	m.height = height
	m.visible = max(1, height-2) // 1 for title, 1 for column header
	m.clampSelection()
}

// SetRows replaces the row data and re-sorts
func (m *overviewModel) SetRows(rows []conn.ConnView) {
	m.rows = rows
	sortRows(m.rows, m.sortCol, m.sortDesc)
	m.clampSelection()
}

// CycleSort advances to the next sort column and resets to its default
// direction
func (m *overviewModel) CycleSort() {
	m.sortCol = m.sortCol.Next()
	m.sortDesc = m.sortCol.DefaultDescending()
	sortRows(m.rows, m.sortCol, m.sortDesc)
}

// ToggleSortDir flips the current sort direction
func (m *overviewModel) ToggleSortDir() {
	m.sortDesc = !m.sortDesc
	sortRows(m.rows, m.sortCol, m.sortDesc)
}

func (m *overviewModel) MoveUp(n int) {
	m.selected -= n
	m.clampSelection()
}

func (m *overviewModel) MoveDown(n int) {
	m.selected += n
	m.clampSelection()
}

func (m *overviewModel) JumpFirst() {
	m.selected = 0
	m.clampSelection()
}

func (m *overviewModel) JumpLast() {
	m.selected = len(m.rows) - 1
	m.clampSelection()
}

func (m *overviewModel) clampSelection() {
	if len(m.rows) == 0 {
		m.selected, m.offset = 0, 0
		return
	}

	if m.selected < 0 {
		m.selected = 0
	} else if m.selected >= len(m.rows) {
		m.selected = len(m.rows) - 1
	}

	// keep selection in the visible window
	if m.selected < m.offset {
		m.offset = m.selected
	} else if m.selected >= m.offset+m.visible {
		m.offset = m.selected - m.visible + 1
	}

	m.offset = max(0, m.offset)
	maxOffset := max(0, len(m.rows)-m.visible)
	m.offset = min(m.offset, maxOffset)
}

// View renders the tab body
func (m overviewModel) View() string {
	if m.width <= 0 || m.height <= 0 {
		return ""
	}

	cols := layoutColumns(m.width)

	var b strings.Builder

	// title row
	title := fmt.Sprintf("Active Connections — %d rows (sort: %s %s)",
		len(m.rows), m.sortCol.Label(), sortArrow(m.sortDesc))
	b.WriteString(m.theme.TableTitle.Render(title))
	b.WriteString("\n")

	// column header
	b.WriteString(m.renderHeader(cols))
	b.WriteString("\n")

	// body
	if len(m.rows) == 0 {
		hint := "No connections yet — waiting for packets…"
		b.WriteString(m.theme.TableDim.Render(hint))
		return b.String()
	}

	end := min(m.offset+m.visible, len(m.rows))
	for i := m.offset; i < end; i++ {
		b.WriteString(m.renderRow(cols, m.rows[i], i == m.selected))
		if i < end-1 {
			b.WriteString("\n")
		}
	}
	return b.String()
}

type column struct {
	sort  SortColumn
	label string
	width int
}

func layoutColumns(totalWidth int) []column {
	const (
		wProto   = 5
		wState   = 12
		wApp     = 22
		wRate    = 18
		wPkts    = 9
		wProcess = 16
		sepChars = 7 // 8 columns, 7 single-space separators
	)
	fixed := wProto + wState + wApp + wRate + wPkts + wProcess + sepChars
	flex := max(20, totalWidth-fixed)
	wLocal := flex / 2
	wRemote := flex - wLocal

	return []column{
		{SortProto, "Pro", wProto},
		{SortLocal, "Local Address", wLocal},
		{SortRemote, "Remote Address", wRemote},
		{SortState, "State", wState},
		{SortApp, "App", wApp},
		{SortBandwidth, "Down/Up", wRate},
		{SortPackets, "Pkts", wPkts},
		{SortProcess, "Process", wProcess},
	}
}

func (m overviewModel) renderHeader(cols []column) string {
	parts := make([]string, 0, len(cols))
	for _, c := range cols {
		label := c.label
		if c.sort == m.sortCol {
			label += " " + sortArrow(m.sortDesc)
		}
		label = padRight(label, c.width)
		if c.sort == m.sortCol {
			parts = append(parts, m.theme.TableHeaderActive.Render(label))
		} else {
			parts = append(parts, m.theme.TableHeader.Render(label))
		}
	}
	return strings.Join(parts, " ")
}

func (m overviewModel) renderRow(cols []column, r conn.ConnView, selected bool) string {
	process := r.ProcessName
	if process == "" {
		process = "—"
	}
	remote := fmtAddr(r.Key.RemoteAddr, r.Key.RemotePort)
	if m.showHostnames && m.resolver != nil {
		if host := m.resolver.Lookup(r.Key.RemoteAddr); host != "" {
			remote = fmt.Sprintf("%s:%d", host, r.Key.RemotePort)
		}
	}
	if m.geoip != nil {
		if cc := m.geoip.CountryCode(r.Key.RemoteAddr); cc != "" {
			remote = remote + " " + cc
		}
	}
	fields := []string{
		r.Key.Proto.String(),
		fmtAddr(r.Key.LocalAddr, r.Key.LocalPort),
		remote,
		r.State.String(),
		appLabel(r.DPI),
		humanRate(r.RateRecv) + " / " + humanRate(r.RateSent),
		fmt.Sprintf("%d/%d", r.PktsSent, r.PktsRecv),
		process,
	}

	parts := make([]string, len(cols))
	for i, c := range cols {
		text := truncate(fields[i], c.width)
		text = padRight(text, c.width)
		switch c.sort {
		case SortProto:
			parts[i] = m.theme.protoStyle(r.Key.Proto) + padRight("", c.width-len(r.Key.Proto.String()))
		case SortState:
			parts[i] = stateStyle(m.theme, r.State).Render(text)
		default:
			parts[i] = text
		}
	}

	line := strings.Join(parts, " ")
	if selected {
		// pad to full width so the highlight extends to the edge
		w := lipgloss.Width(line)
		if w < m.width {
			line += strings.Repeat(" ", m.width-w)
		}
		return m.theme.TableRowSelected.Render(line)
	}
	return line
}

func stateStyle(t Theme, s conn.State) lipgloss.Style {
	switch s {
	case conn.StateClosed, conn.StateTimeWait:
		return t.StateClosed
	case conn.StateSynSent, conn.StateSynRecv,
		conn.StateFinWait1, conn.StateFinWait2,
		conn.StateCloseWait, conn.StateLastAck, conn.StateClosing:
		return t.StateStale
	default:
		return t.StateActive
	}
}

func sortArrow(desc bool) string {
	if desc {
		return "↓"
	}
	return "↑"
}

func padRight(s string, n int) string {
	w := lipgloss.Width(s)
	if w >= n {
		return s
	}
	return s + strings.Repeat(" ", n-w)
}

func truncate(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if lipgloss.Width(s) <= n {
		return s
	}
	if n == 1 {
		return "…"
	}
	// walk runes until width would exceed n-1, then append ellipsis
	runes := []rune(s)
	for i := range runes {
		if lipgloss.Width(string(runes[:i+1])) > n-1 {
			return string(runes[:i]) + "…"
		}
	}
	return s
}
