package ui

import (
	"net/netip"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/rykth/tir/internal/conn"
	"github.com/rykth/tir/internal/filter"
)

type Tab int

const (
	TabOverview Tab = iota
	TabDetails
	TabGraph
	TabInterfaces
	TabHelp

	numTabs = int(TabHelp) + 1
)

func (t Tab) String() string {
	return [...]string{"Overview", "Details", "Graph", "Interfaces", "Help"}[t]
}

// Snapshotter is the read side of conn.Publisher
type Snapshotter interface {
	Latest() *conn.Snapshot
}

// Resolver looks up a cached hostname for an IP
type Resolver interface {
	Lookup(addr netip.Addr) string
}

// CountryLookup returns the ISO-3166-1 alpha-2 country code for an IP, or ""
// when no record is available
type CountryLookup interface {
	CountryCode(addr netip.Addr) string
}

// ModelConfig is everything the model needs to start
type ModelConfig struct {
	Interface       string
	ProcMethod      string // "procfs", "ebpf", "off" (shown in status bar)
	Publisher       Snapshotter
	Resolver        Resolver               // optional (nil disables hostname display)
	Interfaces      InterfaceStatsProvider // optional (nil hides the Interfaces tab)
	GeoIP           CountryLookup          // optional (nil disables country code display)
	RefreshInterval time.Duration
	NoColor         bool
	ShowPTRLookups  bool // include PTR query connections in the table
}

// Model is the root Bubble Tea model
type Model struct {
	cfg   ModelConfig
	theme Theme

	activeTab Tab
	overview  overviewModel

	width  int
	height int

	// last snapshot read from the publisher (may be nil before the first tick)
	snap *conn.Snapshot

	// filter state
	input     filterInput
	filter    *filter.Filter
	filterErr error

	detailsKey    *conn.ConnKey // details state (non-nil = a row was enter-ed in Overview)
	showHostnames bool          // hostname rendering toggle for the Overviews remote column
	series        graphSeries   // graph tab (rolling window of total bandwidth)
	quitArmedAt   time.Time     // quit confirmation
}

const quitGrace = 2 * time.Second

func NewModel(cfg ModelConfig) Model {
	if cfg.RefreshInterval <= 0 {
		cfg.RefreshInterval = time.Second
	}
	theme := NewTheme(cfg.NoColor)
	return Model{
		cfg:           cfg,
		theme:         theme,
		overview:      newOverviewModel(theme, cfg.Resolver, cfg.GeoIP),
		showHostnames: cfg.Resolver != nil,
	}
}

type snapshotTickMsg time.Time

func (m Model) tickSnapshot() tea.Cmd {
	return tea.Tick(m.cfg.RefreshInterval, func(t time.Time) tea.Msg {
		return snapshotTickMsg(t)
	})
}

// Init returns the initial commands (start the snapshot ticker)
func (m Model) Init() tea.Cmd {
	return m.tickSnapshot()
}

// Update handles incoming messages
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.overview.SetSize(m.width, m.bodyHeight())
		return m, nil

	case snapshotTickMsg:
		if s := m.cfg.Publisher.Latest(); s != nil {
			m.snap = s
			m.overview.SetRows(m.filteredRows(s))
			// roll bandwidth totals into the graph series
			var down, up float64
			for _, r := range s.Rows {
				down += r.RateRecv
				up += r.RateSent
			}
			m.series.push(down, up)
		}
		return m, m.tickSnapshot()

	case tea.KeyMsg:
		return m.handleKey(msg)
	}
	return m, nil
}

func (m Model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// filter input mode swallows almost every key
	if m.input.Active() {
		return m.handleFilterKey(msg)
	}

	switch msg.String() {
	case "ctrl+c":
		return m, tea.Quit

	case "q":
		if !m.quitArmedAt.IsZero() && time.Since(m.quitArmedAt) < quitGrace {
			return m, tea.Quit
		}
		m.quitArmedAt = time.Now()
		return m, nil

	case "tab":
		m.activeTab = Tab((int(m.activeTab) + 1) % numTabs)
		return m, nil
	case "shift+tab":
		m.activeTab = Tab((int(m.activeTab) - 1 + numTabs) % numTabs)
		return m, nil

	case "?":
		if m.activeTab == TabHelp {
			m.activeTab = TabOverview
		} else {
			m.activeTab = TabHelp
		}
		return m, nil

	case "/":
		m.input.Activate()
		return m, nil

	case "esc":
		if m.activeTab == TabDetails {
			m.activeTab = TabOverview
			return m, nil
		}
		if !m.filter.IsEmpty() {
			m.input.Clear()
			m.filter = nil
			m.filterErr = nil
			if m.snap != nil {
				m.overview.SetRows(m.filteredRows(m.snap))
			}
			return m, nil
		}
		return m, nil

	case "d":
		if m.cfg.Resolver != nil {
			m.showHostnames = !m.showHostnames
			m.overview.SetShowHostnames(m.showHostnames)
		}
		return m, nil

	case "i":
		if m.activeTab == TabInterfaces {
			m.activeTab = TabOverview
		} else {
			m.activeTab = TabInterfaces
		}
		return m, nil

	case "enter":
		if m.activeTab == TabOverview {
			if row, ok := m.overview.SelectedRow(); ok {
				k := row.Key
				m.detailsKey = &k
				m.activeTab = TabDetails
			}
		}
		return m, nil
	}

	if m.activeTab == TabOverview {
		return m.handleOverviewKey(msg)
	}
	return m, nil
}

func (m Model) handleFilterKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyCtrlC:
		return m, tea.Quit
	case tea.KeyEsc:
		m.input.Clear()
		m.filter = nil
		m.filterErr = nil
		if m.snap != nil {
			m.overview.SetRows(m.filteredRows(m.snap))
		}
		return m, nil
	case tea.KeyEnter:
		m.input.Deactivate()
		return m, nil
	}
	if changed := m.input.HandleKey(msg); changed {
		m.recompileFilter()
		if m.snap != nil {
			m.overview.SetRows(m.filteredRows(m.snap))
		}
	}
	return m, nil
}

func (m *Model) recompileFilter() {
	f, err := filter.Parse(m.input.Value())
	m.filter = f
	m.filterErr = err
}

func (m Model) filteredRows(s *conn.Snapshot) []conn.ConnView {
	out := make([]conn.ConnView, 0, len(s.Rows))
	for _, r := range s.Rows {
		if !m.cfg.ShowPTRLookups && isPTRQuery(r) {
			continue
		}
		if !m.filter.Match(r) {
			continue
		}
		out = append(out, r)
	}
	return out
}

func isPTRQuery(r conn.ConnView) bool {
	if r.Key.Proto != conn.ProtoUDP || r.Key.RemotePort != 53 {
		return false
	}
	if r.DPI.Protocol != "DNS" {
		return false
	}
	return strings.HasSuffix(r.DPI.Host, ".in-addr.arpa") || strings.HasSuffix(r.DPI.Host, ".ip6.arpa")
}

func (m Model) handleOverviewKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "up", "k":
		m.overview.MoveUp(1)
	case "down", "j":
		m.overview.MoveDown(1)
	case "g", "home":
		m.overview.JumpFirst()
	case "G", "end":
		m.overview.JumpLast()
	case "pgup", "ctrl+b":
		m.overview.MoveUp(max(1, m.overview.visible-1))
	case "pgdown", "ctrl+f":
		m.overview.MoveDown(max(1, m.overview.visible-1))
	case "s":
		m.overview.CycleSort()
	case "S":
		m.overview.ToggleSortDir()
	}
	return m, nil
}

func (m Model) bodyHeight() int {
	h := m.height - 2
	if h < 1 {
		return 1
	}
	return h
}

func (m Model) View() string {
	if m.width <= 0 || m.height <= 0 {
		return "Initializing…"
	}

	var b strings.Builder

	labels := make([]string, numTabs)
	for i := range labels {
		labels[i] = Tab(i).String()
	}
	b.WriteString(m.theme.renderTabs(labels, int(m.activeTab)))
	b.WriteString("\n")

	body := m.bodyView()
	b.WriteString(body)
	bodyLines := strings.Count(body, "\n") + 1
	for range max(0, m.bodyHeight()-bodyLines) {
		b.WriteString("\n")
	}

	b.WriteString("\n")
	if m.input.Active() {
		b.WriteString(m.input.View(m.width, m.theme))
	} else {
		b.WriteString(m.statusBar())
	}

	return b.String()
}

func (m Model) bodyView() string {
	switch m.activeTab {
	case TabOverview:
		return m.overview.View()
	case TabDetails:
		return m.detailsView()
	case TabGraph:
		return m.graphView()
	case TabInterfaces:
		return m.interfacesView()
	case TabHelp:
		return m.theme.helpView()
	default:
		return m.theme.placeholderView(m.activeTab.String())
	}
}

func (m Model) statusBar() string {
	items := []statusItem{
		{key: "iface", value: orDash(m.cfg.Interface)},
		{key: "proc", value: orDash(m.cfg.ProcMethod)},
		{key: "conns", value: connsLabel(m.snap)},
	}
	if !m.filter.IsEmpty() {
		items = append(items, statusItem{key: "filter", value: m.filter.Raw()})
	}
	if m.snap != nil {
		items = append(items, statusItem{key: "snap", value: m.snap.GeneratedAt.Format("15:04:05")})
	}

	var warn string
	switch {
	case m.filterErr != nil:
		warn = "filter: " + m.filterErr.Error()
	case !m.quitArmedAt.IsZero() && time.Since(m.quitArmedAt) < quitGrace:
		warn = "press q again to quit"
	}

	hints := []string{"/: filter", "s: sort", "↵: details", "?: help", "q: quit"}

	return m.theme.renderStatusBar(m.width, items, hints, warn)
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func connsLabel(s *conn.Snapshot) string {
	if s == nil {
		return "0"
	}
	return itoa(len(s.Rows))
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
