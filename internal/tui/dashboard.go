// Package tui provides a terminal dashboard for PQCAT scan results.
// Uses bubbletea + lipgloss for a rich interactive terminal UI.
// Works on any terminal — even KVM consoles with no GUI.
package tui

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/soqucoin-labs/pqcat/internal/store"
)

// Colors matching the Labs website palette
var (
	green  = lipgloss.Color("#00ff9d")
	yellow = lipgloss.Color("#ffd700")
	red    = lipgloss.Color("#ff4757")
	dim    = lipgloss.Color("#888888")
	bg     = lipgloss.Color("#0a0a0f")
	accent = lipgloss.Color("#00ff9d")

	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(accent).
			MarginBottom(1)

	headerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#ffffff")).
			Background(lipgloss.Color("#1e2030")).
			Padding(0, 1)

	scoreGreenStyle  = lipgloss.NewStyle().Bold(true).Foreground(green)
	scoreYellowStyle = lipgloss.NewStyle().Bold(true).Foreground(yellow)
	scoreRedStyle    = lipgloss.NewStyle().Bold(true).Foreground(red)
	dimStyle         = lipgloss.NewStyle().Foreground(dim)
	selectedStyle    = lipgloss.NewStyle().Foreground(accent).Bold(true)

	boxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#1e2030")).
			Padding(0, 1)
)

// Model is the main TUI application model.
type Model struct {
	db          *store.DB
	scans       []store.ScanSummary
	assets      []store.AssetRecord
	cursor      int
	mode        string // "list" or "detail"
	width       int
	height      int
	err         error
	lastRefresh time.Time
}

// NewModel creates a new TUI model with database.
func NewModel(db *store.DB) Model {
	return Model{
		db:   db,
		mode: "list",
	}
}

// Init loads initial data.
func (m Model) Init() tea.Cmd {
	return m.loadScans
}

func (m Model) loadScans() tea.Msg {
	scans, err := m.db.GetScans(50)
	if err != nil {
		return errMsg{err}
	}
	return scansMsg{scans}
}

func (m Model) loadAssets(scanID int64) tea.Cmd {
	return func() tea.Msg {
		assets, err := m.db.GetScanAssets(scanID)
		if err != nil {
			return errMsg{err}
		}
		return assetsMsg{assets}
	}
}

type scansMsg struct{ scans []store.ScanSummary }
type assetsMsg struct{ assets []store.AssetRecord }
type errMsg struct{ err error }

// Update handles input events.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
		case "down", "j":
			if m.mode == "list" && m.cursor < len(m.scans)-1 {
				m.cursor++
			} else if m.mode == "detail" && m.cursor < len(m.assets)-1 {
				m.cursor++
			}
		case "enter":
			if m.mode == "list" && len(m.scans) > 0 {
				m.mode = "detail"
				m.cursor = 0
				return m, m.loadAssets(m.scans[m.cursor].ID)
			}
		case "esc", "backspace":
			if m.mode == "detail" {
				m.mode = "list"
				m.cursor = 0
			}
		case "r":
			return m, m.loadScans
		}

	case scansMsg:
		m.scans = msg.scans
		m.lastRefresh = time.Now()
	case assetsMsg:
		m.assets = msg.assets
	case errMsg:
		m.err = msg.err
	}

	return m, nil
}

// View renders the current state.
func (m Model) View() string {
	var b strings.Builder

	// Header
	header := titleStyle.Render("PQCAT Dashboard") + "  " +
		dimStyle.Render(fmt.Sprintf("(%d scans)", len(m.scans)))
	b.WriteString(header + "\n")

	if m.mode == "list" {
		b.WriteString(m.renderScansView())
	} else {
		b.WriteString(m.renderDetailView())
	}

	// Footer
	b.WriteString("\n")
	if m.mode == "list" {
		b.WriteString(dimStyle.Render("↑/↓ navigate • Enter drill-down • r refresh • q quit"))
	} else {
		b.WriteString(dimStyle.Render("↑/↓ navigate • Esc back • q quit"))
	}

	return b.String()
}

func (m Model) renderScansView() string {
	var b strings.Builder

	if len(m.scans) == 0 {
		b.WriteString(dimStyle.Render("\n  No scans in database. Run: pqcat scan tls example.com --save-db\n"))
		return b.String()
	}

	// Stats bar
	totalRed, totalYellow, totalGreen := 0, 0, 0
	var totalScore float64
	for _, s := range m.scans {
		totalRed += s.RedCount
		totalYellow += s.YellowCount
		totalGreen += s.GreenCount
		totalScore += s.Score
	}
	avgScore := totalScore / float64(len(m.scans))

	stats := fmt.Sprintf("  Scans: %d  │  Avg Score: %s  │  Red: %s  │  Yellow: %s  │  Green: %s",
		len(m.scans),
		scoreStyle(avgScore).Render(fmt.Sprintf("%.0f", avgScore)),
		scoreRedStyle.Render(fmt.Sprintf("%d", totalRed)),
		scoreYellowStyle.Render(fmt.Sprintf("%d", totalYellow)),
		scoreGreenStyle.Render(fmt.Sprintf("%d", totalGreen)),
	)
	b.WriteString(boxStyle.Render(stats) + "\n\n")

	// Table header
	hdr := fmt.Sprintf("  %-4s %-25s %-8s %-8s %6s %5s %5s %5s  %-16s",
		"ID", "TARGET", "TYPE", "FW", "SCORE", "RED", "YLW", "GRN", "DATE")
	b.WriteString(headerStyle.Render(hdr) + "\n")

	// Rows
	for i, s := range m.scans {
		prefix := "  "
		style := lipgloss.NewStyle()
		if i == m.cursor {
			prefix = "▸ "
			style = selectedStyle
		}

		row := fmt.Sprintf("%-4d %-25s %-8s %-8s %s %5d %5d %5d  %s",
			s.ID,
			truncate(s.Target, 25),
			s.ScanType,
			s.Framework,
			scoreStyle(s.Score).Render(fmt.Sprintf("%5.1f", s.Score)),
			s.RedCount,
			s.YellowCount,
			s.GreenCount,
			s.CreatedAt.Format("Jan 02 15:04"),
		)
		b.WriteString(style.Render(prefix+row) + "\n")
	}

	return b.String()
}

func (m Model) renderDetailView() string {
	var b strings.Builder

	if len(m.scans) > 0 {
		scan := m.scans[0] // The scan we drilled into
		b.WriteString(fmt.Sprintf("  Scan #%d — %s (%s)\n\n", scan.ID, scan.Target, scan.ScanType))
	}

	hdr := fmt.Sprintf("  %-8s %-20s %-40s %-15s %-10s",
		"ZONE", "ALGORITHM", "LOCATION", "TYPE", "CRIT")
	b.WriteString(headerStyle.Render(hdr) + "\n")

	for i, a := range m.assets {
		prefix := "  "
		style := lipgloss.NewStyle()
		if i == m.cursor {
			prefix = "▸ "
			style = selectedStyle
		}

		zoneColor := dimStyle
		switch a.Zone {
		case "RED":
			zoneColor = scoreRedStyle
		case "YELLOW":
			zoneColor = scoreYellowStyle
		case "GREEN":
			zoneColor = scoreGreenStyle
		}

		row := fmt.Sprintf("%s %-20s %-40s %-15s %-10s",
			zoneColor.Render(fmt.Sprintf("%-8s", a.Zone)),
			a.Algorithm,
			truncate(a.Location, 40),
			a.AssetType,
			a.Criticality,
		)
		b.WriteString(style.Render(prefix+row) + "\n")
	}

	if len(m.assets) == 0 {
		b.WriteString(dimStyle.Render("  No assets found for this scan.\n"))
	}

	return b.String()
}

func scoreStyle(score float64) lipgloss.Style {
	switch {
	case score >= 80:
		return scoreGreenStyle
	case score >= 50:
		return scoreYellowStyle
	default:
		return scoreRedStyle
	}
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-1] + "…"
}

// Run starts the TUI dashboard.
func Run(db *store.DB) error {
	p := tea.NewProgram(NewModel(db), tea.WithAltScreen())
	_, err := p.Run()
	return err
}
