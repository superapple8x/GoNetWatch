package tui

import (
	"gonetwatch/internal/analysis"
	"time"

	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type AnalysisModel struct {
	stats         *analysis.TrafficStats
	bps           float64
	pps           float64
	topTalkers    []analysis.IPStat
	protocols     []analysis.ProtocolStat
	table         table.Model
	interfaceName string
	mitmTarget    string

	// Phase 5: Deep Inspection
	domainLog []analysis.DomainEntry
	alerts    []analysis.Alert
}

func NewAnalysisModel(stats *analysis.TrafficStats, iface string, mitmTarget string) AnalysisModel {
	columns := []table.Column{
		{Title: "Source IP", Width: 20},
		{Title: "Bytes", Width: 15},
	}

	t := table.New(
		table.WithColumns(columns),
		table.WithFocused(false),
		table.WithHeight(10),
	)

	s := table.DefaultStyles()
	s.Header = s.Header.
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("240")).
		BorderBottom(true).
		Bold(true)
	s.Selected = s.Selected.
		Foreground(lipgloss.Color("229")).
		Background(lipgloss.Color("57")).
		Bold(false)
	t.SetStyles(s)

	return AnalysisModel{
		stats:         stats,
		interfaceName: iface,
		table:         t,
		mitmTarget:    mitmTarget,
	}
}

func (m AnalysisModel) Init() tea.Cmd {
	return tickCmd()
}

func tickCmd() tea.Cmd {
	return tea.Tick(250*time.Millisecond, func(t time.Time) tea.Msg {
		return TickMsg(t)
	})
}
