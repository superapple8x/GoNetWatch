package tui

import (
	"fmt"

	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
)

func (m AnalysisModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		}

	case TickMsg:
		// Fetch stats
		bps, pps := m.stats.GetRates()
		m.bps = bps
		m.pps = pps
		m.topTalkers = m.stats.GetTopTalkers(10)
		m.protocols = m.stats.GetProtocolStats()

		// Phase 5: Fetch domain log and alerts
		m.domainLog = m.stats.GetDomainLog()
		m.alerts = m.stats.GetAlerts()

		// Update table
		rows := make([]table.Row, len(m.topTalkers))
		for i, stat := range m.topTalkers {
			rows[i] = table.Row{stat.IP, fmt.Sprintf("%d", stat.Bytes)}
		}
		m.table.SetRows(rows)

		return m, tickCmd()
	}

	m.table, cmd = m.table.Update(msg)
	return m, cmd
}

