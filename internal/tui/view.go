package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FAFAFA")).
			Background(lipgloss.Color("#7D56F4")).
			Padding(0, 1)

	infoStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFF7DB")).
			Border(lipgloss.RoundedBorder()).
			Padding(0, 1).
			Margin(0, 1)
)

func (m AnalysisModel) View() string {
	headerText := fmt.Sprintf("GoNetWatch - Monitoring: %s", m.interfaceName)
	if m.mitmTarget != "" {
		headerText += fmt.Sprintf(" [MITM Target: %s]", m.mitmTarget)
	}
	title := titleStyle.Render(headerText)

	// QoS Panel
	qos := fmt.Sprintf("Bandwidth: %s\nPacket Rate: %.2f PPS", formatBps(m.bps), m.pps)
	qosBox := infoStyle.Render(qos)

	// Top Talkers
	ttBox := infoStyle.Render("Top Talkers\n" + m.table.View())

	// Protocols
	var protoStrs []string
	limit := 5
	if len(m.protocols) < limit {
		limit = len(m.protocols)
	}

	for i := 0; i < limit; i++ {
		p := m.protocols[i]
		protoStrs = append(protoStrs, fmt.Sprintf("%s: %d", p.Protocol, p.Count))
	}
	if len(protoStrs) == 0 {
		protoStrs = append(protoStrs, "Waiting for data...")
	}
	protoBox := infoStyle.Render("Protocols:\n" + strings.Join(protoStrs, "\n"))

	// Layout
	row1 := lipgloss.JoinHorizontal(lipgloss.Top, qosBox, protoBox)
	body := lipgloss.JoinVertical(lipgloss.Left, title, row1, ttBox)

	return body + "\nPress q to quit."
}

func formatBps(bps float64) string {
	if bps >= 1e6 {
		return fmt.Sprintf("%.2f Mbps", bps/1e6)
	}
	if bps >= 1e3 {
		return fmt.Sprintf("%.2f Kbps", bps/1e3)
	}
	return fmt.Sprintf("%.2f bps", bps)
}

