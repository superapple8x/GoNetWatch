package tui

import (
	"fmt"
	"strings"
	"time"

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

	// Phase 5: New styles for domain log and alerts
	alertStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(lipgloss.Color("#FF0000")).
			Bold(true).
			Padding(0, 1)

	normalStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#00FF00")).
			Bold(true)

	domainSNIStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#00FF00")) // Green for HTTPS

	domainDNSStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFFF00")) // Yellow for DNS

	domainHTTPStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FF0000")) // Red for HTTP
)

func (m AnalysisModel) View() string {
	headerText := fmt.Sprintf("GoNetWatch - %s", m.interfaceName)
	if m.mitmTarget != "" {
		headerText += fmt.Sprintf(" [MITM: %s]", m.mitmTarget)
	}

	if m.width > 0 {
		headerText = truncateMiddle(headerText, m.width-4)
	}

	title := titleStyle.Render(headerText)

	// Build 3-column layout
	leftCol := renderMetricsPanel(m)
	centerCol := renderTrafficPanel(m)
	rightCol := renderSecurityPanel(m)

	// Choose layout based on available width
	var columns string
	switch {
	case m.width >= 120:
		columns = lipgloss.JoinHorizontal(lipgloss.Top, leftCol, centerCol, rightCol)
	case m.width >= 90:
		sidebar := lipgloss.JoinVertical(lipgloss.Left, leftCol, rightCol)
		columns = lipgloss.JoinHorizontal(lipgloss.Top, sidebar, centerCol)
	default:
		columns = lipgloss.JoinVertical(lipgloss.Left, leftCol, rightCol, centerCol)
	}

	body := lipgloss.JoinVertical(lipgloss.Left, title, columns)

	if m.quitting {
		return overlay(body, m.width, m.height)
	}

	return body + "\nPress q to quit."
}

func overlay(background string, width, height int) string {
	modalStyle := lipgloss.NewStyle().
		Width(50).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("62")).
		Padding(1, 2).
		Align(lipgloss.Center)

	question := lipgloss.NewStyle().Bold(true).Render("Save Session Report?")
	help := lipgloss.NewStyle().Faint(true).Render("(y/n)")

	modal := modalStyle.Render(lipgloss.JoinVertical(lipgloss.Center, question, "\n", help))

	// Center the modal
	// We can't easily do true layering in pure string return without a layout manager,
	// but we can replace the content or append it.
	// For a better UX, let's just return the modal centered on a blank screen or
	// try to place it.
	// Simplest approach: Just return the modal.
	return lipgloss.Place(width, height, lipgloss.Center, lipgloss.Center, modal)
}

// renderMetricsPanel creates the left column with QoS metrics
func renderMetricsPanel(m AnalysisModel) string {
	var content strings.Builder

	content.WriteString(lipgloss.NewStyle().Bold(true).Render("📊 Metrics"))
	content.WriteString("\n\n")

	content.WriteString(fmt.Sprintf("Bandwidth: %s\n", formatBps(m.bps)))
	content.WriteString(fmt.Sprintf("Packet Rate: %.2f PPS\n\n", m.pps))

	content.WriteString(fmt.Sprintf("Interface: %s\n", m.interfaceName))
	if m.mitmTarget != "" {
		content.WriteString(fmt.Sprintf("MITM Target: %s\n", m.mitmTarget))
	}

	width := 30
	if m.width > 0 {
		switch {
		case m.width < 70:
			width = m.width - 4
			if width < 18 {
				width = 18
			}
		case m.width < 90:
			width = int(float64(m.width) * 0.45)
			if width < 22 {
				width = 22
			}
		default:
			width = int(float64(m.width) * 0.25) // 25%
			if width < 20 {
				width = 20
			}
		}
	}

	return infoStyle.Copy().Margin(0, marginForWidth(m.width)).Width(width).Render(content.String())
}

// renderTrafficPanel creates the center column with traffic data
func renderTrafficPanel(m AnalysisModel) string {
	var content strings.Builder

	// Top Talkers section
	content.WriteString(lipgloss.NewStyle().Bold(true).Render("🔝 Top Talkers"))
	content.WriteString("\n")
	content.WriteString(m.table.View())
	content.WriteString("\n\n")

	// Domain Log section
	content.WriteString(lipgloss.NewStyle().Bold(true).Render("🌐 Live Domain Log"))
	content.WriteString("\n")

	maxEntries := 15
	switch {
	case m.width < 60:
		maxEntries = 6
	case m.width < 90:
		maxEntries = 10
	}

	if len(m.domainLog) == 0 {
		content.WriteString(lipgloss.NewStyle().Italic(true).Faint(true).Render("Waiting for traffic..."))
	} else {
		// Show last N entries (newest last)
		start := 0
		if len(m.domainLog) > maxEntries {
			start = len(m.domainLog) - maxEntries
		}

		for i := start; i < len(m.domainLog); i++ {
			entry := m.domainLog[i]
			timestamp := entry.Timestamp.Format("15:04:05")

			// Color-code by source
			var styledDomain string
			switch entry.Source {
			case "SNI":
				styledDomain = domainSNIStyle.Render(truncateEnd(entry.Hostname, domainWidth(m.width)))
			case "DNS":
				styledDomain = domainDNSStyle.Render(truncateEnd(entry.Hostname, domainWidth(m.width)))
			case "HTTP":
				styledDomain = domainHTTPStyle.Render(truncateEnd(entry.Hostname, domainWidth(m.width)))
			default:
				styledDomain = truncateEnd(entry.Hostname, domainWidth(m.width))
			}

			content.WriteString(fmt.Sprintf("[%s] %s (%s)\n", timestamp, styledDomain, entry.Source))
		}
	}

	width := 45
	if m.width > 0 {
		switch {
		case m.width < 70:
			width = m.width - 4
			if width < 26 {
				width = 26
			}
		case m.width < 120:
			width = int(float64(m.width) * 0.55)
			if width < 32 {
				width = 32
			}
		default:
			width = int(float64(m.width) * 0.40) // 40%
			if width < 30 {
				width = 30
			}
		}
	}

	return infoStyle.Copy().Margin(0, marginForWidth(m.width)).Width(width).Render(content.String())
}

// renderSecurityPanel creates the right column with security monitoring
func renderSecurityPanel(m AnalysisModel) string {
	var content strings.Builder

	content.WriteString(lipgloss.NewStyle().Bold(true).Render("🛡️  Anomaly Detection"))
	content.WriteString("\n\n")

	if len(m.alerts) == 0 {
		// No alerts - system normal
		content.WriteString(normalStyle.Render("✓ System Normal"))
		content.WriteString("\n\n")
		content.WriteString(lipgloss.NewStyle().Faint(true).Render("No anomalies detected"))
	} else {
		// Show recent alerts
		content.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("#FFA500")).Render(fmt.Sprintf("%d Active Alert(s)", len(m.alerts))))
		content.WriteString("\n\n")

		maxAlerts := 4
		if m.width < 80 {
			maxAlerts = 2
		}
		alerts := m.alerts
		if len(alerts) > maxAlerts {
			alerts = alerts[:maxAlerts]
		}

		for _, alert := range alerts {
			age := time.Since(alert.Timestamp)

			// Flash red for alerts less than 10 seconds old
			var alertText string
			if age < 10*time.Second {
				alertText = alertStyle.Render(fmt.Sprintf("[!] %s", alert.Type))
			} else {
				alertText = lipgloss.NewStyle().
					Foreground(lipgloss.Color("#FF6B6B")).
					Bold(true).
					Render(fmt.Sprintf("[!] %s", alert.Type))
			}

			content.WriteString(alertText)
			content.WriteString("\n")
			content.WriteString(lipgloss.NewStyle().Faint(true).Render(fmt.Sprintf("    %s", truncateEnd(alert.Message, alertWidth(m.width)))))
			content.WriteString("\n")
			content.WriteString(lipgloss.NewStyle().Faint(true).Render(fmt.Sprintf("    %s ago", formatDuration(age))))
			content.WriteString("\n\n")
		}
	}

	width := 35
	if m.width > 0 {
		switch {
		case m.width < 70:
			width = m.width - 4
			if width < 22 {
				width = 22
			}
		case m.width < 120:
			width = int(float64(m.width) * 0.45) // 45% when paired in sidebar
			if width < 26 {
				width = 26
			}
		default:
			width = int(float64(m.width) * 0.35) // 35%
			if width < 25 {
				width = 25
			}
		}
	}

	return infoStyle.Copy().Margin(0, marginForWidth(m.width)).Width(width).Render(content.String())
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

func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	return fmt.Sprintf("%dh", int(d.Hours()))
}

// marginForWidth reduces horizontal margin when space is tight.
func marginForWidth(width int) int {
	if width > 0 && width < 80 {
		return 0
	}
	return 1
}

// truncateEnd trims a string and adds an ellipsis if it exceeds max characters.
func truncateEnd(s string, max int) string {
	if max <= 0 {
		return ""
	}
	if len(s) <= max {
		return s
	}
	if max <= 3 {
		return s[:max]
	}
	return s[:max-3] + "..."
}

// truncateMiddle shortens a string by replacing the middle with an ellipsis.
func truncateMiddle(s string, max int) string {
	if max <= 0 {
		return ""
	}
	if len(s) <= max {
		return s
	}
	if max <= 3 {
		return s[:max]
	}
	half := (max - 3) / 2
	return s[:half] + "..." + s[len(s)-half:]
}

func domainWidth(width int) int {
	if width == 0 {
		return 30
	}
	switch {
	case width < 60:
		return 18
	case width < 90:
		return 22
	default:
		return 32
	}
}

func alertWidth(width int) int {
	if width == 0 {
		return 40
	}
	switch {
	case width < 70:
		return 28
	case width < 90:
		return 34
	default:
		return 48
	}
}
