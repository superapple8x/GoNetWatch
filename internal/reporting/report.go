package reporting

import (
	"fmt"
	"gonetwatch/internal/analysis"
	"os"
	"time"
)

// GenerateSessionReport generates a report of the session's activity.
// Currently supports "html" format.
func GenerateSessionReport(stats *analysis.TrafficStats, format string) (string, error) {
	if format != "html" {
		return "", fmt.Errorf("unsupported format: %s", format)
	}

	timestamp := time.Now().Format("20060102_150405")
	filename := fmt.Sprintf("report_%s.html", timestamp)

	file, err := os.Create(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()

	// Gather data
	totalBytes := stats.GetTotalDataTransferred()
	domains := stats.GetAllDomains()
	alerts := stats.GetAllAlerts()
	topTalkers := stats.GetTopTalkers(10)

	// Generate HTML content
	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GoNetWatch Session Report - %s</title>
    <style>
        body { font-family: sans-serif; margin: 20px; color: #333; }
        h1, h2 { color: #2c3e50; }
        table { width: 100%%; border-collapse: collapse; margin-bottom: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        .summary { background: #eef; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .alert { color: #d9534f; font-weight: bold; }
    </style>
</head>
<body>
    <h1>GoNetWatch Session Report</h1>
    <div class="summary">
        <p><strong>Date:</strong> %s</p>
        <p><strong>Total Data Transferred:</strong> %s</p>
    </div>

    <h2>Top 10 Talkers</h2>
    <table>
        <thead>
            <tr>
                <th>IP Address</th>
                <th>Data Transferred (Bytes)</th>
            </tr>
        </thead>
        <tbody>
`, timestamp, time.Now().Format(time.RFC1123), formatBytes(totalBytes))

	for _, talker := range topTalkers {
		html += fmt.Sprintf("            <tr><td>%s</td><td>%d</td></tr>\n", talker.IP, talker.Bytes)
	}

	html += `        </tbody>
    </table>

    <h2>Security Alerts</h2>
    <table>
        <thead>
            <tr>
                <th>Time</th>
                <th>Type</th>
                <th>Source</th>
                <th>Message</th>
            </tr>
        </thead>
        <tbody>
`

	if len(alerts) == 0 {
		html += "            <tr><td colspan=\"4\">No alerts triggered during this session.</td></tr>\n"
	} else {
		for _, alert := range alerts {
			html += fmt.Sprintf("            <tr><td>%s</td><td class=\"alert\">%s</td><td>%s</td><td>%s</td></tr>\n",
				alert.Timestamp.Format("15:04:05"), alert.Type, alert.Source, alert.Message)
		}
	}

	html += `        </tbody>
    </table>

    <h2>Domain History (Unique Domains)</h2>
    <table>
        <thead>
            <tr>
                <th>Time First Seen</th>
                <th>Hostname</th>
                <th>Source</th>
            </tr>
        </thead>
        <tbody>
`

	if len(domains) == 0 {
		html += "            <tr><td colspan=\"3\">No domains captured.</td></tr>\n"
	} else {
		for _, domain := range domains {
			html += fmt.Sprintf("            <tr><td>%s</td><td>%s</td><td>%s</td></tr>\n",
				domain.Timestamp.Format("15:04:05"), domain.Hostname, domain.Source)
		}
	}

	html += `        </tbody>
    </table>
</body>
</html>`

	_, err = file.WriteString(html)
	if err != nil {
		return "", err
	}

	return filename, nil
}

func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
