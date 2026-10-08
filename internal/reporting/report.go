package reporting

import (
	"encoding/json"
	"fmt"
	"gonetwatch/internal/analysis"
	"html"
	"html/template"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// SessionMeta carries session context for the report. Zero values are
// filled in from stats/time.Now so callers can pass a partial struct.
type SessionMeta struct {
	Interface  string
	MitmTarget string
	StartTime  time.Time
	EndTime    time.Time
}

// talkerRow is one Top Talkers table row.
type talkerRow struct {
	Rank  int
	IP    string
	Bytes int
	Human string
	Pct   float64
	Bar   float64
}

// protoRow is one protocol distribution row.
type protoRow struct {
	Protocol string
	Count    int64
	Pct      float64
	Bar      float64
}

// portRow is one Top Ports table row.
type portRow struct {
	Rank    int
	Port    int
	Service string
	Label   string
	Bytes   int
	Human   string
	Pct     float64
	Bar     float64
}

// domainRow is one domain history row.
type domainRow struct {
	Hostname   string
	Source     string
	BadgeClass string
	FirstSeen  string
	Ago        string
}

// alertRow is one security alert row.
type alertRow struct {
	Time          string
	Ago           string
	Type          string
	SeverityClass string
	SeverityLabel string
	Source        string
	Message       string
}

// reportData is the template model. SVG fields are pre-escaped template.HTML.
type reportData struct {
	Title         string
	GeneratedAt   string
	FileStamp     string
	Interface     string
	MitmTarget    string
	StartStr      string
	EndStr        string
	DurationStr   string
	TotalBytes    int64
	TotalHuman    string
	TotalPackets  int64
	AvgBps        float64
	AvgBpsHuman   string
	AvgPps        float64
	UniqueDomains int
	AlertCount    int
	Talkers       []talkerRow
	Protocols     []protoRow
	Ports         []portRow
	Domains       []domainRow
	SNICount      int
	DNSCount      int
	HTTPCount     int
	OtherCount    int
	Alerts        []alertRow
	ProtoSVG      template.HTML
	TalkerSVG     template.HTML
	ChartJSON     template.JS
	HasTalkers    bool
	HasProtocols  bool
	HasPorts      bool
	HasDomains    bool
	HasAlerts     bool
}

// GenerateSessionReport generates a report of the session's activity.
// Currently supports "html" format. Kept for backward compatibility;
// it derives session timing from stats and the current time.
func GenerateSessionReport(stats *analysis.TrafficStats, format string) (string, error) {
	return GenerateSessionReportWithMeta(stats, SessionMeta{}, format)
}

// GenerateSessionReportWithMeta generates the report with explicit session context.
func GenerateSessionReportWithMeta(stats *analysis.TrafficStats, meta SessionMeta, format string) (string, error) {
	if format != "html" {
		return "", fmt.Errorf("unsupported format: %s", format)
	}

	now := time.Now()
	end := meta.EndTime
	if end.IsZero() {
		end = now
	}
	start := meta.StartTime
	if start.IsZero() {
		start = stats.GetStartTime()
	}
	if start.IsZero() {
		start = end
	}
	if end.Before(start) {
		end, start = start, end
	}
	durationSecs := end.Sub(start).Seconds()
	if durationSecs < 1 {
		durationSecs = 1
	}

	if err := os.MkdirAll("reports", 0755); err != nil {
		return "", fmt.Errorf("failed to create report directory: %v", err)
	}
	fileStamp := end.Format("20060102_150405")
	filename := filepath.Join("reports", fmt.Sprintf("report_%s.html", fileStamp))

	totalBytes := stats.GetTotalDataTransferred()
	totalPackets := stats.GetTotalPackets()
	domains := stats.GetAllDomains()
	alerts := stats.GetAllAlerts()
	talkers := stats.GetTopTalkers(10)
	protocols := stats.GetProtocolStats()
	ports := stats.GetTopPorts(10)

	data := buildReportData(meta, start, end, now, fileStamp, durationSecs, totalBytes, totalPackets, domains, alerts, talkers, protocols, ports)

	tmpl, err := template.New("report").Parse(reportTemplate)
	if err != nil {
		return "", fmt.Errorf("failed to parse report template: %v", err)
	}

	file, err := os.Create(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()

	if err := tmpl.Execute(file, data); err != nil {
		return "", fmt.Errorf("failed to render report: %v", err)
	}

	return filename, nil
}

func buildReportData(meta SessionMeta, start, end, now time.Time, fileStamp string, durationSecs float64, totalBytes, totalPackets int64, domains []analysis.DomainEntry, alerts []analysis.Alert, talkers []analysis.IPStat, protocols []analysis.ProtocolStat, ports []analysis.PortStat) reportData {
	avgBps := float64(totalBytes*8) / durationSecs
	avgPps := float64(totalPackets) / durationSecs

	// Talkers
	tRows := make([]talkerRow, 0, len(talkers))
	var maxTalker int
	for _, t := range talkers {
		if t.Bytes > maxTalker {
			maxTalker = t.Bytes
		}
	}
	for i, t := range talkers {
		var pct, bar float64
		if totalBytes > 0 {
			pct = float64(t.Bytes) / float64(totalBytes) * 100
		}
		if maxTalker > 0 {
			bar = float64(t.Bytes) / float64(maxTalker) * 100
		}
		tRows = append(tRows, talkerRow{Rank: i + 1, IP: t.IP, Bytes: t.Bytes, Human: formatBytes(int64(t.Bytes)), Pct: pct, Bar: bar})
	}

	// Protocols
	var totalProto int64
	for _, p := range protocols {
		totalProto += p.Count
	}
	pRows := make([]protoRow, 0, len(protocols))
	var maxProto int64
	for _, p := range protocols {
		if p.Count > maxProto {
			maxProto = p.Count
		}
	}
	for _, p := range protocols {
		var pct, bar float64
		if totalProto > 0 {
			pct = float64(p.Count) / float64(totalProto) * 100
		}
		if maxProto > 0 {
			bar = float64(p.Count) / float64(maxProto) * 100
		}
		pRows = append(pRows, protoRow{Protocol: p.Protocol, Count: p.Count, Pct: pct, Bar: bar})
	}

	// Ports
	portRows := make([]portRow, 0, len(ports))
	var maxPort int
	for _, p := range ports {
		if p.Bytes > maxPort {
			maxPort = p.Bytes
		}
	}
	for i, p := range ports {
		svc := analysis.GetServiceName(p.Port)
		label := fmt.Sprintf("%d", p.Port)
		if svc != label {
			label = fmt.Sprintf("%s (%d)", svc, p.Port)
		}
		var pct, bar float64
		if totalBytes > 0 {
			pct = float64(p.Bytes) / float64(totalBytes) * 100
		}
		if maxPort > 0 {
			bar = float64(p.Bytes) / float64(maxPort) * 100
		}
		portRows = append(portRows, portRow{Rank: i + 1, Port: p.Port, Service: svc, Label: label, Bytes: p.Bytes, Human: formatBytes(int64(p.Bytes)), Pct: pct, Bar: bar})
	}

	// Domains
	dRows := make([]domainRow, 0, len(domains))
	var sni, dns, httpN, other int
	for _, d := range domains {
		badge := "badge-other"
		switch d.Source {
		case "SNI":
			badge = "badge-sni"
			sni++
		case "DNS":
			badge = "badge-dns"
			dns++
		case "HTTP":
			badge = "badge-http"
			httpN++
		default:
			other++
		}
		dRows = append(dRows, domainRow{
			Hostname:   d.Hostname,
			Source:     d.Source,
			BadgeClass: badge,
			FirstSeen:  d.Timestamp.Format("15:04:05"),
			Ago:        formatAgo(now.Sub(d.Timestamp)),
		})
	}

	// Alerts, newest first
	aRows := make([]alertRow, 0, len(alerts))
	for i := len(alerts) - 1; i >= 0; i-- {
		a := alerts[i]
		class, label := severityForAlert(string(a.Type))
		aRows = append(aRows, alertRow{
			Time:          a.Timestamp.Format("15:04:05"),
			Ago:           formatAgo(now.Sub(a.Timestamp)) + " ago",
			Type:          string(a.Type),
			SeverityClass: class,
			SeverityLabel: label,
			Source:        a.Source,
			Message:       a.Message,
		})
	}

	// Chart payloads
	protoLabels := make([]string, 0, len(pRows))
	protoCounts := make([]int64, 0, len(pRows))
	for _, p := range pRows {
		protoLabels = append(protoLabels, p.Protocol)
		protoCounts = append(protoCounts, p.Count)
	}
	talkerLabels := make([]string, 0, len(tRows))
	talkerBytes := make([]int, 0, len(tRows))
	for _, t := range tRows {
		talkerLabels = append(talkerLabels, t.IP)
		talkerBytes = append(talkerBytes, t.Bytes)
	}
	chartPayload, _ := json.Marshal(map[string]any{
		"protoLabels": protoLabels, "protoCounts": protoCounts,
		"talkerLabels": talkerLabels, "talkerBytes": talkerBytes,
	})

	return reportData{
		Title:         "GoNetWatch Session Report",
		GeneratedAt:   end.Format(time.RFC1123),
		FileStamp:     fileStamp,
		Interface:     meta.Interface,
		MitmTarget:    meta.MitmTarget,
		StartStr:      start.Format("2006-01-02 15:04:05"),
		EndStr:        end.Format("2006-01-02 15:04:05"),
		DurationStr:   formatDurationHMS(end.Sub(start)),
		TotalBytes:    totalBytes,
		TotalHuman:    formatBytes(totalBytes),
		TotalPackets:  totalPackets,
		AvgBps:        avgBps,
		AvgBpsHuman:   formatBps(avgBps),
		AvgPps:        avgPps,
		UniqueDomains: len(dRows),
		AlertCount:    len(aRows),
		Talkers:       tRows,
		Protocols:     pRows,
		Ports:         portRows,
		Domains:       dRows,
		SNICount:      sni,
		DNSCount:      dns,
		HTTPCount:     httpN,
		OtherCount:    other,
		Alerts:        aRows,
		ProtoSVG:      template.HTML(buildDonutSVG(pRows)),
		TalkerSVG:     template.HTML(buildTalkerBarsSVG(tRows)),
		ChartJSON:     template.JS(chartPayload),
		HasTalkers:    len(tRows) > 0,
		HasProtocols:  len(pRows) > 0,
		HasPorts:      len(portRows) > 0,
		HasDomains:    len(dRows) > 0,
		HasAlerts:     len(aRows) > 0,
	}
}

func severityForAlert(t string) (class, label string) {
	switch t {
	case "BROADCAST_STORM":
		return "sev-critical", "Critical"
	case "POSSIBLE_DOS":
		return "sev-critical", "Critical"
	case "UNSECURE_PROTOCOL":
		return "sev-warning", "Warning"
	default:
		return "sev-info", "Info"
	}
}

var donutPalette = []string{"#7D56F4", "#00C2A8", "#FFB020", "#FF6B6B", "#4EA1FF", "#B388FF", "#FFD166", "#8AC926"}

// buildDonutSVG renders a static donut chart for protocol share. Always
// rendered so the report is readable offline; Chart.js replaces it when online.
func buildDonutSVG(rows []protoRow) string {
	if len(rows) == 0 {
		return ""
	}
	const r = 54.0
	const cx, cy = 70.0, 70.0
	circ := 2 * 3.141592653589793 * r
	var total float64
	for _, p := range rows {
		total += float64(p.Count)
	}
	if total <= 0 {
		return ""
	}
	var sb strings.Builder
	sb.WriteString(`<svg class="svg-donut" viewBox="0 0 140 140" role="img" aria-label="Protocol distribution">`)
	offset := 0.0
	for i, p := range rows {
		frac := float64(p.Count) / total
		dash := frac * circ
		color := donutPalette[i%len(donutPalette)]
		sb.WriteString(fmt.Sprintf(
			`<circle cx="%.1f" cy="%.1f" r="%.1f" fill="none" stroke="%s" stroke-width="18" stroke-dasharray="%.2f %.2f" stroke-dashoffset="%.2f" transform="rotate(-90 %.1f %.1f)"><title>%s: %d packets (%.1f%%)</title></circle>`,
			cx, cy, r, color, dash, circ-dash, -offset, cx, cy,
			html.EscapeString(p.Protocol), p.Count, frac*100))
		offset += dash
	}
	sb.WriteString(fmt.Sprintf(`<text x="%.1f" y="%.1f" text-anchor="middle" dominant-baseline="middle" class="donut-center">%d</text>`, cx, cy, int64(total)))
	sb.WriteString(`</svg>`)
	// Legend
	sb.WriteString(`<ul class="legend">`)
	for i, p := range rows {
		color := donutPalette[i%len(donutPalette)]
		sb.WriteString(fmt.Sprintf(`<li><span class="swatch" style="background:%s"></span><span class="mono">%s</span><span class="muted">%d (%.1f%%)</span></li>`,
			color, html.EscapeString(p.Protocol), p.Count, p.Pct))
	}
	sb.WriteString(`</ul>`)
	return sb.String()
}

// buildTalkerBarsSVG renders static horizontal bars for top talkers.
func buildTalkerBarsSVG(rows []talkerRow) string {
	if len(rows) == 0 {
		return ""
	}
	n := len(rows)
	if n > 10 {
		n = 10
		rows = rows[:n]
	}
	const w = 420.0
	rowH := 26.0
	h := float64(n)*rowH + 8
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf(`<svg class="svg-bars" viewBox="0 0 %.0f %.0f" role="img" aria-label="Top talkers by bytes">`, w, h))
	for i, t := range rows[:n] {
		y := float64(i)*rowH + 4
		bw := t.Bar / 100 * (w - 170)
		if bw < 2 && t.Bytes > 0 {
			bw = 2
		}
		sb.WriteString(fmt.Sprintf(`<text x="0" y="%.1f" class="bar-label mono">%s</text>`, y+13, html.EscapeString(truncateIP(t.IP, 22))))
		sb.WriteString(fmt.Sprintf(`<rect x="150" y="%.1f" width="%.1f" height="14" rx="4" fill="#7D56F4"><title>%s: %s (%.1f%%)</title></rect>`,
			y, bw, html.EscapeString(t.IP), html.EscapeString(t.Human), t.Pct))
		sb.WriteString(fmt.Sprintf(`<text x="%.1f" y="%.1f" class="bar-value">%s</text>`, 156+bw, y+12, html.EscapeString(t.Human)))
	}
	sb.WriteString(`</svg>`)
	return sb.String()
}

func truncateIP(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max <= 3 {
		return s[:max]
	}
	return s[:max-3] + "..."
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

func formatBps(bps float64) string {
	if bps >= 1e6 {
		return fmt.Sprintf("%.2f Mbps", bps/1e6)
	}
	if bps >= 1e3 {
		return fmt.Sprintf("%.2f Kbps", bps/1e3)
	}
	return fmt.Sprintf("%.2f bps", bps)
}

func formatDurationHMS(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	s := int(d.Seconds())
	h := s / 3600
	m := (s % 3600) / 60
	sec := s % 60
	if h > 0 {
		return fmt.Sprintf("%dh %dm %ds", h, m, sec)
	}
	if m > 0 {
		return fmt.Sprintf("%dm %ds", m, sec)
	}
	return fmt.Sprintf("%ds", sec)
}

func formatAgo(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm %ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	return fmt.Sprintf("%dh %dm", int(d.Hours()), int(d.Minutes())%60)
}

const reportTemplate = `<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="color-scheme" content="dark light">
<title>{{.Title}} - {{.FileStamp}}</title>
<style>
:root{
  --bg:#0f1117; --bg-soft:#161a26; --card:#1a1f2e; --card-2:#202637;
  --border:#2b3348; --text:#e8eaf0; --muted:#9aa3b8; --faint:#6b7386;
  --accent:#7D56F4; --accent-soft:rgba(125,86,244,.16);
  --green:#00C2A8; --yellow:#FFB020; --red:#FF6B6B; --blue:#4EA1FF;
  --mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  --sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
}
@media (prefers-color-scheme: light){
  :root{ --bg:#f4f5f9; --bg-soft:#ffffff; --card:#ffffff; --card-2:#f0f2f8;
    --border:#dfe3ee; --text:#1c2333; --muted:#5b6478; --faint:#8a93a8;
    --accent-soft:rgba(125,86,244,.12); }
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font-family:var(--sans);line-height:1.5}
.wrap{max-width:1120px;margin:0 auto;padding:28px 20px 64px}
header.hero{background:linear-gradient(135deg,#241d4e,#101527 60%);border:1px solid var(--border);border-radius:14px;padding:26px 26px 20px;margin-bottom:22px}
header.hero h1{margin:0 0 6px;font-size:26px;letter-spacing:.2px}
.sub{color:var(--muted);margin:2px 0;font-size:14px}
.sub .mono{font-family:var(--mono)}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:18px 0 4px}
.kpi{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:12px 14px}
.kpi .k{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted)}
.kpi .v{font-size:20px;font-weight:700;margin-top:2px}
.kpi .s{font-size:12px;color:var(--faint)}
section.card{background:var(--bg-soft);border:1px solid var(--border);border-radius:12px;padding:18px;margin-top:16px}
section.card h2{margin:0 0 4px;font-size:17px}
section.card p.desc{margin:0 0 12px;color:var(--muted);font-size:13px}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:16px}
@media(max-width:860px){.grid2{grid-template-columns:1fr}}
table{width:100%;border-collapse:collapse;font-size:13.5px}
thead th{position:sticky;top:0;background:var(--card-2);text-align:left;font-size:11.5px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);border-bottom:1px solid var(--border);padding:9px 10px;white-space:nowrap}
tbody td{padding:8px 10px;border-bottom:1px solid var(--border);vertical-align:middle}
tbody tr:nth-child(even){background:rgba(255,255,255,.018)}
tbody tr:hover{background:var(--accent-soft)}
td.num,th.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
td.mono{font-family:var(--mono);font-size:12.8px}
.bar{height:8px;border-radius:99px;background:rgba(255,255,255,.08);overflow:hidden;min-width:90px}
.bar > span{display:block;height:100%;background:linear-gradient(90deg,var(--accent),#9d7bff)}
.badge{display:inline-block;padding:1px 9px;border-radius:99px;font-size:11.5px;font-weight:700;letter-spacing:.02em;border:1px solid transparent;white-space:nowrap}
.badge-sni{background:rgba(0,194,168,.15);color:var(--green);border-color:rgba(0,194,168,.4)}
.badge-dns{background:rgba(255,176,32,.14);color:var(--yellow);border-color:rgba(255,176,32,.4)}
.badge-http{background:rgba(255,107,107,.14);color:var(--red);border-color:rgba(255,107,107,.45)}
.badge-other{background:rgba(154,163,184,.14);color:var(--muted);border-color:var(--border)}
.sev{display:inline-block;padding:1px 9px;border-radius:6px;font-size:11.5px;font-weight:800;white-space:nowrap}
.sev-critical{background:rgba(255,107,107,.16);color:var(--red);border:1px solid rgba(255,107,107,.45)}
.sev-warning{background:rgba(255,176,32,.14);color:var(--yellow);border:1px solid rgba(255,176,32,.4)}
.sev-info{background:rgba(78,161,255,.14);color:var(--blue);border:1px solid rgba(78,161,255,.4)}
.muted{color:var(--muted)} .faint{color:var(--faint)}
.empty{padding:18px;text-align:center;color:var(--muted);border:1px dashed var(--border);border-radius:10px;font-size:14px}
.svg-donut{width:190px;height:190px}
.donut-center{fill:var(--text);font-size:20px;font-weight:800}
.legend{list-style:none;margin:10px 0 0;padding:0;font-size:13px}
.legend li{display:flex;align-items:center;gap:8px;padding:3px 0}
.swatch{width:12px;height:12px;border-radius:3px;display:inline-block}
.legend .mono{font-family:var(--mono)}
.svg-bars{width:100%;height:auto}
.svg-bars .bar-label{fill:var(--muted);font-size:11px;font-family:var(--mono)}
.svg-bars .bar-value{fill:var(--text);font-size:11px}
.chart-js canvas{width:100%!important;max-height:300px}
.mode-badge{font-size:12px;color:var(--muted);border:1px solid var(--border);border-radius:99px;padding:2px 10px;margin-left:8px}
.filters{margin:0 0 10px;display:flex;gap:8px;flex-wrap:wrap}
.filters button{background:var(--card);color:var(--text);border:1px solid var(--border);border-radius:99px;padding:4px 12px;font-size:12.5px;cursor:pointer}
.filters button.active{background:var(--accent);border-color:var(--accent);color:#fff}
footer{margin-top:22px;color:var(--faint);font-size:12.5px;text-align:center}
a{color:var(--blue)}
@media print{
  body{background:#fff;color:#111}
  header.hero{background:#fff;color:#111;border-color:#ccc}
  section.card{background:#fff;border-color:#ccc;break-inside:avoid}
  .kpi{background:#fff;border-color:#ccc}
  tbody tr:nth-child(even){background:#f6f6f6}
  .chart-js{display:none!important}
  .mode-badge{display:none}
}
</style>
</head>
<body>
<div class="wrap">
<header class="hero">
  <h1>{{.Title}}</h1>
  <p class="sub">Generated <span class="mono">{{.GeneratedAt}}</span> &middot; Session <span class="mono">{{.StartStr}} &rarr; {{.EndStr}}</span> ({{.DurationStr}})</p>
  <p class="sub">Interface <span class="mono">{{if .Interface}}{{.Interface}}{{else}}unknown{{end}}</span>{{if .MitmTarget}} &middot; MITM target <span class="mono">{{.MitmTarget}}</span>{{end}}</p>
  <div class="kpis">
    <div class="kpi"><div class="k">Total data</div><div class="v">{{.TotalHuman}}</div><div class="s">{{.TotalBytes}} bytes</div></div>
    <div class="kpi"><div class="k">Packets</div><div class="v">{{.TotalPackets}}</div><div class="s">{{.AvgPps | printf "%.1f"}} pps avg</div></div>
    <div class="kpi"><div class="k">Avg rate</div><div class="v">{{.AvgBpsHuman}}</div><div class="s">over {{.DurationStr}}</div></div>
    <div class="kpi"><div class="k">Domains</div><div class="v">{{.UniqueDomains}}</div><div class="s">SNI {{.SNICount}} &middot; DNS {{.DNSCount}} &middot; HTTP {{.HTTPCount}}</div></div>
    <div class="kpi"><div class="k">Alerts</div><div class="v">{{.AlertCount}}</div><div class="s">{{if .HasAlerts}}review below{{else}}system normal{{end}}</div></div>
  </div>
</header>

<section class="card">
  <h2>Top Talkers <span class="mode-badge">share of {{.TotalHuman}}</span></h2>
  <p class="desc">Ranked by bytes sent (source IP). Bar shows share of the busiest talker.</p>
  {{if .HasTalkers}}
  <div class="grid2">
    <div>
      <table>
        <thead><tr><th>#</th><th>IP address</th><th class="num">Bytes</th><th class="num">Share</th><th style="width:26%">Trend</th></tr></thead>
        <tbody>
        {{range .Talkers}}<tr><td class="muted">{{.Rank}}</td><td class="mono">{{.IP}}</td><td class="num mono">{{.Human}}<div class="faint" style="font-size:11px">{{.Bytes}} B</div></td><td class="num">{{printf "%.1f" .Pct}}%</td><td><div class="bar"><span style="width:{{printf "%.1f" .Bar}}%"></span></div></td></tr>{{end}}
        </tbody>
      </table>
    </div>
    <div>
      <div class="svg-chart">{{.TalkerSVG}}</div>
      <div class="chart-js" hidden><canvas id="talkerChart"></canvas></div>
    </div>
  </div>
  {{else}}<div class="empty">No traffic captured in this session.</div>{{end}}
</section>

<section class="card">
  <h2>Traffic composition <span class="mode-badge" id="chart-mode">static charts (offline)</span></h2>
  <p class="desc">Protocol share by packet count; ports by bytes. Interactive charts load when Chart.js is reachable.</p>
  <div class="grid2">
    <div>
      <h3 style="margin:4px 0 8px;font-size:14px">Protocols</h3>
      {{if .HasProtocols}}
      <div class="svg-chart">{{.ProtoSVG}}</div>
      <div class="chart-js" hidden><canvas id="protoChart"></canvas></div>
      <table style="margin-top:10px">
        <thead><tr><th>Protocol</th><th class="num">Packets</th><th class="num">Share</th></tr></thead>
        <tbody>{{range .Protocols}}<tr><td class="mono">{{.Protocol}}</td><td class="num mono">{{.Count}}</td><td class="num">{{printf "%.1f" .Pct}}%</td></tr>{{end}}</tbody>
      </table>
      {{else}}<div class="empty">No protocol data.</div>{{end}}
    </div>
    <div>
      <h3 style="margin:4px 0 8px;font-size:14px">Top ports</h3>
      {{if .HasPorts}}
      <table>
        <thead><tr><th>#</th><th>Port</th><th class="num">Bytes</th><th class="num">Share</th><th style="width:24%">Trend</th></tr></thead>
        <tbody>{{range .Ports}}<tr><td class="muted">{{.Rank}}</td><td class="mono">{{.Label}}</td><td class="num mono">{{.Human}}</td><td class="num">{{printf "%.1f" .Pct}}%</td><td><div class="bar"><span style="width:{{printf "%.1f" .Bar}}%"></span></div></td></tr>{{end}}</tbody>
      </table>
      {{else}}<div class="empty">No port data.</div>{{end}}
    </div>
  </div>
</section>

<section class="card">
  <h2>Domain history ({{.UniqueDomains}} unique)</h2>
  <p class="desc">First-seen time per hostname. SNI = HTTPS destination, DNS = query, HTTP = plaintext host header.</p>
  {{if .HasDomains}}
  <div class="filters" id="domain-filters">
    <button data-f="all" class="active">All ({{.UniqueDomains}})</button>
    <button data-f="SNI">SNI ({{.SNICount}})</button>
    <button data-f="DNS">DNS ({{.DNSCount}})</button>
    <button data-f="HTTP">HTTP ({{.HTTPCount}})</button>
  </div>
  <table id="domain-table">
    <thead><tr><th>First seen</th><th>Hostname</th><th>Source</th><th class="num">Seen</th></tr></thead>
    <tbody>{{range .Domains}}<tr data-src="{{.Source}}"><td class="mono muted">{{.FirstSeen}}<div class="faint" style="font-size:11px">{{.Ago}}</div></td><td class="mono">{{.Hostname}}</td><td><span class="badge {{.BadgeClass}}">{{.Source}}</span></td><td class="num faint">{{.Ago}}</td></tr>{{end}}</tbody>
  </table>
  {{else}}<div class="empty">No domains captured.</div>{{end}}
</section>

<section class="card">
  <h2>Security alerts ({{.AlertCount}})</h2>
  <p class="desc">Newest first. Critical = broadcast storm / possible DoS; Warning = plaintext protocol.</p>
  {{if .HasAlerts}}
  <table>
    <thead><tr><th>Time</th><th>Severity</th><th>Type</th><th>Source</th><th>Message</th></tr></thead>
    <tbody>{{range .Alerts}}<tr><td class="mono muted">{{.Time}}<div class="faint" style="font-size:11px">{{.Ago}}</div></td><td><span class="sev {{.SeverityClass}}">{{.SeverityLabel}}</span></td><td class="mono">{{.Type}}</td><td class="mono">{{.Source}}</td><td>{{.Message}}</td></tr>{{end}}</tbody>
  </table>
  {{else}}<div class="empty">No alerts triggered during this session. System normal.</div>{{end}}
</section>

<footer>GoNetWatch session report &middot; {{.GeneratedAt}} &middot; static SVG charts always available; interactive charts require network access for the Chart.js CDN.</footer>
</div>
<script id="report-data" type="application/json">{{.ChartJSON}}</script>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js" defer onerror="window.__chartFailed=true"></script>
<script>
(function(){
  // Offline-safe domain filter (no library needed).
  var btns = document.querySelectorAll('#domain-filters button');
  btns.forEach(function(b){
    b.addEventListener('click', function(){
      btns.forEach(function(x){x.classList.remove('active')});
      b.classList.add('active');
      var f = b.getAttribute('data-f');
      document.querySelectorAll('#domain-table tbody tr').forEach(function(tr){
        tr.style.display = (f === 'all' || tr.getAttribute('data-src') === f) ? '' : 'none';
      });
    });
  });
  function boot(){
    var badge = document.getElementById('chart-mode');
    try{
      var raw = document.getElementById('report-data').textContent;
      var d = JSON.parse(raw);
      if (window.__chartFailed || typeof window.Chart === 'undefined') return;
      if (!d || (!d.protoLabels.length && !d.talkerLabels.length)) return;
      document.querySelectorAll('.chart-js').forEach(function(el){ el.hidden = false; });
      document.querySelectorAll('.svg-chart').forEach(function(el){ el.style.display = 'none'; });
      Chart.defaults.color = '#9aa3b8';
      Chart.defaults.borderColor = 'rgba(154,163,184,.15)';
      if (d.protoLabels.length){
        new Chart(document.getElementById('protoChart'), {type:'doughnut',
          data:{labels:d.protoLabels, datasets:[{data:d.protoCounts,
            backgroundColor:['#7D56F4','#00C2A8','#FFB020','#FF6B6B','#4EA1FF','#B388FF','#FFD166','#8AC926']}]},
          options:{plugins:{legend:{position:'bottom',labels:{boxWidth:12}}}}});
      }
      if (d.talkerLabels.length){
        new Chart(document.getElementById('talkerChart'), {type:'bar',
          data:{labels:d.talkerLabels, datasets:[{data:d.talkerBytes, backgroundColor:'#7D56F4'}]},
          options:{indexAxis:'y', plugins:{legend:{display:false}}, scales:{x:{beginAtZero:true}}}});
      }
      if (badge) badge.textContent = 'interactive charts';
    }catch(e){ /* keep static SVG fallback */ }
  }
  if (document.readyState === 'complete') boot();
  else window.addEventListener('load', boot);
})();
</script>
</body>
</html>`
