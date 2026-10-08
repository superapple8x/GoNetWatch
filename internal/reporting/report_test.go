package reporting

import (
	"gonetwatch/internal/analysis"
	"gonetwatch/internal/models"
	"os"
	"strings"
	"testing"
	"time"
)

func waitForDomains(t *testing.T, stats *analysis.TrafficStats, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(stats.GetAllDomains()) >= want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d domains, got %d", want, len(stats.GetAllDomains()))
}

func TestGenerateSessionReport(t *testing.T) {
	// Setup mock stats
	stats := analysis.NewTrafficStats()

	// Simulate some traffic
	pkt1 := models.PacketData{
		SrcIP:    "192.168.1.10",
		DstIP:    "1.1.1.1",
		Length:   500,
		Protocol: "TCP",
		Hostname: "example.com",
		DstPort:  443,
	}
	stats.ProcessPacket(pkt1)

	pkt2 := models.PacketData{
		SrcIP:    "192.168.1.10",
		DstIP:    "8.8.8.8",
		Length:   300,
		Protocol: "UDP",
		Hostname: "google.com",
		DstPort:  53,
	}
	stats.ProcessPacket(pkt2)
	waitForDomains(t, stats, 2)

	// Generate report
	filename, err := GenerateSessionReport(stats, "html")
	if err != nil {
		t.Fatalf("Failed to generate report: %v", err)
	}
	defer os.Remove(filename) // Cleanup

	// Verify file exists
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		t.Fatalf("Report file was not created: %s", filename)
	}

	// Read content
	content, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("Failed to read report file: %v", err)
	}
	html := string(content)

	// Verify content
	if !strings.Contains(html, "GoNetWatch Session Report") {
		t.Error("Report missing title")
	}
	if !strings.Contains(html, "example.com") {
		t.Error("Report missing domain example.com")
	}
	if !strings.Contains(html, "google.com") {
		t.Error("Report missing domain google.com")
	}
	if !strings.Contains(html, "192.168.1.10") {
		t.Error("Report missing source IP")
	}
}

func TestReportReadableFormatting(t *testing.T) {
	stats := analysis.NewTrafficStats()
	stats.ProcessPacket(models.PacketData{SrcIP: "10.0.0.1", DstIP: "1.1.1.1", Length: 2048, Protocol: "TCP", SrcPort: 12345, DstPort: 443, Hostname: "video.example.com"})
	stats.ProcessPacket(models.PacketData{SrcIP: "10.0.0.2", DstIP: "8.8.8.8", Length: 1024, Protocol: "UDP", SrcPort: 54321, DstPort: 53, Hostname: "dns.example.org"})
	stats.ProcessPacket(models.PacketData{SrcIP: "10.0.0.1", DstIP: "9.9.9.9", Length: 512, Protocol: "TCP", SrcPort: 12345, DstPort: 80})
	waitForDomains(t, stats, 2)

	meta := SessionMeta{Interface: "eth0", MitmTarget: "10.0.0.1", StartTime: time.Now().Add(-90 * time.Second), EndTime: time.Now()}
	filename, err := GenerateSessionReportWithMeta(stats, meta, "html")
	if err != nil {
		t.Fatalf("GenerateSessionReportWithMeta: %v", err)
	}
	defer os.Remove(filename)

	raw, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	html := string(raw)

	checks := []string{
		"data-theme=\"dark\"",
		"eth0",
		"10.0.0.1", // mitm target + talker
		"Total data",
		"2.0 KB",   // human bytes for a talker (2048+512=2560 -> 2.5 KB; 2048 alone -> 2.0 KB)
		"Protocols",
		"Top ports",
		"443",
		"badge-sni",
		"badge-dns",
		"chart.js",
		"report-data",
		"static SVG charts always available",
		"<svg",
		"1m 30s", // duration
	}
	for _, want := range checks {
		if !strings.Contains(html, want) {
			t.Errorf("report missing %q", want)
		}
	}
	if strings.Contains(html, "No domains captured.") {
		t.Error("expected domains to be listed, got empty state")
	}
}

func TestReportEscapesHTML(t *testing.T) {
	stats := analysis.NewTrafficStats()
	evil := `<script>alert("x")</script>.example.com`
	stats.ProcessPacket(models.PacketData{SrcIP: "10.0.0.9", DstIP: "1.1.1.1", Length: 100, Protocol: "TCP", DstPort: 443, Hostname: evil})
	waitForDomains(t, stats, 1)

	filename, err := GenerateSessionReport(stats, "html")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	defer os.Remove(filename)
	raw, _ := os.ReadFile(filename)
	html := string(raw)
	if strings.Contains(html, evil) {
		t.Error("report contains unescaped hostname")
	}
	if !strings.Contains(html, "&lt;script&gt;") {
		t.Error("expected escaped <script> in report")
	}
}

func TestReportEmptyState(t *testing.T) {
	stats := analysis.NewTrafficStats()
	filename, err := GenerateSessionReport(stats, "html")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	defer os.Remove(filename)
	raw, _ := os.ReadFile(filename)
	html := string(raw)
	for _, want := range []string{"No traffic captured", "No protocol data.", "No port data.", "No domains captured.", "System normal"} {
		if !strings.Contains(html, want) {
			t.Errorf("empty report missing %q", want)
		}
	}
}

func TestStatsSessionCounters(t *testing.T) {
	stats := analysis.NewTrafficStats()
	if stats.GetStartTime().IsZero() {
		t.Error("expected non-zero start time")
	}
	if stats.GetTotalPackets() != 0 {
		t.Errorf("expected 0 packets, got %d", stats.GetTotalPackets())
	}
	stats.ProcessPacket(models.PacketData{Length: 10})
	stats.ProcessPacket(models.PacketData{Length: 20})
	if got := stats.GetTotalPackets(); got != 2 {
		t.Errorf("expected 2 packets, got %d", got)
	}
	if got := stats.GetTotalDataTransferred(); got != 30 {
		t.Errorf("expected 30 bytes, got %d", got)
	}
}
