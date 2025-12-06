package reporting

import (
	"gonetwatch/internal/analysis"
	"gonetwatch/internal/models"
	"os"
	"strings"
	"testing"
)

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
