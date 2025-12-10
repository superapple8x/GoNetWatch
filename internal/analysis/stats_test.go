package analysis

import (
	"gonetwatch/internal/models"
	"testing"
	"time"
)

func TestGetTopPorts(t *testing.T) {
	stats := NewTrafficStats()

	// Simulating packets
	// Port 80: 1000 bytes
	stats.ProcessPacket(models.PacketData{
		SrcPort:  80,
		DstPort:  12345,
		Length:   500,
		Protocol: "TCP",
	})
	stats.ProcessPacket(models.PacketData{
		SrcPort:  12345,
		DstPort:  80,
		Length:   500,
		Protocol: "TCP",
	})

	// Port 443: 2000 bytes
	stats.ProcessPacket(models.PacketData{
		SrcPort:  443,
		DstPort:  12345,
		Length:   1000,
		Protocol: "TCP",
	})
	stats.ProcessPacket(models.PacketData{
		SrcPort:  12345,
		DstPort:  443,
		Length:   1000,
		Protocol: "TCP",
	})

	// Port 53: 100 bytes
	stats.ProcessPacket(models.PacketData{
		SrcPort:  53,
		DstPort:  12345,
		Length:   50,
		Protocol: "UDP",
	})
	stats.ProcessPacket(models.PacketData{
		SrcPort:  12345,
		DstPort:  53,
		Length:   50,
		Protocol: "UDP",
	})

	topPorts := stats.GetTopPorts(3)

	if len(topPorts) != 3 {
		t.Fatalf("Expected 3 top ports, got %d", len(topPorts))
	}

	// 12345 should be first (3100 bytes)
	if topPorts[0].Port != 12345 || topPorts[0].Bytes != 3100 {
		t.Errorf("Expected port 12345 with 3100 bytes, got %d with %d bytes", topPorts[0].Port, topPorts[0].Bytes)
	}

	// 443 should be second (2000 bytes)
	if topPorts[1].Port != 443 || topPorts[1].Bytes != 2000 {
		t.Errorf("Expected port 443 with 2000 bytes, got %d with %d bytes", topPorts[1].Port, topPorts[1].Bytes)
	}

	// 80 should be third (1000 bytes)
	if topPorts[2].Port != 80 || topPorts[2].Bytes != 1000 {
		t.Errorf("Expected port 80 with 1000 bytes, got %d with %d bytes", topPorts[2].Port, topPorts[2].Bytes)
	}
}

func TestGlobalBandwidthSmoothing(t *testing.T) {
	stats := NewTrafficStats()
	stats.smoothingWindowCount = 3 // shorten for test predictability

	// Window 1: 1000 bytes over 1s => 8000 bps
	stats.lastTick = time.Now().Add(-1 * time.Second)
	stats.ProcessPacket(models.PacketData{Length: 1000})
	first := stats.GetMetrics()

	// Window 2: No packets, expect smoothed value ~4000 bps
	stats.lastTick = time.Now().Add(-1 * time.Second)
	second := stats.GetMetrics()

	if first.GlobalBps < 7900 || first.GlobalBps > 8100 {
		t.Fatalf("expected first window around 8000 bps, got %.2f", first.GlobalBps)
	}

	if second.GlobalBps <= 2500 || second.GlobalBps >= 5500 {
		t.Fatalf("expected smoothed bandwidth to decay toward zero (around 4000 bps), got %.2f", second.GlobalBps)
	}
}

func TestIPBandwidthSmoothingDecaysWhenInactive(t *testing.T) {
	stats := NewTrafficStats()
	stats.smoothingWindowCount = 3

	// Window 1: traffic for IP
	stats.lastTick = time.Now().Add(-1 * time.Second)
	stats.ProcessPacket(models.PacketData{
		DstIP:  "1.1.1.1",
		Length: 1000,
	})
	first := stats.GetMetrics()

	// Window 2: no traffic; value should be lower but still present
	stats.lastTick = time.Now().Add(-1 * time.Second)
	second := stats.GetMetrics()

	// Window 3: still no traffic; value should decay further
	stats.lastTick = time.Now().Add(-1 * time.Second)
	third := stats.GetMetrics()

	if first.IPBps["1.1.1.1"] <= 0 {
		t.Fatalf("expected initial IP bandwidth > 0, got %.2f", first.IPBps["1.1.1.1"])
	}

	if second.IPBps["1.1.1.1"] >= first.IPBps["1.1.1.1"] {
		t.Fatalf("expected bandwidth to decrease after an empty window, got first=%.2f second=%.2f", first.IPBps["1.1.1.1"], second.IPBps["1.1.1.1"])
	}

	if thirdVal, ok := third.IPBps["1.1.1.1"]; !ok || thirdVal >= second.IPBps["1.1.1.1"] {
		t.Fatalf("expected bandwidth to keep decaying; second=%.2f third=%.2f", second.IPBps["1.1.1.1"], thirdVal)
	}
}
