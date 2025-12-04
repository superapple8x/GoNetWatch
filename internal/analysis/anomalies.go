package analysis

import (
	"fmt"
	"gonetwatch/internal/models"
	"sync"
	"time"
)

// AnomalyType represents the type of anomaly detected.
type AnomalyType string

const (
	AnomalyBroadcastStorm AnomalyType = "BROADCAST_STORM"
	AnomalyUnsecure       AnomalyType = "UNSECURE_PROTOCOL"
	AnomalyDoS            AnomalyType = "POSSIBLE_DOS"
)

// Alert represents a detected security anomaly.
type Alert struct {
	Type      AnomalyType
	Source    string // IP or source identifier
	Message   string // Human-readable description
	Timestamp time.Time
}

// AnomalyDetector monitors network traffic for suspicious patterns.
type AnomalyDetector struct {
	mu sync.Mutex

	// Broadcast Storm Detection
	broadcastCount     int
	broadcastWindow    time.Time
	broadcastThreshold int // Trigger alert if > this many broadcasts/sec

	// Unsecure Protocol Detection (throttling)
	unsecureAlerts map[string]time.Time // key: "IP:port" -> last alert time

	// DoS Detection (per-IP packet rate)
	ipPacketCount map[string]int       // IP -> packet count
	ipWindow      map[string]time.Time // IP -> window start time
	dosThreshold  int                  // Trigger alert if > this many packets/sec

	// Alert History (circular buffer)
	alerts    []Alert
	maxAlerts int
}

// NewAnomalyDetector creates a new anomaly detection engine.
func NewAnomalyDetector() *AnomalyDetector {
	return &AnomalyDetector{
		broadcastThreshold: 50,  // 50 broadcasts/sec
		dosThreshold:       500, // 500 packets/sec from single IP
		unsecureAlerts:     make(map[string]time.Time),
		ipPacketCount:      make(map[string]int),
		ipWindow:           make(map[string]time.Time),
		alerts:             make([]Alert, 0),
		maxAlerts:          20, // Keep last 20 alerts
	}
}

// ProcessPacket analyzes a packet for anomalies.
func (ad *AnomalyDetector) ProcessPacket(pkt models.PacketData) {
	ad.mu.Lock()
	defer ad.mu.Unlock()

	now := time.Now()

	// Rule 1: Broadcast Storm Detection
	ad.detectBroadcastStorm(pkt, now)

	// Rule 2: Unsecure Protocol Detection
	ad.detectUnsecureProtocol(pkt, now)

	// Rule 3: DoS Pattern Detection
	ad.detectDoS(pkt, now)
}

// detectBroadcastStorm checks for excessive broadcast packets.
func (ad *AnomalyDetector) detectBroadcastStorm(pkt models.PacketData, now time.Time) {
	// Check if destination MAC is broadcast address
	if pkt.EthDst == "ff:ff:ff:ff:ff:ff" {
		// Reset counter if window expired
		if now.Sub(ad.broadcastWindow) > time.Second {
			ad.broadcastCount = 0
			ad.broadcastWindow = now
		}

		ad.broadcastCount++

		// Trigger alert if threshold exceeded
		if ad.broadcastCount > ad.broadcastThreshold {
			alert := Alert{
				Type:      AnomalyBroadcastStorm,
				Source:    "Network",
				Message:   fmt.Sprintf("Broadcast storm detected: %d broadcasts in 1 second", ad.broadcastCount),
				Timestamp: now,
			}
			ad.addAlert(alert)
			// Reset to avoid spam
			ad.broadcastCount = 0
			ad.broadcastWindow = now
		}
	}
}

// detectUnsecureProtocol checks for plaintext protocol usage.
func (ad *AnomalyDetector) detectUnsecureProtocol(pkt models.PacketData, now time.Time) {
	unsecurePorts := map[int]string{
		80: "HTTP",
		21: "FTP",
		23: "Telnet",
	}

	if protocolName, isUnsecure := unsecurePorts[pkt.DstPort]; isUnsecure {
		// Throttle alerts: max 1 per IP/port combination per 10 seconds
		key := fmt.Sprintf("%s:%d", pkt.SrcIP, pkt.DstPort)
		lastAlert, exists := ad.unsecureAlerts[key]

		if !exists || now.Sub(lastAlert) > 10*time.Second {
			alert := Alert{
				Type:      AnomalyUnsecure,
				Source:    pkt.SrcIP,
				Message:   fmt.Sprintf("Plaintext %s traffic on port %d from %s", protocolName, pkt.DstPort, pkt.SrcIP),
				Timestamp: now,
			}
			ad.addAlert(alert)
			ad.unsecureAlerts[key] = now
		}
	}
}

// detectDoS checks for single-source high packet rate.
func (ad *AnomalyDetector) detectDoS(pkt models.PacketData, now time.Time) {
	if pkt.SrcIP == "" {
		return
	}

	// Initialize window if not exists
	if _, exists := ad.ipWindow[pkt.SrcIP]; !exists {
		ad.ipWindow[pkt.SrcIP] = now
		ad.ipPacketCount[pkt.SrcIP] = 0
	}

	// Reset counter if window expired
	if now.Sub(ad.ipWindow[pkt.SrcIP]) > time.Second {
		ad.ipPacketCount[pkt.SrcIP] = 0
		ad.ipWindow[pkt.SrcIP] = now
	}

	ad.ipPacketCount[pkt.SrcIP]++

	// Trigger alert if threshold exceeded
	if ad.ipPacketCount[pkt.SrcIP] > ad.dosThreshold {
		alert := Alert{
			Type:      AnomalyDoS,
			Source:    pkt.SrcIP,
			Message:   fmt.Sprintf("High packet rate from %s: %d pps", pkt.SrcIP, ad.ipPacketCount[pkt.SrcIP]),
			Timestamp: now,
		}
		ad.addAlert(alert)
		// Reset to avoid spam
		ad.ipPacketCount[pkt.SrcIP] = 0
		ad.ipWindow[pkt.SrcIP] = now
	}
}

// addAlert adds an alert to the history (circular buffer).
func (ad *AnomalyDetector) addAlert(alert Alert) {
	ad.alerts = append(ad.alerts, alert)

	// Keep only last maxAlerts
	if len(ad.alerts) > ad.maxAlerts {
		ad.alerts = ad.alerts[len(ad.alerts)-ad.maxAlerts:]
	}
}

// GetRecentAlerts returns the most recent alerts (thread-safe).
func (ad *AnomalyDetector) GetRecentAlerts(limit int) []Alert {
	ad.mu.Lock()
	defer ad.mu.Unlock()

	if len(ad.alerts) == 0 {
		return []Alert{}
	}

	// Return last N alerts (newest last)
	start := 0
	if len(ad.alerts) > limit {
		start = len(ad.alerts) - limit
	}

	// Make a copy to avoid race conditions
	result := make([]Alert, len(ad.alerts)-start)
	copy(result, ad.alerts[start:])

	return result
}
