package analysis

import (
	"gonetwatch/internal/models"
	"sort"
	"sync"
	"time"
)

// IPStat holds stats for a single IP.
type IPStat struct {
	IP    string
	Bytes int
}

// ProtocolStat holds stats for a single protocol.
type ProtocolStat struct {
	Protocol string
	Count    int64
}

// DomainEntry represents a captured domain name with metadata.
type DomainEntry struct {
	Hostname  string
	Timestamp time.Time
	Source    string // "SNI", "DNS", or "HTTP"
}

// TrafficStats tracks network statistics.
type TrafficStats struct {
	mu             sync.Mutex // Protects basic stats
	totalBytes     int64
	windowBytes    int64
	windowPackets  int64
	lastTick       time.Time
	ipBytes        map[string]int
	protocolCounts map[string]int64

	// Phase 5: Deep Inspection (Async Pipeline)
	analysisChan    chan models.PacketData
	domainMu        sync.Mutex // Protects domain logging
	domainLog       []DomainEntry
	maxDomainLog    int
	allDomains      map[string]DomainEntry // Full history for session report
	anomalyDetector *AnomalyDetector
}

// NewTrafficStats creates a new TrafficStats instance.
func NewTrafficStats() *TrafficStats {
	s := &TrafficStats{
		lastTick:        time.Now(),
		ipBytes:         make(map[string]int),
		protocolCounts:  make(map[string]int64),
		analysisChan:    make(chan models.PacketData, 2048), // Buffer for analysis
		domainLog:       make([]DomainEntry, 0),
		maxDomainLog:    50, // Keep last 50 domain entries for UI
		allDomains:      make(map[string]DomainEntry),
		anomalyDetector: NewAnomalyDetector(DefaultConfig()),
	}

	// Start background analysis worker
	go s.analysisWorker()

	return s
}

// ProcessPacket updates stats with a new packet.
// This is the "Fast Path" - keep it lightweight!
func (s *TrafficStats) ProcessPacket(pkt models.PacketData) {
	s.mu.Lock()

	s.totalBytes += int64(pkt.Length)
	s.windowBytes += int64(pkt.Length)
	s.windowPackets++

	// Update Top Talkers (Source IP)
	if pkt.SrcIP != "" {
		s.ipBytes[pkt.SrcIP] += pkt.Length
	}

	// Update Protocol Distribution
	// Use a default if protocol is empty (though tshark usually provides it)
	proto := pkt.Protocol
	if proto == "" {
		proto = "Unknown"
	}
	s.protocolCounts[proto]++
	s.mu.Unlock()

	// Send to analysis worker (Non-blocking drop if full)
	select {
	case s.analysisChan <- pkt:
	default:
		// Channel full: Drop packet for analysis ONLY.
		// We already counted it for bandwidth stats, so accuracy is preserved.
	}
}

// analysisWorker processes packets for Deep Inspection and Anomaly Detection.
func (s *TrafficStats) analysisWorker() {
	for pkt := range s.analysisChan {
		// 1. Domain Logging
		if pkt.Hostname != "" {
			s.domainMu.Lock()
			// Determine source type based on which field was populated
			source := "HTTP"
			if pkt.DstPort == 443 || pkt.DstPort == 853 {
				source = "SNI" // HTTPS or DNS over TLS
			} else if pkt.DstPort == 53 || pkt.Protocol == "UDP" {
				source = "DNS" // DNS query
			}

			entry := DomainEntry{
				Hostname:  pkt.Hostname,
				Timestamp: time.Now(),
				Source:    source,
			}
			s.domainLog = append(s.domainLog, entry)

			// Keep circular buffer (last N entries) for UI
			if len(s.domainLog) > s.maxDomainLog {
				s.domainLog = s.domainLog[len(s.domainLog)-s.maxDomainLog:]
			}

			// Keep full history for report (unique domains)
			if _, exists := s.allDomains[pkt.Hostname]; !exists {
				s.allDomains[pkt.Hostname] = entry
			}
			s.domainMu.Unlock()
		}

		// 2. Anomaly Detection
		// AnomalyDetector has its own internal locking, so this is safe.
		s.anomalyDetector.ProcessPacket(pkt)
	}
}

// GetRates returns the bandwidth (bps) and packet rate (pps) since the last call.
func (s *TrafficStats) GetRates() (float64, float64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	duration := now.Sub(s.lastTick).Seconds()
	if duration == 0 {
		return 0, 0
	}

	// Bytes * 8 = Bits
	bps := (float64(s.windowBytes) * 8) / duration
	pps := float64(s.windowPackets) / duration

	// Reset window
	s.windowBytes = 0
	s.windowPackets = 0
	s.lastTick = now

	return bps, pps
}

// GetBandwidth returns the bandwidth in bits per second since the last call.
// Deprecated: Use GetRates instead.
func (s *TrafficStats) GetBandwidth() float64 {
	bps, _ := s.GetRates()
	return bps
}

// GetTopTalkers returns the top N IPs by volume.
func (s *TrafficStats) GetTopTalkers(limit int) []IPStat {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Convert map to slice
	stats := make([]IPStat, 0, len(s.ipBytes))
	for ip, bytes := range s.ipBytes {
		stats = append(stats, IPStat{IP: ip, Bytes: bytes})
	}

	// Sort descending by bytes
	sort.Slice(stats, func(i, j int) bool {
		return stats[i].Bytes > stats[j].Bytes
	})

	// Limit results
	if len(stats) > limit {
		return stats[:limit]
	}
	return stats
}

// GetProtocolStats returns the protocol distribution.
func (s *TrafficStats) GetProtocolStats() []ProtocolStat {
	s.mu.Lock()
	defer s.mu.Unlock()

	stats := make([]ProtocolStat, 0, len(s.protocolCounts))
	for proto, count := range s.protocolCounts {
		stats = append(stats, ProtocolStat{Protocol: proto, Count: count})
	}

	// Sort descending by count
	sort.Slice(stats, func(i, j int) bool {
		return stats[i].Count > stats[j].Count
	})

	return stats
}

// GetDomainLog returns the recent domain log entries (Phase 5).
func (s *TrafficStats) GetDomainLog() []DomainEntry {
	s.domainMu.Lock()
	defer s.domainMu.Unlock()

	// Return a copy to avoid race conditions
	result := make([]DomainEntry, len(s.domainLog))
	copy(result, s.domainLog)
	return result
}

// GetAlerts returns recent security alerts (Phase 5).
func (s *TrafficStats) GetAlerts() []Alert {
	// Anomaly detector has its own mutex, no need to lock here
	return s.anomalyDetector.GetRecentAlerts(5)
}

// GetAllDomains returns all unique domains visited during the session.
func (s *TrafficStats) GetAllDomains() []DomainEntry {
	s.domainMu.Lock()
	defer s.domainMu.Unlock()

	domains := make([]DomainEntry, 0, len(s.allDomains))
	for _, entry := range s.allDomains {
		domains = append(domains, entry)
	}
	// Sort by timestamp
	sort.Slice(domains, func(i, j int) bool {
		return domains[i].Timestamp.Before(domains[j].Timestamp)
	})
	return domains
}

// GetTotalDataTransferred returns the total bytes processed.
func (s *TrafficStats) GetTotalDataTransferred() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.totalBytes
}

// GetAllAlerts returns all alerts generated during the session.
func (s *TrafficStats) GetAllAlerts() []Alert {
	return s.anomalyDetector.GetAllAlerts()
}
