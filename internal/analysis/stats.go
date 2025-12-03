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

// TrafficStats tracks network statistics.
type TrafficStats struct {
	mu             sync.Mutex
	totalBytes     int64
	windowBytes    int64
	windowPackets  int64
	lastTick       time.Time
	ipBytes        map[string]int
	protocolCounts map[string]int64
}

// NewTrafficStats creates a new TrafficStats instance.
func NewTrafficStats() *TrafficStats {
	return &TrafficStats{
		lastTick:       time.Now(),
		ipBytes:        make(map[string]int),
		protocolCounts: make(map[string]int64),
	}
}

// ProcessPacket updates stats with a new packet.
func (s *TrafficStats) ProcessPacket(pkt models.PacketData) {
	s.mu.Lock()
	defer s.mu.Unlock()

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
