package models

import "time"

// PacketData holds the extracted information from a network packet.
type PacketData struct {
	Timestamp time.Time
	SrcIP     string
	DstIP     string
	SrcPort   int
	DstPort   int
	Protocol  string
	Length    int

	// Layer 7 Metadata (Phase 5)
	Hostname string // Best available hostname (SNI > DNS > HTTP)
	EthDst   string // Destination MAC address (for broadcast detection)
}
