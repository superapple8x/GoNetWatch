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
}
