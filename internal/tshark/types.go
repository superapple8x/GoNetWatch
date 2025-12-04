package tshark

// EkPacket represents the top-level structure of a Tshark -T ek output line.
type EkPacket struct {
	Timestamp string   `json:"timestamp"`
	Layers    EkLayers `json:"layers"`
}

// EkLayers holds the specific protocol layers we are interested in.
// When using -e flags with -T ek, tshark flattens the structure and replaces dots with underscores.
type EkLayers struct {
	FrameLen   []string `json:"frame_len,omitempty"`
	IPSrc      []string `json:"ip_src,omitempty"`
	IPDst      []string `json:"ip_dst,omitempty"`
	TCPSrcPort []string `json:"tcp_srcport,omitempty"`
	TCPDstPort []string `json:"tcp_dstport,omitempty"`
	UDPSrcPort []string `json:"udp_srcport,omitempty"`
	UDPDstPort []string `json:"udp_dstport,omitempty"`

	// Layer 7 Metadata (Phase 5)
	DnsQuery []string `json:"dns_qry_name,omitempty"`
	TlsSni   []string `json:"tls_handshake_extensions_server_name,omitempty"`
	HttpHost []string `json:"http_host,omitempty"`
	EthDst   []string `json:"eth_dst,omitempty"`
}
