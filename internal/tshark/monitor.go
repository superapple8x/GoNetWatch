package tshark

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"gonetwatch/internal/models"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// StartCapture begins the tshark process and streams parsed packets to the out channel.
func StartCapture(ctx context.Context, interfaceName string, captureFilter string, out chan<- models.PacketData) error {
	// Construct the tshark command
	// -l: flush stdout after each packet
	// -n: disable name resolution
	// -T ek: output in Elasticsearch JSON format
	// -e ...: fields to extract
	args := []string{
		"-l", "-n", "-T", "ek",
		"-e", "frame.len",
		"-e", "ip.src", "-e", "ip.dst",
		"-e", "tcp.srcport", "-e", "tcp.dstport",
		"-e", "udp.srcport", "-e", "udp.dstport",
		"-e", "dns.qry.name",
		"-e", "tls.handshake.extensions_server_name",
		"-e", "http.host",
		"-e", "eth.dst",
	}

	if interfaceName != "" {
		args = append([]string{"-i", interfaceName}, args...)
	}

	if captureFilter != "" {
		args = append(args, "-f", captureFilter)
	}

	cmd := exec.CommandContext(ctx, "tshark", args...)

	cmd.Stderr = os.Stderr

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to get stdout pipe: %v", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start tshark: %v", err)
	}

	go func() {
		scanner := bufio.NewScanner(stdout)

		// Wait for command to finish (which happens when context is canceled)
		defer func() {
			cmd.Wait()
		}()

		for scanner.Scan() {
			line := scanner.Text()

			if strings.TrimSpace(line) == "" {
				continue
			}

			// Tshark -T ek outputs an index line before each packet sometimes, or just packet lines.
			// We look for lines containing "layers".
			if !strings.Contains(line, "\"layers\"") {
				continue
			}

			var ekPkt EkPacket
			if err := json.Unmarshal([]byte(line), &ekPkt); err != nil {
				// Skip malformed lines
				continue
			}

			pkt := convertToModel(ekPkt)
			if pkt != nil {
				out <- *pkt
			}
		}
	}()

	return nil
}

func convertToModel(ek EkPacket) *models.PacketData {
	// We need at least IP info
	// Check flattened structure fields
	if len(ek.Layers.IPSrc) == 0 && len(ek.Layers.IPDst) == 0 {
		return nil
	}

	p := &models.PacketData{
		Timestamp: time.Now(), // Use current time or parse ek.Timestamp
	}

	// Extract Length
	if len(ek.Layers.FrameLen) > 0 {
		if val, err := strconv.Atoi(ek.Layers.FrameLen[0]); err == nil {
			p.Length = val
		}
	}

	// Extract IP
	if len(ek.Layers.IPSrc) > 0 {
		p.SrcIP = ek.Layers.IPSrc[0]
	}
	if len(ek.Layers.IPDst) > 0 {
		p.DstIP = ek.Layers.IPDst[0]
	}

	// Extract Ports & Protocol
	// Check flattened TCP ports
	if len(ek.Layers.TCPSrcPort) > 0 || len(ek.Layers.TCPDstPort) > 0 {
		p.Protocol = "TCP"
		if len(ek.Layers.TCPSrcPort) > 0 {
			p.SrcPort, _ = strconv.Atoi(ek.Layers.TCPSrcPort[0])
		}
		if len(ek.Layers.TCPDstPort) > 0 {
			p.DstPort, _ = strconv.Atoi(ek.Layers.TCPDstPort[0])
		}
	} else if len(ek.Layers.UDPSrcPort) > 0 || len(ek.Layers.UDPDstPort) > 0 {
		p.Protocol = "UDP"
		if len(ek.Layers.UDPSrcPort) > 0 {
			p.SrcPort, _ = strconv.Atoi(ek.Layers.UDPSrcPort[0])
		}
		if len(ek.Layers.UDPDstPort) > 0 {
			p.DstPort, _ = strconv.Atoi(ek.Layers.UDPDstPort[0])
		}
	} else {
		// Might be ICMP or other IP protocol
		p.Protocol = "OTHER"
	}

	// Extract Hostname (Phase 5) - Priority: TLS SNI > DNS Query > HTTP Host
	if len(ek.Layers.TlsSni) > 0 && ek.Layers.TlsSni[0] != "" {
		p.Hostname = ek.Layers.TlsSni[0]
	} else if len(ek.Layers.DnsQuery) > 0 && ek.Layers.DnsQuery[0] != "" {
		p.Hostname = ek.Layers.DnsQuery[0]
	} else if len(ek.Layers.HttpHost) > 0 && ek.Layers.HttpHost[0] != "" {
		p.Hostname = ek.Layers.HttpHost[0]
	}

	// Extract Ethernet Destination MAC (for broadcast detection)
	if len(ek.Layers.EthDst) > 0 {
		p.EthDst = ek.Layers.EthDst[0]
	}

	return p
}
