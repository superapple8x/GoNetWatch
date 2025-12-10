package tshark

import (
	"bufio"
	"context"
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
	// -T fields: output specific fields (TSV by default)
	// -e ...: fields to extract
	args := []string{
		"-l", "-n", "-T", "fields",
		// Field order MUST match the parsing logic below
		"-e", "frame.len", // 0
		"-e", "ip.src", // 1
		"-e", "ip.dst", // 2
		"-e", "tcp.srcport", // 3
		"-e", "tcp.dstport", // 4
		"-e", "udp.srcport", // 5
		"-e", "udp.dstport", // 6
		"-e", "dns.qry.name", // 7
		"-e", "tls.handshake.extensions_server_name", // 8
		"-e", "http.host", // 9
		"-e", "eth.dst", // 10
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

		// Wait for command to finish
		defer func() {
			cmd.Wait()
		}()

		for scanner.Scan() {
			line := scanner.Text()
			if line == "" {
				continue
			}

			// Tshark -T fields uses tab as default separator
			fields := strings.Split(line, "\t")

			// Ensure we have enough fields (we asked for 11 fields)
			if len(fields) < 11 {
				continue
			}

			// Parse the fields into PacketData
			pkt := models.PacketData{
				Timestamp: time.Now(),
			}

			// 0: frame.len
			if len(fields[0]) > 0 {
				if l, err := strconv.Atoi(fields[0]); err == nil {
					pkt.Length = l
				}
			}

			// 1: ip.src
			pkt.SrcIP = fields[1]

			// 2: ip.dst
			pkt.DstIP = fields[2]

			// Determine Protocol & Ports
			// 3: tcp.srcport, 4: tcp.dstport
			if len(fields[3]) > 0 {
				pkt.Protocol = "TCP"
				pkt.SrcPort, _ = strconv.Atoi(fields[3])
				pkt.DstPort, _ = strconv.Atoi(fields[4])
			} else if len(fields[5]) > 0 {
				// 5: udp.srcport, 6: udp.dstport
				pkt.Protocol = "UDP"
				pkt.SrcPort, _ = strconv.Atoi(fields[5])
				pkt.DstPort, _ = strconv.Atoi(fields[6])
			} else {
				pkt.Protocol = "OTHER"
			}

			// Layer 7 Metadata (Phase 5)
			// Priority: TLS SNI > DNS > HTTP
			// Note: tshark might return multiple comma-separated values for a field if multiple layers match
			// We usually take the first one.

			// 8: tls.handshake.extensions_server_name
			if len(fields[8]) > 0 {
				pkt.Hostname = strings.Split(fields[8], ",")[0]
			} else if len(fields[7]) > 0 {
				// 7: dns.qry.name
				pkt.Hostname = strings.Split(fields[7], ",")[0]
			} else if len(fields[9]) > 0 {
				// 9: http.host
				pkt.Hostname = strings.Split(fields[9], ",")[0]
			}

			// 10: eth.dst
			pkt.EthDst = fields[10]

			// Filter: If we didn't get IP src/dst, it might be a non-IP frame (ARP, etc)
			// But we still want to count its bytes if possible.
			// However, TrafficStats mainly keys off IP.
			// Let's pass it if we have at least a length.
			if pkt.Length > 0 {
				out <- pkt
			}
		}
	}()

	return nil
}
