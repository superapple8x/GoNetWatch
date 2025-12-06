package discovery

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// ScanConfig controls the scanning behavior.
type ScanConfig struct {
	// RateLimit introduces a delay between ARP requests to avoid overrunning buffers.
	// Defaults to 50µs if unset or <= 0.
	RateLimit time.Duration
	// IdleWait is how long to wait for late replies after sending probes.
	// Defaults to 500ms if unset or <= 0.
	IdleWait time.Duration
	// MaxHosts caps how many hosts we will probe in large subnets to avoid long scans.
	// Defaults to 4096 if unset. Set to 0 or a negative number to disable the cap.
	MaxHosts int
	// Promisc controls whether we open the interface in promiscuous mode.
	// Defaults to true if unset.
	Promisc *bool
}

func applyDefaults(cfg *ScanConfig) ScanConfig {
	if cfg == nil {
		return ScanConfig{
			RateLimit: 50 * time.Microsecond,
			IdleWait:  500 * time.Millisecond,
			MaxHosts:  4096,
			Promisc:   ptrBool(true),
		}
	}

	out := *cfg
	if out.RateLimit <= 0 {
		out.RateLimit = 50 * time.Microsecond
	}
	if out.IdleWait <= 0 {
		out.IdleWait = 500 * time.Millisecond
	}
	if out.MaxHosts == 0 {
		// Explicitly disable cap when zero.
		out.MaxHosts = -1
	} else if out.MaxHosts < 0 {
		out.MaxHosts = -1
	}
	if out.MaxHosts > 0 && out.MaxHosts < 512 {
		// Keep a sane minimum if capped.
		out.MaxHosts = 512
	}
	if out.Promisc == nil {
		out.Promisc = ptrBool(true)
	}
	return out
}

// Scan performs an ARP scan on the specified interface to discover hosts.
// It returns a list of discovered hosts.
func Scan(ctx context.Context, interfaceName string, cfg *ScanConfig) ([]Host, error) {
	config := applyDefaults(cfg)

	// Get interface details
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return nil, fmt.Errorf("could not get interface: %v", err)
	}

	// Get local IP and netmask
	var localIP net.IP
	var localNet *net.IPNet
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("could not get interface addresses: %v", err)
	}

	foundIPv4 := false
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok {
			if ip4 := ipnet.IP.To4(); ip4 != nil {
				localIP = ip4
				localNet = ipnet
				foundIPv4 = true
				break
			}
		}
	}

	if !foundIPv4 {
		return nil, errors.New("no IPv4 address found on interface")
	}

	// Open handle for reading and writing
	handle, err := pcap.OpenLive(interfaceName, 65536, *config.Promisc, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("could not open handle: %v", err)
	}
	defer handle.Close()

	// Set filter to only see ARP replies
	if err := handle.SetBPFFilter("arp"); err != nil {
		return nil, fmt.Errorf("could not set BPF filter: %v", err)
	}

	// Channel to collect results
	hostsChan := make(chan Host)
	doneChan := make(chan struct{})

	// Map to store unique hosts
	discoveredHosts := make(map[string]Host)
	var mu sync.Mutex

	// Start reading packets in a goroutine
	go func() {
		src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
		in := src.Packets()

		for {
			select {
			case <-ctx.Done():
				return
			case <-doneChan:
				return
			case packet, ok := <-in:
				if !ok {
					return
				}
				arpLayer := packet.Layer(layers.LayerTypeARP)
				if arpLayer == nil {
					continue
				}
				arp := arpLayer.(*layers.ARP)

				// We only care about replies (Operation 2)
				if arp.Operation != layers.ARPReply {
					continue
				}

				// Check if the reply is from our subnet
				ip := net.IP(arp.SourceProtAddress)
				if !localNet.Contains(ip) {
					continue
				}

				// Ignore our own IP
				if ip.Equal(localIP) {
					continue
				}

				mac := net.HardwareAddr(arp.SourceHwAddress)

				host := Host{
					IP:  ip,
					MAC: mac,
				}
				hostsChan <- host
			}
		}
	}()

	// Send ARP requests
	// We'll iterate through all IPs in the subnet and send an ARP request
	// This is a simple implementation. For larger subnets, this might be slow.
	// Assuming /24 for simplicity or iterating appropriately.

	// Calculate start and end IP
	// ip := localIP.Mask(localNet.Mask) // Unused

	// Simple iteration for /24 or smaller.
	// For this MVP, we'll just assume standard iteration logic or use a helper.

	// Start a goroutine to collect results while we send
	go func() {
		for host := range hostsChan {
			mu.Lock()
			if _, exists := discoveredHosts[host.IP.String()]; !exists {
				discoveredHosts[host.IP.String()] = host
			}
			mu.Unlock()
		}
	}()

	// Send ARP requests
	// We iterate through the subnet.
	// Optimization: Iterator approach to avoid pre-allocating millions of IPs for large subnets.

	// Calculate network address (start)
	// Calculate network address (start)
	// We use localIP which we forced to 4 bytes earlier. localNet.IP might be 16 bytes.
	currentIP := make(net.IP, len(localIP))
	copy(currentIP, localIP)
	mask := localNet.Mask

	// Ensure mask is used safely.
	// If mask is 4 bytes, currentIP (4 bytes) is safe.
	// If mask is 16 bytes, we only use the first 4 bytes since currentIP is 4 bytes.
	for i := range currentIP {
		if i < len(mask) {
			currentIP[i] &= mask[i]
		}
	}

	// Calculate broadcast address for filtering
	broadcastIP := make(net.IP, len(currentIP))
	copy(broadcastIP, currentIP)
	for i := range broadcastIP {
		if i < len(mask) {
			broadcastIP[i] |= ^mask[i]
		}
	}

	// Use a ticker to limit the rate slightly to avoid overwhelming the local buffer
	ticker := time.NewTicker(config.RateLimit)
	defer ticker.Stop()

	// Flag to skip the very first IP (Network Address) if it matches currentIP
	// (It will match initially)
	first := true
	scanned := 0

	for ; localNet.Contains(currentIP); inc(currentIP) {
		// Cap scan size for very large subnets
		if config.MaxHosts > 0 && scanned >= config.MaxHosts {
			break
		}

		// Check context
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
		}

		// Clone IP for sending because inc modifies it in place,
		// and while sendARPRequest doesn't store it, it's safer/cleaner to use a copy
		// if we were passing it to a goroutine.
		// Here, sendARPRequest uses it synchronously for serialization.
		// However, we need to be careful about not skipping the first one if logic demands,
		// but typically we skip network address (first) and broadcast (last).

		if first {
			first = false
			continue // Skip network address
		}

		if currentIP.Equal(broadcastIP) {
			continue // Skip broadcast address
		}

		// Don't scan self
		if currentIP.Equal(localIP) {
			continue
		}

		if err := sendARPRequest(handle, iface, localIP, currentIP); err != nil {
			// Log error but continue?
			continue
		}
		scanned++
	}

	// Wait for replies for a short period, or until context is done
	// We already have a goroutine reading into hostsChan.
	// We just need to wait a bit for stragglers.

	waitTimer := time.NewTimer(config.IdleWait)
	defer waitTimer.Stop()

	select {
	case <-ctx.Done():
	case <-waitTimer.C:
	}

	close(doneChan)
	close(hostsChan)

	// Convert map to slice
	mu.Lock()
	defer mu.Unlock()

	result := make([]Host, 0, len(discoveredHosts))
	for _, host := range discoveredHosts {
		result = append(result, host)
	}

	// Sort by IP
	sort.Slice(result, func(i, j int) bool {
		return bytes.Compare(result[i].IP, result[j].IP) < 0
	})

	return result, nil
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func ptrBool(v bool) *bool {
	return &v
}

// sendARPRequest sends a single ARP request
func sendARPRequest(handle *pcap.Handle, iface *net.Interface, srcIP, dstIP net.IP) error {
	eth := layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(iface.HardwareAddr),
		SourceProtAddress: []byte(srcIP.To4()),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    []byte(dstIP.To4()),
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	if err := gopacket.SerializeLayers(buf, opts, &eth, &arp); err != nil {
		return err
	}
	return handle.WritePacketData(buf.Bytes())
}
