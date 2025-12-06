package discovery

import (
	"bytes"
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

// Scan performs an ARP scan on the specified interface to discover hosts.
// It returns a list of discovered hosts.
func Scan(interfaceName string) ([]Host, error) {
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
	handle, err := pcap.OpenLive(interfaceName, 65536, true, pcap.BlockForever)
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
	// Note: This can be optimized.
	ips := ipsInSubnet(localNet)
	for _, targetIP := range ips {
		// Don't scan network address, broadcast, or self
		if targetIP.Equal(localIP) || targetIP.Equal(localNet.IP) {
			continue
		}

		if err := sendARPRequest(handle, iface, localIP, targetIP); err != nil {
			// Log error but continue?
			continue
		}
		// Small delay to avoid flooding
		time.Sleep(2 * time.Millisecond)
	}

	// Wait for replies
	time.Sleep(2 * time.Second)
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

// ipsInSubnet returns all IPs in the subnet
func ipsInSubnet(ipnet *net.IPNet) []net.IP {
	var ips []net.IP
	for ip := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		newIP := make(net.IP, len(ip))
		copy(newIP, ip)
		ips = append(ips, newIP)
	}
	// Remove network address and broadcast address if possible,
	// but the loop above includes them. The caller handles filtering.
	if len(ips) > 2 {
		return ips[1 : len(ips)-1]
	}
	return ips
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
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
