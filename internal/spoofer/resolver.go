package spoofer

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// GetMAC resolves the MAC address for a given IP on the specified network interface.
// It sends an ARP broadcast request and waits for a reply.
func GetMAC(ipStr string, interfaceName string) (net.HardwareAddr, error) {
	targetIP := net.ParseIP(ipStr)
	if targetIP == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ipStr)
	}

	// Get interface details
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return nil, fmt.Errorf("failed to get interface %s: %v", interfaceName, err)
	}

	// Open up a pcap handle for packet reads/writes
	handle, err := pcap.OpenLive(interfaceName, 65536, true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("failed to open handle: %v", err)
	}
	defer handle.Close()

	// Find our source IP for the ARP packet
	var srcIP net.IP
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("failed to get interface addresses: %v", err)
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok {
			if ipnet.IP.To4() != nil {
				srcIP = ipnet.IP
				break
			}
		}
	}
	if srcIP == nil {
		return nil, errors.New("could not determine source IP for interface")
	}

	// Construct ARP Request
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
		DstProtAddress:    []byte(targetIP.To4()),
	}

	// Serialize packet
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	if err := gopacket.SerializeLayers(buf, opts, &eth, &arp); err != nil {
		return nil, fmt.Errorf("failed to serialize packet: %v", err)
	}

	// Send packet
	if err := handle.WritePacketData(buf.Bytes()); err != nil {
		return nil, fmt.Errorf("failed to write packet: %v", err)
	}

	// Wait for reply
	start := time.Now()
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	
	// Set a timeout logic loop
	timeout := 3 * time.Second

	for {
		if time.Since(start) > timeout {
			return nil, errors.New("timeout waiting for ARP reply")
		}

		select {
		case packet := <-packetSource.Packets():
			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer != nil {
				arpPacket, _ := arpLayer.(*layers.ARP)
				// Check if it's a reply for us and from the target IP
				if arpPacket.Operation == layers.ARPReply &&
					net.IP(arpPacket.SourceProtAddress).Equal(targetIP) {
					return net.HardwareAddr(arpPacket.SourceHwAddress), nil
				}
			}
		case <-time.After(100 * time.Millisecond):
			// check timeout in outer loop
			continue
		}
	}
}

