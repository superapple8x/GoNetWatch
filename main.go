package main

import (
	"flag"
	"fmt"
	"gonetwatch/internal/analysis"
	"gonetwatch/internal/models"
	"gonetwatch/internal/spoofer"
	"gonetwatch/internal/tshark"
	"gonetwatch/internal/tui"
	"log"

	tea "github.com/charmbracelet/bubbletea"
)

func main() {
	interfaceName := flag.String("i", "", "Network interface to capture from (e.g., eth0, wlan0)")
	targetIP := flag.String("target", "", "Target IP for MITM (requires -gateway)")
	gatewayIP := flag.String("gateway", "", "Gateway IP for MITM (requires -target)")
	flag.Parse()

	if *interfaceName == "" {
		fmt.Println("Please provide an interface name with -i")
		fmt.Println("Example: ./gonetwatch -i wlan0")
		return
	}

	// MITM Setup
	var captureFilter string
	var mitmTarget string
	
	if *targetIP != "" && *gatewayIP != "" {
		fmt.Println("Starting MITM setup...")
		mitmTarget = *targetIP
		
		// 1. Enable IP Forwarding
		if err := spoofer.EnableIPForwarding(); err != nil {
			log.Fatalf("Failed to enable IP forwarding: %v", err)
		}
		defer func() {
			fmt.Println("Disabling IP Forwarding...")
			spoofer.DisableIPForwarding()
		}()

		// 2. Initialize Spoofer Engine
		engine, err := spoofer.NewEngine(*targetIP, *gatewayIP, *interfaceName)
		if err != nil {
			log.Fatalf("Failed to initialize spoofer: %v", err)
		}

		// 3. Start Spoofing
		if err := engine.Start(); err != nil {
			log.Fatalf("Failed to start spoofer: %v", err)
		}
		defer func() {
			fmt.Println("Stopping Spoofer...")
			engine.Stop()
		}()

		// 4. Set Filter to avoid double counting
		// We want to ignore packets originating from our own MAC (re-transmissions)
		captureFilter = fmt.Sprintf("not ether src %s", engine.HostMAC.String())
		fmt.Printf("MITM Active. Filter: %s\n", captureFilter)
	} else if *targetIP != "" || *gatewayIP != "" {
		log.Fatal("Both -target and -gateway must be specified for MITM mode")
	}

	// Create channel for packets
	packetChan := make(chan models.PacketData, 1000)

	// Start Tshark capture
	err := tshark.StartCapture(*interfaceName, captureFilter, packetChan)
	if err != nil {
		log.Fatalf("Error starting capture: %v", err)
	}

	// Initialize analysis engine
	stats := analysis.NewTrafficStats()

	// Background packet processor
	go func() {
		for pkt := range packetChan {
			stats.ProcessPacket(pkt)
		}
	}()

	// Initialize and run the TUI
	// We pass the mitmTarget string to update the UI header
	model := tui.NewAnalysisModel(stats, *interfaceName, mitmTarget)
	p := tea.NewProgram(model, tea.WithAltScreen()) // Use AltScreen for full terminal UI
	
	if _, err := p.Run(); err != nil {
		// TUI exited with error
		log.Printf("Error running TUI: %v", err)
		// Defers will run here
	}
	
	// Normal exit - defers will run
}
