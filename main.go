package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"gonetwatch/internal/analysis"
	"gonetwatch/internal/discovery"
	"gonetwatch/internal/models"
	"gonetwatch/internal/spoofer"
	"gonetwatch/internal/tshark"
	"gonetwatch/internal/tui"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

func main() {
	interfaceName := flag.String("i", "", "Network interface to capture from (e.g., eth0, wlan0)")
	targetIP := flag.String("target", "", "Target IP for MITM (requires -gateway)")
	gatewayIP := flag.String("gateway", "", "Gateway IP for MITM (requires -target)")
	scanTimeout := flag.Duration("scan-timeout", 10*time.Second, "Timeout for network discovery scan")
	scanIdleWait := flag.Duration("scan-idle-wait", 500*time.Millisecond, "Time to wait for late ARP replies after probing")
	scanRate := flag.Duration("scan-rate", 50*time.Microsecond, "Delay between ARP probe sends during discovery")
	scanMaxHosts := flag.Int("scan-max-hosts", 4096, "Maximum hosts to probe during discovery (caps large subnets). Set 0 or negative to scan the full subnet.")
	scanPromisc := flag.Bool("scan-promisc", true, "Open capture in promiscuous mode during discovery")
	flag.Parse()

	if *interfaceName == "" {
		fmt.Println("Please provide an interface name with -i")
		fmt.Println("Example: ./gonetwatch -i wlan0")
		return
	}

	// MITM Setup
	var captureFilter string
	var mitmTarget string

	// Interactive Discovery if target is not specified
	if *targetIP == "" {
		fmt.Printf("No target specified. Scanning network on %s...\n", *interfaceName)

		// Create a context with a timeout for the scan
		scanCtx, scanCancel := context.WithTimeout(context.Background(), *scanTimeout)
		defer scanCancel()

		hosts, err := discovery.Scan(scanCtx, *interfaceName, &discovery.ScanConfig{
			RateLimit: *scanRate,
			IdleWait:  *scanIdleWait,
			MaxHosts:  *scanMaxHosts,
			Promisc:   scanPromisc,
		})
		if err != nil {
			if err == context.DeadlineExceeded {
				fmt.Println("Scan timed out.")
			} else {
				log.Fatalf("Network scan failed: %v", err)
			}
		}

		if len(hosts) == 0 {
			fmt.Println("No hosts found.")
			return
		}

		fmt.Println("\nAvailable Targets:")
		for i, host := range hosts {
			fmt.Printf("[%d] IP: %s\tMAC: %s\n", i+1, host.IP, host.MAC)
		}

		reader := bufio.NewReader(os.Stdin)
		fmt.Print("\nSelect target (number): ")
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)
		index, err := strconv.Atoi(input)
		if err != nil || index < 1 || index > len(hosts) {
			log.Fatal("Invalid selection")
		}

		selectedHost := hosts[index-1]
		*targetIP = selectedHost.IP.String()
		fmt.Printf("Selected Target: %s\n", *targetIP)

		// Ask for Gateway
		fmt.Print("Enter Gateway IP (leave empty to attempt auto-detection or skip MITM): ")
		gwInput, _ := reader.ReadString('\n')
		gwInput = strings.TrimSpace(gwInput)
		if gwInput != "" {
			*gatewayIP = gwInput
		}
	}

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

		// 4. Keep the original “working” filter: drop host-sourced frames to avoid
		// double-counting forwarded packets. The ARP MITM ensures the target's traffic
		// passes through us, so capturing everything except our own transmissions is sufficient
		// and historically accurate.
		captureFilter = fmt.Sprintf("not ether src %s", engine.HostMAC.String())
		fmt.Printf("MITM Active. Filter: %s\n", captureFilter)
	} else if *targetIP != "" || *gatewayIP != "" {
		log.Fatal("Both -target and -gateway must be specified for MITM mode")
	}

	// Create channel for packets
	packetChan := make(chan models.PacketData, 1000)

	// Create context for cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start Tshark capture
	err := tshark.StartCapture(ctx, *interfaceName, captureFilter, packetChan)
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
