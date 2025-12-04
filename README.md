# GoNetWatch

A terminal-based network telemetry and visualization engine that provides real-time network traffic analysis with a beautiful TUI interface.

## Features

### Real-Time Network Monitoring
- Capture and analyze live network traffic from any network interface
- Interactive TUI dashboard built with Bubbletea
- Metrics displayed:
  - Bandwidth usage (auto-scaling: bps/Kbps/Mbps)
  - Packet rate (PPS)
  - Top talkers (IP addresses with highest traffic)
  - Protocol distribution
  - Connection statistics

### Deep Inspection (Phase 5)
- **Layer 7 Hostname Extraction**: See actual domain names being accessed
  - HTTPS traffic via TLS SNI (Server Name Indication)
  - DNS queries in real-time
  - HTTP host headers
- **Live Domain Log**: Scrolling history of accessed domains
  - Color-coded by protocol: 🟢 HTTPS (SNI), 🟡 DNS, 🔴 HTTP
  - Last 50 entries tracked with timestamps

### Security Monitoring (Phase 5)
- **Real-Time Anomaly Detection Engine**:
  - **Broadcast Storm Detection**: Alerts when >50 broadcasts/second
  - **Unsecure Protocol Alerts**: Flags plaintext HTTP, FTP, Telnet traffic
  - **DoS Pattern Detection**: Identifies high packet rates (>500 pps) from single sources
- **Visual Alert System**: 
  - Flashing red alerts for recent threats (<10 seconds)
  - Alert history with timestamps
  - "System Normal" indicator when no threats detected

### MITM Mode
- Advanced man-in-the-middle capabilities for deep network analysis
  - ARP cache poisoning for traffic redirection
  - Automatic IP forwarding management
  - Traffic interception and analysis
  - See encrypted traffic metadata (SNI) even without SSL decryption

### Forensic Analysis
- Analyze pre-recorded `.pcap` files
- Review historical network behavior

## Requirements

- Go 1.25.4 or later
- Tshark (Wireshark CLI) installed and available in PATH
- Linux or Windows (with Wireshark installed)

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd GoNetWatch
```

2. Install dependencies:
```bash
go mod download
```

3. Build the project:
```bash
go build -o gonetwatch
```

## Usage

### Basic Monitoring

Monitor traffic on a specific network interface:
```bash
./gonetwatch -i wlan0
```

Replace `wlan0` with your network interface name (e.g., `eth0`, `enp0s3`).

### MITM Mode

For advanced analysis with man-in-the-middle capabilities:
```bash
sudo ./gonetwatch -i wlan0 -target 192.168.1.100 -gateway 192.168.1.1
```

**Note**: MITM mode requires root/sudo privileges and will:
- Enable IP forwarding automatically
- Perform ARP cache poisoning to redirect traffic
- Filter out duplicate packets from your own machine

### Phase 5: Deep Inspection Features

#### View Domain Names (Passive Mode)
Monitor DNS queries without MITM:
```bash
sudo ./gonetwatch -i wlan0
```

You'll see DNS queries in the **Live Domain Log** (center panel) highlighted in yellow.

#### Full Deep Inspection (MITM Mode)
See HTTPS destination domains via SNI extraction:
```bash
sudo ./gonetwatch -i wlan0 -target 192.168.1.50 -gateway 192.168.1.1
```

- **Green domains (SNI)**: HTTPS traffic (e.g., `youtube.com`, `google.com`)
- **Yellow domains (DNS)**: DNS queries
- **Red domains (HTTP)**: Plaintext HTTP (security risk!)

#### Security Monitoring
The right panel shows real-time anomaly detection:

- **Broadcast Storm Alert**: Too many broadcast packets detected
- **Unsecure Protocol Alert**: Plaintext traffic (HTTP/FTP/Telnet) detected
- **DoS Pattern Alert**: High packet rate from single source

Alerts flash **red** when recent (<10 seconds), then fade to show history.

### Dashboard Layout

```
┌─────────────────────────────────────────────────────────┐
│ GoNetWatch - Monitoring: wlan0 [MITM Target: x.x.x.x]  │
└─────────────────────────────────────────────────────────┘
┌─────────┬──────────────────┬────────────────────────────┐
│ Metrics │ Traffic & Domains│ Security Monitoring        │
│         │                  │                            │
│ • BW    │ • Top Talkers    │ • Anomaly Detection Engine │
│ • PPS   │ • Domain Log     │ • Real-time Alerts         │
│ • Info  │                  │ • System Status            │
└─────────┴──────────────────┴────────────────────────────┘
```

## Architecture

The system follows a pipeline architecture:

1. **Data Source**: Tshark performs packet capture and protocol decoding
2. **Transport**: Packet data streamed via stdout in JSON/EK format
3. **Processing Core**: Go application parses, aggregates statistics, and calculates rates
4. **Presentation Layer**: Bubbletea framework renders the TUI

## Project Structure

```
GoNetWatch/
├── main.go                 # Entry point
├── internal/
│   ├── analysis/          # Traffic statistics and analysis
│   ├── models/            # Data models
│   ├── spoofer/           # MITM functionality (ARP spoofing, forwarding)
│   ├── tshark/            # Tshark integration and monitoring
│   └── tui/               # Terminal UI components
└── legacy/                # Backup files
```

## Dependencies

- [Bubbletea](https://github.com/charmbracelet/bubbletea) - TUI framework
- [Lipgloss](https://github.com/charmbracelet/lipgloss) - Styling
- [gopacket](https://github.com/google/gopacket) - Packet processing

## License

[Add your license here]

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.


