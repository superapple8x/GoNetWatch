# GoNetWatch

A terminal-based network telemetry and visualization engine that provides real-time network traffic analysis with a beautiful TUI interface.

## Features

- **Real-time Network Monitoring**: Capture and analyze live network traffic from any network interface
- **Interactive TUI Dashboard**: Beautiful terminal interface built with Bubbletea showing:
  - Bandwidth usage (Mbps) and packet rate (PPS)
  - Top talkers (IP addresses with highest traffic)
  - Protocol distribution
  - Connection statistics
- **MITM Mode**: Advanced man-in-the-middle capabilities for network analysis
  - ARP cache poisoning
  - Automatic IP forwarding management
  - Traffic interception and analysis
- **Forensic Analysis**: Analyze pre-recorded `.pcap` files

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

