Here is the completely rewritten Software Requirements Specification (SRS). You can copy-paste this directly into your project documentation.

It is structured to emphasize that you are building an Advanced Visualization Engine that leverages industry-standard tools, which is a very valid and professional software engineering approach.

Project Name: GoShark Analyzer

A Terminal-Based Network Telemetry & Visualization Engine

1. Introduction
1.1 Purpose

The purpose of this project is to develop a lightweight, terminal-based dashboard that aggregates and visualizes network traffic in real-time. By acting as a wrapper for the industry-standard Tshark (Wireshark CLI), the tool translates complex, high-volume packet logs into actionable summaries—such as Quality of Service (QoS) metrics, Protocol Distribution, and Top Talkers—for network administrators.

1.2 Scope

The software functions as a Telemetry Aggregator. It does not interface directly with the network driver; instead, it orchestrates a subprocess (tshark) to perform packet capture and decoding. The system supports two operational modes:

Live Monitor Mode: Capturing real-time traffic from a local Network Interface.

Forensic Mode: Ingesting pre-recorded .pcap files to analyze historical data or router-level logs from external networks.

2. System Architecture
2.1 Design Philosophy

The system follows a Pipeline Architecture:

Data Source: Tshark executes the capture and applies protocol decoding filters.

Transport: Packet data is streamed via stdout in JSON/EK format to the main application.

Processing Core: The Go application parses the stream, aggregates statistics in memory, and calculates rates.

Presentation Layer: The Bubbletea framework renders the TUI (Terminal User Interface).

2.2 Technology Stack

Backend Engine: Tshark (Wireshark Command Line Utility).

Role: Reliable packet capturing, protocol decoding (Dissectors), and File I/O.

Application Logic: Go (Golang) v1.21+.

Role: Process orchestration, concurrency management, and statistical aggregation.

Frontend Interface: Bubbletea & Lipgloss.

Role: Rendering the reactive terminal dashboard.

3. Functional Requirements
3.1 Data Ingestion & Control

FR-01 (Process Management): The system shall spawn and manage a child process of tshark with optimized flags (e.g., -l -n -T ek) to minimize latency.

FR-02 (Live Capture): The system shall allow the user to select a live Network Interface (NIC) to begin real-time analysis.

FR-03 (Offline Analysis): The system shall accept a path to a standard .pcap or .pcapng file and replay the traffic to generate summary statistics (Forensic Mode).

3.2 Data Processing

FR-04 (Stream Parsing): The system shall parse the incoming Newline Delimited JSON (NDJSON) stream to extract fields: frame.len, ip.src, ip.dst, tcp.port, and udp.port.

FR-05 (Bandwidth Calculation): The system shall calculate the data rate (Bits Per Second) by aggregating the frame.len of packets received within a sliding 1-second window.

3.3 Analytics & Summarization

FR-06 (Top Talkers): The system shall maintain a frequency map of Source IP addresses and display the top 5 IPs responsible for the highest volume of traffic.

FR-07 (Protocol Heuristics): The system shall categorize traffic based on Transport Layer ports (e.g., 80/443 = Web, 53 = DNS, 22 = SSH) and display a percentage breakdown.

FR-08 (Connection Tracking): The system shall distinguish between TCP (Connection-oriented) and UDP (Connection-less) traffic volumes.

**3.4 Active Interception (MITM Mode)**
*   **FR-09 (Target Selection):** The system shall allow the user to specify a Target IP (Victim) and Gateway IP.
*   **FR-10 (ARP Cache Poisoning):** The system shall inject forged ARP Reply packets to redirect the target's traffic through the host machine.
*   **FR-11 (IP Forwarding):** The system shall (on supported OSs) automatically enable kernel-level IP forwarding to maintain the target's internet connectivity during analysis.


4. User Interface Requirements
4.1 Dashboard Layout

The application shall utilize a split-pane TUI layout containing:

QoS Panel: A Gauge or Big Numeric display showing current Bandwidth usage (Mbps) and Packet Rate (PPS).

Traffic Matrix: A tabular view of "Top Talkers" (Source IP vs. Total Bytes).

Protocol Distribution: A list or bar chart visualizing the ratio of protocols detected (e.g., HTTP vs. Unknown).

Status Footer: Indicators for "Live/Offline" mode, Interface Name, and Total Packets Processed.

4.2 User Experience

UI-01: The dashboard must refresh asynchronously (minimum 4Hz) to provide smooth feedback without blocking the data ingestion pipeline.

UI-02: The user must be able to pause/resume the visual updates (freezing the view) while data collection continues in the background.

5. Non-Functional Requirements
5.1 System Dependencies

The host machine must have Wireshark (Tshark) installed and added to the System Path.

5.2 Performance

The Go parser must utilize buffered I/O to handle high-velocity JSON streams (up to 10,000 packets per second) without causing a memory leak or crash.

5.3 Cross-Platform Compatibility

The tool shall function on both Windows and Linux environments, provided the underlying Tshark installation is present and functioning.