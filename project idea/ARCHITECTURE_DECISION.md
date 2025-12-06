# Architecture Decision Record (ADR): Migration to Tshark Wrapper


## Context & Problem Statement
Phase 1 of the project successfully implemented a native packet sniffer using `gopacket` and CGO bindings for `libpcap`. However, strict requirements regarding "Whole Network" visibility, simplified cross-platform deployment, and the need for robust offline `.pcap` analysis have highlighted limitations in the native approach:
1.  **Complexity:** Native implementation requires complex C-compiler (GCC/MinGW) setups on Windows environments.
2.  **Scope Creep:** Re-implementing protocol dissectors (decoders) that Wireshark already provides is inefficient.
3.  **Deployment:** Enabling "Full Network" monitoring via native code is hardware-dependent.

## The Decision
We are pivoting the backend architecture from a **Native Sniffer** to a **Tshark Wrapper**.
Instead of asking the kernel for packets directly, the Go application will orchestrate a `tshark` subprocess and parse its JSON output stream.

## Implementation Changes
*   **DEPRECATED:** Direct usage of `github.com/google/gopacket`.
*   **DEPRECATED:** The `internal/sniffer/` package from Phase 1.
*   **NEW DEPENDENCY:** Host machine must have Wireshark/Tshark installed.
*   **NEW LOGIC:** `main.go` will now execute `exec.Command("tshark", ...)` and parse `stdout`.

## Legacy Code Note
The Phase 1 implementation (Environment Setup & Basic Sniffer) has been archived in the `/legacy` directory for reference but should not be used for future phases.

---
