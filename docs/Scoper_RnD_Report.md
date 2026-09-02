## Research & Development Report  
### Project: Scoper – Network Packet Analyzer  
### Organization: CyberOctet Labs  

---

## 1. Introduction

Scoper is a professional-grade **network packet analyzer** being developed at **CyberOctet Labs** as part of an applied cybersecurity and networking program.  
This Research & Development (R&D) report documents the background study, problem understanding, technology evaluation, design decisions, experimentation, and learnings that led to the current version of Scoper.

The goal of this R&D effort is to build a modern, dark-themed, user-friendly packet analysis tool that can be used both for **learning purposes** and for **real-world security analysis**, with capabilities comparable to established tools while offering a cleaner UI and integrated AI assistance.

---

## 2. Problem Statement & Motivation

Modern networks generate huge volumes of traffic, and cybersecurity professionals rely on packet analyzers to:

- Inspect raw packets at different layers (Ethernet, IP, TCP/UDP, application).  
- Diagnose connectivity problems, performance issues, and misconfigurations.  
- Detect malicious activity such as scans, floods, and data exfiltration.  

Popular tools like **Wireshark** are extremely powerful but can feel overwhelming for new learners and are not easily customizable for course-specific scenarios. In addition:

- They may lack **integrated AI assistance** for explaining packets in simple language.  
- Their interfaces and filter languages can be intimidating for beginners.  
- Adding custom anomaly detection or tailored dashboards often requires plugins or external tooling.

**R&D Objective:**  
Design and implement a **teaching-friendly yet professional** packet analyzer that:

- Provides a clear, modern UI focused on core workflows (capture → filter → inspect → analyze).  
- Offers **built-in traffic visualization and anomaly detection**.  
- Integrates an **AI Copilot** that can explain packets, streams, and potential threats.  

---

## 3. Literature Survey & Previous Research

During the initial research phase, we studied existing tools, standards, and technologies:

### 3.1 Existing Packet Analyzers

- **Wireshark**  
  - Industry-standard open-source packet analyzer.  
  - Strengths: deep protocol support, powerful display filters, extensive documentation.  
  - Challenges: complex UI, heavy for simple teaching scenarios, plugin-based extensibility.  

- **tcpdump / tshark**  
  - Command-line tools for capturing and filtering packets.  
  - Suitable for scripting and automation, but not ideal for visual learning.  

From these tools, Scoper adopts:

- The idea of **display filters** that work on already captured packets.  
- A **layered protocol view** (Ethernet → IP → TCP/UDP → application protocols).  
- The concept of **follow stream** for analyzing conversations between endpoints (planned).  

### 3.2 Protocol and Capture Libraries

We evaluated several libraries for capturing and decoding packets:

- **Scapy** (Python)  
  - Powerful packet crafting, sniffing, and decoding library.  
  - Cross‑platform support via **Npcap** (Windows) and **libpcap** (Linux/macOS).  
  - Easy to integrate with Python-based GUIs.  

- **libpcap / WinPcap / Npcap**  
  - Low-level capture libraries providing access to raw network traffic.  
  - Typically wrapped by higher-level tools (Wireshark, Scapy, etc.).  

Scapy was selected as the primary capture and decoding engine due to:

- Its rich protocol support (Ethernet, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, DHCP, HTTP, etc.).  
- Python integration (critical because Scoper is written in Python).  
- Community familiarity within cybersecurity training.

### 3.3 Display Filters & Query Languages

We studied **Wireshark display filters** and **BPF (Berkeley Packet Filter)** syntax.  
Key observations:

- BPF is powerful but low-level and platform-dependent.  
- Wireshark-style expressions (`tcp and port 80`, `ip.src == 1.2.3.4`) are more readable.  

R&D outcome: Scoper implements a **pure-Python Wireshark-style display filter engine** (`core/packet_filter.py`) that:

- Parses expressions into an AST via a custom tokenizer and recursive-descent parser.  
- Supports logical operators (`and`, `or`, `not`), parentheses, hosts, ports, nets, and protocol names.  
- Operates on `PacketInfo` objects after capture, avoiding OS/BPF dependencies and making it highly portable for teaching environments.

---

## 4. Technology & Design Decisions

### 4.1 Language and Framework

- **Programming Language**: Python  
  - Fast prototyping, easy to learn, widely used in cybersecurity.  

- **GUI Framework**: PySide6 (Qt for Python)  
  - Modern, cross‑platform, supports high‑DPI displays.  
  - Allows rich, dark-themed UIs with split panes, tabs, and dashboards.  

This combination enables Scoper to be both **educational** and **production‑capable**.

### 4.2 Architecture Overview

From the codebase, Scoper is logically divided into:

- **Core capture engine** (`core.capture_engine.CaptureEngine`)  
  - Handles live capture using Scapy, interface discovery via a driver manager, and basic statistics (PPS, bytes/sec, protocol counts, top talkers).  
  - Provides callbacks so the UI can receive packets and updated stats without blocking.  

- **Protocol decoder** (`core.protocol_decoder.decoder.ProtocolDecoder`)  
  - Decodes raw bytes into layers: Ethernet, ARP, IPv4/IPv6, TCP/UDP, ICMP, DNS, DHCP, HTTP.  
  - Produces structured `ProtocolLayer` and `ProtocolField` objects for tree‑based viewing.  

- **Display filter engine** (`core.packet_filter.PacketFilter`)  
  - Interprets Wireshark-like expressions and evaluates them on captured packets.  

- **Backend driver manager** (`backend.*`)  
  - Abstracts away Npcap/libpcap detection, installation status, and test captures.  

- **UI layer** (`ui.main_window`, `ui.panels.*`, `ui.style.*`)  
  - Packet table, details pane, hex view, monitoring dashboard, AI Copilot, and dark theme.  

- **Analysis layer** (`analysis.anomaly_detection.AnomalyDetector`)  
  - Online statistics and heuristics for detecting PPS spikes, port scans, SYN floods, DNS anomalies, suspicious ports, etc.

### 4.3 Key R&D Design Choices

- **Post-capture display filters rather than pre-capture BPF filters**  
  - Simplifies the capture logic and avoids OS-specific filter compilation issues.  
  - Safer for beginners: all packets are captured, and filters only hide/show in the UI.  

- **Bounded in-memory packet buffer**  
  - `CaptureEngine` uses a `deque` with a maximum size to avoid memory exhaustion.  
  - Suitable for classroom/lab environments where long captures need to stay stable.  

- **Batch UI updates**  
  - Packets are batched and flushed to the UI periodically to keep the interface responsive during high-throughput captures.  

- **Integrated AI Copilot**  
  - Uses a BYOK (Bring Your Own Key) model to support multiple providers (OpenAI, Anthropic, Gemini, Groq, Ollama).  
  - Embeds context about the selected packet/stream and recent packets into the AI prompt.  
  - Helps students understand complex traces (e.g. TCP handshake, TLS negotiation, DNS behavior) in natural language.

---

## 5. Experimental Setup & Implementation Phases

The R&D work was organized in phases:

### Phase 1 – Baseline Capture & Table View

- Implemented `CaptureEngine` using Scapy to sniff packets from selected interfaces.  
- Verified capture correctness on different adapters (Wi‑Fi, Ethernet, loopback).  
- Created a basic packet table with timestamp, source, destination, protocol, length, and info.  

**Outcome:** A minimal but working packet sniffer with a tabular list of packets.

### Phase 2 – Protocol Decoding & Detailed Views

- Added `ProtocolDecoder` to parse packet bytes into protocol layers.  
- Built a `PacketDetailsWidget` (tree view) and `HexViewWidget` (hex+ASCII) to display decoded fields and raw data.  
- Designed consistent color coding for key fields (IP, ports, checksums, flags).  

**Outcome:** Students can inspect packets at multiple layers, understand headers, and correlate hex bytes with decoded fields.

### Phase 3 – Display Filter Engine

- Designed the pure-Python tokenizer, parser, and evaluator for display filters.  
- Implemented support for expressions similar to Wireshark (ports, hosts, nets, protocols, boolean logic).  
- Integrated filter validation and feedback in the main window (green/red status text).  

**Outcome:** Users can interactively filter captured traffic using readable expressions without touching low-level BPF.

### Phase 4 – Monitoring Dashboard & Statistics

- Implemented `MonitoringDashboard` with real-time charts (packets per second) and protocol distribution.  
- Added top-level stats widgets (PPS, Bytes/s, total packets, duration).  
- Ensured updates are throttled for smoother visualization and lower CPU usage.  

**Outcome:** A visually appealing live dashboard to demonstrate traffic patterns and protocol mix in real time.

### Phase 5 – Anomaly Detection Engine

- Implemented `AnomalyDetector` with adaptive baselines using moving averages and variance.  
- Detectors include: PPS spikes, port scans, SYN floods, DNS anomalies, failed handshakes, suspicious ports, and unusual packet sizes.  
- Designed a flexible structure to export alerts and integrate with future UI panels.  

**Outcome:** Scoper can be used in labs to demonstrate how automated anomaly detection works on top of raw packet data.

### Phase 6 – AI Copilot Integration

- Designed the `AICopilotWidget` with a chat-style interface.  
- Implemented support for multiple AI providers and a per-provider key store.  
- Built routines to extract packet/stream context and feed it into prompts for explanation and threat analysis.  

**Outcome:** Students can ask natural-language questions about traffic (e.g., “Explain this TCP handshake” or “Is this packet suspicious?”) and get guided explanations.

---

## 6. Evaluation & Findings

Through iterative testing and classroom-style usage, several observations were made:

- **Usability**  
  - The simplified interface (two main panes + bottom dashboard) is less intimidating than Wireshark for beginners.  
  - Integrated filter hints and the filter-help dialog significantly reduce errors when writing expressions.  

- **Performance**  
  - For typical lab traffic volumes, Scoper maintains smooth UI updates and low CPU usage due to batched rendering and bounded buffers.  
  - Very high-rate captures will eventually hit UI/Scapy limits, which is acceptable given the educational focus.  

- **Educational Value**  
  - The combination of detailed protocol decoding, hex view, and AI explanations provides multiple learning angles (visual, textual, and interactive).  
  - Anomaly detection outputs can be used to design **attack vs. normal traffic** lab exercises.

Limitations identified:

- Capture and decoding performance will not match heavily optimized C/C++ tools like Wireshark.  
- Advanced features (e.g., deep TLS decryption, VoIP analysis) are not within the current scope.  
- AI explanations depend on external APIs or a locally running LLM.

---

## 7. Conclusion

This R&D project demonstrates that **Scoper**, developed at **CyberOctet Labs**, can serve as a **modern educational packet analyzer** that is:

- Technically grounded (using Scapy, Qt, and well-known capture mechanisms).  
- Pedagogically effective (clear views, filters, dashboards, AI explanations).  
- Extensible (protocol decoder, anomaly engine, AI panel, and modular UI).  

The research into existing tools, display filter languages, anomaly detection techniques, and AI-assisted analysis directly influenced the architecture and feature set of Scoper. The resulting application provides both **professional-grade capabilities** and a **learning-friendly experience** for students studying networking and cybersecurity at CyberOctet.

---

## 8. Future R&D Directions

Based on the current results, several R&D extensions are planned:

- **Deeper anomaly and threat detection**  
  - Integrate reputation/threat‑intel feeds for known malicious IPs/domains.  
  - Add ML‑based anomaly detection on top of baseline heuristics.  

- **Richer protocol support**  
  - Extend decoding to more application protocols (SMTP, FTP, TLS handshake details, HTTP/2).  

- **Advanced AI workflows**  
  - One-click “Explain capture” summaries.  
  - AI‑guided lab scenarios where the model asks students questions based on live traffic.  

- **Collaboration and reporting**  
  - Export of R&D findings, anomaly timelines, and AI explanations into structured PDF/HTML reports.  

These enhancements will continue to align Scoper with CyberOctet’s mission of providing **hands-on, research‑driven cybersecurity education**.

