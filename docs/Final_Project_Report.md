## 1. Introduction

*(Font: Heading size 16, content size 12, line spacing 1.5, page number in footer. Start this heading on a new page.)*

This document presents the **Final Project Report** for **Scoper**, a professional network packet analyzer developed at **CyberOctet Labs**. The project brings together live packet capture, protocol decoding, anomaly detection, and AI-assisted explanations into a single modern, dark‑themed desktop application.

The report describes why Scoper was created, how it improves the learning experience compared to traditional tools like Wireshark, and how it implements core software engineering concepts such as requirements analysis, system design, implementation, testing, and documentation in a real-world cybersecurity context.

---

## 2. Table of Contents

*(Font: Heading size 16, subpoints size 14, content size 12, line spacing 1.5, page number in footer. Start this heading on a new page.)*

1. Introduction  
2. Table of Contents  
3. Overview  
4. Purpose  
5. Scope  
6. Functional Specification  
7. Methodology  
8. Project Body  
   - What we did  
   - How we did it  
   - Proof of Concept (POC)  
   - Problem we solved  
9. Challenges Faced  
10. Conclusion  
11. Future Scope  

---

## 3. Overview

*(Font: Heading size 16, content size 12, line spacing 1.5, page number in footer. Start this heading on a new page.)*

Scoper is a **desktop network packet analyzer** built in Python using **PySide6 (Qt for Python)** and **Scapy**. It captures live traffic from Npcap/libpcap-compatible network interfaces, decodes packets into protocol layers, and presents them in an intuitive, dark‑themed user interface designed for both learning and professional use.

The application consists of a packet capture engine, protocol decoder, Wireshark‑style display filter engine, real‑time monitoring dashboard, anomaly detection module, and an embedded AI Copilot panel. Together, these components make Scoper a complete environment for understanding network behavior, diagnosing issues, and exploring security scenarios.

Key highlights of Scoper include:

- **Core functionality**: Live packet capture, protocol decoding (Ethernet, IPv4/IPv6, TCP, UDP, ICMP, ARP, DNS, DHCP, HTTP), saving captures to PCAP/PCAPNG, and powerful display filters.  
- **User interface**: A modern, dark‑themed, two‑pane layout with a bottom dashboard, hex/ASCII view, and an AI assistant tab integrated directly into the main window.  
- **Reliability and performance**: Bounded in‑memory buffers, batched UI updates, cross‑platform driver management, and robust error handling to keep the tool stable even under high traffic.  

---

## 4. Purpose

*(Font: Heading size 16, content size 12, line spacing 1.5, page number in footer. Start this heading on a new page.)*

The primary purpose of Scoper is to **monitor and analyze network traffic in real time** while making packet analysis more accessible to students and security practitioners at CyberOctet. The tool bridges the gap between highly complex professional tools and the needs of a structured learning environment.

By implementing Scoper, the project aims to:

- **Address a specific real-world problem**: Traditional analyzers like Wireshark are extremely powerful but can be visually cluttered, hard to customize for teaching, and lack integrated AI explanations.  
- **Provide an efficient and understandable solution**: Scoper offers focused dashboards, simplified filter syntax help, and curated protocol views, allowing learners to quickly move from “raw packets” to “conceptual understanding”.  
- **Enhance user experience**: A dark, consistent theme, responsive layout, clear error messages, and embedded AI Copilot improve usability and reduce the time needed to interpret complex traces.  

Additionally, the project serves as a practical capstone for applying networking, operating systems, GUI design, AI integration, and secure coding practices in a single cohesive application.

---

## 5. Scope

*(Font: Heading size 16, subpoints size 14 if used, content size 12, line spacing 1.5, page number in footer. Start this heading on a new page.)*

The scope of Scoper defines what capabilities are delivered in this version and what is intentionally left for future work.

**In-Scope Features (What the system does):**

- **Live packet capture**: Capture Ethernet, IPv4/IPv6, TCP, UDP, ICMP, ARP, DNS, DHCP and HTTP traffic from Npcap/libpcap‑compatible interfaces using Scapy.  
- **Interactive analysis UI**: Show packets in a sortable table, detailed protocol tree view, synchronized hex/ASCII view, and real‑time monitoring dashboard with PPS and protocol distribution charts.  
- **Display filters**: Apply Wireshark‑style display filters (e.g., `tcp and port 443`, `host 8.8.8.8`, `net 192.168.0.0/24`) to already‑captured packets using a pure‑Python filter engine.  
- **Anomaly indications**: Detect and summarize suspicious behavior such as PPS spikes, port scans, SYN floods, DNS bursts, suspicious ports, and unusual packet sizes.  
- **AI Copilot (chatbot)**: Explain individual packets and streams, highlight potential issues, and answer natural‑language questions using external LLM providers or local Ollama.  
- **Capture export**: Save captured traffic to PCAP/PCAPNG files for offline analysis or sharing.  

**Out-of-Scope (Not covered in this version):**

- **Deep content inspection and decryption** of encrypted protocols such as full TLS session decoding.  
- **VoIP/media‑specific analysis** (e.g., RTP streams, call reconstruction).  
- **Large‑scale distributed capture** or remote sensor management.  

This scope keeps the project realistic for an academic timeframe while still delivering a complete, usable packet analyzer tailored to CyberOctet’s curriculum.

---

## 6. Functional Specification

*(Font: Heading size 16, subpoints size 14, content size 12, line spacing 1.5, page number in footer. Start this heading on a new page.)*

The functional specification describes what Scoper is expected to do from the user's perspective.

**Functional Requirements:**

- **User Interface Requirements (size 14 subheading)**  
  - The system shall provide a user-friendly graphical interface to start/stop captures, select interfaces, apply filters, and inspect packets.  
  - The interface shall display a packet table, packet details tree, hex/ASCII view, monitoring dashboard, and AI Copilot in clearly separated panels.  

- **Core Functional Requirements (size 14 subheading)**  
  - The system shall allow the user to capture network packets from selected Npcap/libpcap interfaces.  
  - The system shall decode captured packets into protocol layers and show important fields (IP addresses, ports, flags, lengths, checksums).  
  - The system shall let the user apply display filters (e.g., `tcp and port 80`) to show only matching packets without restarting the capture.  
  - The system shall display basic statistics (packets captured, PPS, bytes per second, protocol distribution) in real time.  
  - The system shall allow saving captured traffic to PCAP/PCAPNG files.  

- **AI & BYOK Functional Requirements (size 14 subheading)**  
  - The system shall provide an AI Copilot panel that can explain the currently selected packet and related traffic in natural language.  
  - The system shall support multiple AI providers (OpenAI, Anthropic, Gemini, Groq, Ollama) through a **BYOK (Bring Your Own Key)** approach so that CyberOctet and students can choose their preferred vendor or local model without hard‑coding one provider.  
  - The system shall store API keys locally per provider and allow switching providers at runtime.  
  - The system shall safely include packet context (IP/port, protocol, basic hex dump) in prompts so that the AI can reason about what is happening on the network.  

- **Data Handling Requirements (size 14 subheading)**  
  - The system shall keep a bounded in‑memory list of recent packets to prevent uncontrolled memory growth.  
  - The system shall not permanently store packet contents unless the user explicitly saves a capture file.  
  - The system shall allow display‑only filtering and basic search operations on captured packets.  

**Non-Functional Requirements:**

- **Performance**: For typical lab‑scale traffic, the system should update the UI and statistics in near real time (sub‑second perceived updates) while remaining responsive.  
- **Reliability**: The system should handle driver errors, permission issues, and missing dependencies gracefully, showing clear instructions (e.g., when Npcap is not installed).  
- **Usability**: The interface should be intuitive for first-time users, with meaningful defaults, tooltips, filter help dialogs, and keyboard shortcuts (F5/F6 for start/stop).  

---

## 7. Methodology

*(Font: Heading size 16, subpoints size 14, content size 12, line spacing 1.5, page number in footer. Start this heading on a new page.)*

The project followed an **iterative, incremental** software development approach to allow continuous testing on real network traffic and quick feedback from mentors at CyberOctet.

**Development Approach (size 14 subheading):**

- Requirements were gathered from the CyberOctet curriculum and existing lab exercises, focusing on core packet analysis scenarios (identifying handshakes, DNS lookups, basic attacks).  
- The work was split into iterations: capture + table view, protocol decoding, filters, dashboard, anomaly detection, and finally AI Copilot integration.  
- Each iteration delivered a working subset of features that could be demonstrated and refined before moving on.  

**Design and Implementation (size 14 subheading):**

- The architecture was divided into clear layers: capture engine, protocol decoder, analysis, UI panels, and AI integration. This separation makes it easier to reason about changes and future extensions.  
- The application was implemented in **Python** using **Scapy** for packet capture/decoding and **PySide6 (Qt)** for the user interface.  
- BYOK support for the AI Copilot was designed so that providers can be added or changed without altering the core packet analysis logic.  

**Testing (size 14 subheading):**

- Functional testing was performed by capturing traffic on Wi‑Fi, Ethernet, and loopback interfaces and verifying that protocols, IPs, ports, and lengths matched expectations.  
- Display filters were tested with multiple expressions (`tcp`, `udp or icmp`, `host 8.8.8.8`, `port 53`) to ensure correct matching and error handling.  
- Stress testing used short high‑rate captures to verify that bounded buffers and batched UI updates prevent freezes or crashes.  
- AI Copilot testing involved sample prompts such as “Explain this packet” and “Is this suspicious?” for different traffic types.  

**Tools and Technologies (size 14 subheading):**

- **Programming Language**: Python 3  
- **Frameworks / Libraries**: PySide6 (Qt), Scapy, Matplotlib, NumPy, psutil.  
- **AI/LLM Providers**: OpenAI, Anthropic, Gemini, Groq, Ollama via BYOK model.  
- **Version Control**: Git (GitHub / local repo) for source management.  
- **IDE/Editor**: Cursor / VS Code and standard Python tooling.  

---

## 8. Project Body

*(Font: Heading size 16, subpoints size 14, content size 12, line spacing 1.5, page number in footer. Start this heading on a new page.)*

### What we did (size 14 subheading)

In this project, we developed **Scoper**, a CyberOctet-branded packet analyzer that enables users to **capture, filter, visualize, and interpret network traffic** in real time. The primary focus was on **teaching-friendly packet analysis** without sacrificing professional features.

The system consists of the following major components:

- **Capture Engine**: A Scapy-based engine that discovers interfaces via a driver manager, handles Npcap/libpcap checks, and streams captured packets into the UI with statistics.  
- **Protocol Decoder**: A decoder that converts raw bytes into protocol layers (Ethernet, IP, TCP/UDP, ICMP, ARP, DNS, DHCP, HTTP) and exposes them to the packet details and hex view panels.  
- **Display Filter Engine**: A pure‑Python engine that parses Wireshark‑style expressions and filters `PacketInfo` objects post‑capture.  
- **Monitoring Dashboard**: Real‑time charts for packets per second and protocol distribution, plus compact KPI widgets (PPS, Bytes/s, Total, Duration).  
- **Anomaly Detector**: Heuristic detectors for PPS spikes, port scans, SYN floods, DNS anomalies, suspicious ports, and unusual packet sizes.  
- **AI Copilot (BYOK Chatbot)**: An integrated chat panel that uses external or local LLMs to explain packets and streams and compare behavior against typical security patterns.  

### How we did it (size 14 subheading)

We began by analyzing the limitations of existing tools (especially Wireshark) in a teaching environment: complex UI, heavy feature set, and no integrated guided explanations. Requirements from CyberOctet’s labs were converted into concrete scenarios (viewing TCP handshakes, checking DNS lookups, spotting basic attacks).

Key steps included:

- Designing the overall architecture around a central `CaptureEngine` and independent UI panels so that future features can be added without breaking existing ones.  
- Implementing capture and decoding using Python, Scapy, and PySide6, and validating correctness against known traffic patterns.  
- Building the display filter engine from scratch to avoid OS‑dependent BPF compilation and to keep behavior deterministic in the classroom.  
- Adding a dashboard and anomaly detection layer to visually connect raw packets with higher‑level behavior (traffic spikes, scans, floods).  
- Integrating the AI Copilot using a BYOK model so organizations or students can bring their own AI provider keys, or rely on a local Ollama instance when cloud access is limited.  

### Proof of Concept (POC) (size 14 subheading)

To validate the feasibility of the solution, we created a Proof of Concept that demonstrated:

- The ability to capture live traffic on Wi‑Fi/Ethernet interfaces and display it in a continuously updating table.  
- Correct protocol decoding for common scenarios like web browsing, DNS resolution, and ICMP echo (ping) packets.  
- Correct operation of display filters (`tcp`, `dns and port 53`, `host 8.8.8.8`) on captured traffic without restarting the capture.  
- Basic anomaly alerts during scripted test attacks such as simple port scans and SYN floods.  
- Successful AI explanations of selected packets, where the chatbot could identify TCP handshakes, HTTP requests, and suspicious traffic patterns.  

The successful POC confirmed that the chosen technologies (Python, Scapy, PySide6) and design decisions (post‑capture filters, batched UI updates, BYOK AI integration) were appropriate for the problem.

### Which problem we solved (size 14 subheading)

The project solves the problem of **making network packet analysis approachable and guided for students**, while still being useful to practicing security analysts. Traditional tools like Wireshark can feel overwhelming; they provide powerful views but little narrative explanation or real‑time guidance.

By using Scoper:

- Users can **understand** what packets and protocols are doing through a combination of visuals, decoded fields, and AI explanations.  
- Organizations like CyberOctet can **run structured labs and demos** using a tool branded and customized for their teaching style, without depending entirely on third‑party UI conventions.  
- The overall analysis process becomes **faster, more insightful, and more interactive**, because users can filter traffic, see real‑time charts, read anomaly hints, and ask the AI for explanations in the same window.  

---

## 9. Challenges Faced

*(Font: Heading size 16, subpoints size 14 if used, content size 12, line spacing 1.5, page number in footer. Start this heading on a new page.)*

During the development of Scoper, several technical and design challenges were encountered:

- **Technical Challenges (size 14 subheading)**  
  - Integrating **Scapy** with **Npcap/libpcap** across different platforms, and handling permission issues on Windows when raw capture requires administrator rights.  
  - Managing performance for live captures so that the UI remains responsive while processing many packets per second, including optimizing batch sizes and limiting in‑memory buffers.  
  - Implementing a pure‑Python display filter engine compatible with Wireshark‑style expressions without relying on native BPF compilation.  
  - Embedding multiple AI providers in a safe BYOK pattern, dealing with different HTTP APIs, error formats, and latency constraints.  

- **Design and Implementation Challenges (size 14 subheading)**  
  - Designing a **clean, dark-themed interface** that is visually modern but still clearly communicates technical information (IPs, ports, flags, hex dumps).  
  - Separating concerns between the capture logic, analysis logic, and UI widgets so that future features (like new detectors or protocols) can be added with minimal impact.  
  - Deciding where AI assistance should be visible and how much packet context to send so that explanations are accurate but privacy is respected.  

- **Testing and Debugging Challenges (size 14 subheading)**  
  - Reproducing edge cases such as low‑traffic interfaces, loopback traffic, and intermittent connectivity to validate that Scoper handles “boring” as well as “busy” networks.  
  - Debugging race conditions between the capture thread and the Qt UI thread, and moving to a signal/slot model to ensure thread‑safe updates.  
  - Validating anomaly detection heuristics (e.g., port scans vs. normal browsing) to reduce false positives during typical lab usage.  

For each challenge, we consulted documentation, experimented with small test scripts, and iteratively improved the implementation until the tool was stable and easy to demonstrate in a lab environment.

---

## 10. Conclusion

*(Font: Heading size 16, content size 12, line spacing 1.5, page number in footer. Start this heading on a new page.)*

In conclusion, the project successfully achieved its primary objectives of **building a modern, CyberOctet-branded packet analyzer that is both educational and practical**. Scoper provides a complete workflow from live capture and protocol decoding to visualization, anomaly hints, and AI‑powered explanations in a single, coherent application.

Compared to using Wireshark alone, Scoper offers a **simpler, curated interface**, integrated teaching aids (filter help, dashboards, anomaly summaries), and an **AI chatbot** that can translate low‑level packet details into human‑readable insights. This makes it especially valuable in classroom and lab settings where students are seeing packets for the first time.

Through this project, we gained experience in network programming, GUI design, concurrency, AI integration, and security‑oriented software engineering. The work demonstrates that Python, when combined with Scapy and Qt, can deliver a serious yet student‑friendly packet analyzer aligned with CyberOctet’s mission.

---

## 11. Future Scope

*(Font: Heading size 16, subpoints size 14 if used, content size 12, line spacing 1.5, page number in footer. Start this heading on a new page.)*

There are several opportunities to extend and improve Scoper in future work:

- **Feature Enhancements (size 14 subheading)**  
  - Add a dedicated **anomaly alerts panel** that lists detected events with timelines and allows exporting them into lab reports.  
  - Implement “**Follow Stream**” views for TCP/UDP conversations with reconstructed payloads and AI summaries for entire sessions.  
  - Add deeper protocol decoders (SMTP, FTP, TLS handshake details, HTTP/2, custom lab protocols).  

- **Technical Improvements (size 14 subheading)**  
  - Further optimize packet processing and UI updates for very high‑rate traffic and longer captures.  
  - Integrate threat‑intelligence lookups (e.g., reputation checks for IPs/domains) into the anomaly engine and AI prompts.  
  - Provide configuration profiles so CyberOctet trainers can enable/disable modules per lab exercise.  

- **Scalability and Deployment (size 14 subheading)**  
  - Package Scoper as an installer for Windows and as an AppImage/flatpak for Linux to simplify student deployment.  
  - Explore a client–server model where multiple students can connect to a shared capture sensor while still using their local Scoper UI.  

By implementing these enhancements, Scoper can grow from an advanced teaching tool into a robust, semi‑professional packet analysis platform that continues to showcase CyberOctet’s R&D and training capabilities.

---

**Formatting Note:**  
This file provides the complete textual content and structure of the "Final_Project_Report" for **Scoper**. To fully match your formatting requirements (each main point on a new page, heading font size 16, subpoints 14, content 12, line spacing 1.5, and page numbers), copy this content into a word processor (such as Microsoft Word or Google Docs), then:

- Apply a Heading style with font size 16 to each main heading (1–11).  
- Apply a subheading style with font size 14 to subpoints.  
- Set body text to font size 12 with 1.5 line spacing.  
- Insert page breaks so each main heading starts on a new page.  
- Insert page numbers in the footer of each page.  
