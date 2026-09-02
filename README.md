# Scoper

Scoper is a network packet analyzer my friend and I built together as a capstone project at CyberOctet Labs. It captures live traffic, decodes it protocol by protocol, and shows it in a dark-themed interface that's meant to be easier to read than a raw packet dump.

---

## Features

- Live packet capture — Ethernet, IPv4/IPv6, TCP, UDP, ICMP, ARP, DNS, DHCP, HTTP
- Protocol tree view + synced Hex/ASCII view (click a field, see the bytes highlight)
- Real-time anomaly detection — port scans, SYN floods, DNS bursts, PPS spikes
- Display filters (`tcp and port 443`, `host 8.8.8.8`, etc.)
- PCAP/PCAPNG export

**Known limitation:** no TLS/HTTPS decoding yet, so a lot of real-world (encrypted) traffic only shows up to the TCP layer.

---

## How to use it

**Download the built app** (no Python needed):
1. Grab `scoper-v1.0.zip` from [Releases](../../releases)
2. Extract it, run `scoper.exe`
3. Install [Npcap](https://npcap.com/) first if you don't have it

**Or run from source:**
```bash
git clone https://github.com/thattweeb/Scoper.git
cd Scoper
pip install -r requirements.txt
python run.py
```
(Linux also needs `sudo apt install libpcap-dev`)

**Using it:**
1. Pick an interface, hit Start Capture
2. Click a packet — see it decoded in Packet Details, Hex/ASCII, and Metadata
3. Use the filter bar to narrow traffic down
4. Export a capture if you want to reopen it later

---

## Background

Capstone project at CyberOctet.