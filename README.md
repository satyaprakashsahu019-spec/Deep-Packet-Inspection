# Deep Packet Inspection (DPI) Engine & Network Packet Analyzer

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Dependencies](https://img.shields.io/badge/dependencies-none%20(standard%20lib)-brightgreen.svg)]()
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A high-performance, multi-threaded **Deep Packet Inspection (DPI) engine and network packet analyzer** written in pure, idiomatic Python. 

Built with **zero external third-party dependencies** — relying strictly on Python's standard library (`struct`, `socket`, `threading`, `queue`, `dataclasses`, `enum`), making it lightweight, cross-platform, and immediately runnable on any standard Python installation.

---

## ✨ Features

- **Protocol Decoding (L2 to L7):** Dissects Ethernet frames, IPv4 packets, TCP/UDP segments, and application layer payloads.
- **TLS SNI Extraction:** Inspects TLS Client Hello handshakes to extract Server Name Indication (SNI) domain names across encrypted HTTPS sessions.
- **Application Identification:** Automatic classification of network flows into application categories (YouTube, Google, Netflix, Facebook, TikTok, Spotify, Discord, etc.).
- **Multi-Threaded Pipelined Architecture:** Uses a concurrent pipeline pattern:
  $$\text{PCAP Reader} \longrightarrow \text{Load Balancer (LB) Threads} \longrightarrow \text{Fast Path (FP) Worker Threads} \longrightarrow \text{PCAP Writer}$$
- **Stateful Connection Tracking:** Maintains 5-tuple (`src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`) flow tables and TCP lifecycle states.
- **Dynamic Rule Engine:** Real-time blocking by Source IP, Application signature, Destination Port, or Domain patterns with wildcard matching (e.g., `*.tiktok.com`).
- **Endian-Aware PCAP I/O:** Custom PCAP parser and generator supporting both Little-Endian and Big-Endian packet capture files.

---

## 📂 Project Architecture

```text
├── dpi/
│   ├── __init__.py
│   ├── types.py               # 5-tuple, Connection states, Action enums, Stats
│   ├── pcap.py                # Endian-aware PCAP reader and writer
│   ├── parser.py              # Protocol decoders (Ethernet, IPv4, TCP, UDP)
│   ├── extractors.py          # TLS SNI, HTTP Host, DNS, and QUIC extractors
│   ├── rules.py               # Thread-safe rule management & filtering
│   ├── connection_tracker.py  # Flow table & connection lifecycle tracker
│   ├── queue.py               # Thread-safe bounded queue with shutdown signaling
│   ├── fast_path.py           # Worker threads executing inspection & rule evaluation
│   ├── load_balancer.py       # Consistent hash load balancing across worker threads
│   └── engine.py              # Main DPI multi-threaded pipeline orchestrator
├── tests/                     # Unit test suite covering all modules
├── packet_analyzer.py         # Packet-by-packet CLI decoder & hex viewer
├── packet_inspector_simple.py # Quick line-by-line inspection CLI
├── dpi_simple.py              # Single-threaded DPI engine CLI
├── dpi_mt.py                  # High-performance multi-threaded DPI engine CLI
├── dpi_engine.py              # Full modular DPI engine CLI with custom thread counts
├── run_tests.py               # Automated test runner
├── generate_test_pcap.py      # Test PCAP traffic generator
├── rules.txt                  # Sample filtering rules configuration
└── test_dpi.pcap              # Sample PCAP capture file
```

---

## 🚀 Quick Start

### 1. Packet Analyzer (Inspect Headers & Payloads)
Decode and inspect packet headers and preview payload bytes:
```bash
python packet_analyzer.py test_dpi.pcap
python packet_analyzer.py test_dpi.pcap 10   # Display first 10 packets only
```

### 2. Simple DPI Engine (Single-Threaded)
Filter network traffic, extract TLS SNI, and block by Application or IP:
```bash
# Block YouTube traffic and a specific source IP
python dpi_simple.py test_dpi.pcap filtered.pcap --block-app YouTube --block-ip 192.168.1.50
```

### 3. Multi-Threaded DPI Engine (High Performance)
Pipelines traffic across Reader $\rightarrow$ Load Balancers $\rightarrow$ Fast Path workers $\rightarrow$ Output Writer:
```bash
python dpi_mt.py test_dpi.pcap filtered.pcap --block-app Facebook --block-domain *.tiktok.com
```

### 4. Full Modular Engine CLI
Configurable worker thread counts and rules file support:
```bash
python dpi_engine.py test_dpi.pcap filtered.pcap --lbs 2 --fps 2 --block-app YouTube --block-ip 192.168.1.50
```

### 5. Run All Unit Tests
```bash
python run_tests.py
```

---

## 🔍 How Deep Packet Inspection (DPI) Works

### 1. Protocol Decoding
Every network frame is unpacked layer-by-layer using Python's `struct` module:
- **Layer 2 (Data Link)**: Ethernet header (14 bytes) $\rightarrow$ MAC addresses, EtherType.
- **Layer 3 (Network)**: IPv4 header (20+ bytes) $\rightarrow$ Version, IHL, TTL, Protocol (TCP/UDP), Source IP, Destination IP.
- **Layer 4 (Transport)**: TCP header (20+ bytes) $\rightarrow$ Ports, Sequence/Ack numbers, Data Offset, Flags (SYN, ACK, FIN, RST, PSH).
- **Layer 7 (Application)**: Payload containing TLS Client Hello, HTTP requests, or DNS queries.

### 2. TLS Server Name Indication (SNI) Extraction
Even though HTTPS encrypts traffic, the initial **Client Hello** handshake contains the requested domain name in plaintext:
1. Verify TLS Record Header (`0x16` Handshake).
2. Verify Handshake Type (`0x01` Client Hello).
3. Walk the packet skipping version, 32-byte random, session ID, cipher suites, and compression methods.
4. Iterate TLS Extensions looking for Extension Type `0x0000` (SNI).
5. Extract the server hostname bytes (e.g. `www.youtube.com`).

---

## 🛡️ Blocking & Filtering Rules

Rules can be specified via command-line arguments or loaded from a configuration file:

### Command Line Options
- `--block-ip <ip>`: Drops any packet originating from the source IP (e.g. `192.168.1.50`).
- `--block-app <app>`: Drops any connection identified as the application (e.g. `YouTube`, `Facebook`, `TikTok`).
- `--block-domain <pattern>`: Drops connections matching domain or pattern with wildcards (e.g. `*.tiktok.com`, `facebook`).
- `--block-port <port>`: Drops packets to destination port (e.g. `8080`, `443`).
- `--rules <file>`, `--load-rules <file>`: Loads rules from a configuration file.
- `--save-rules <file>`: Saves active blocking rules to a configuration file.

### Rules File Format (`rules.txt`)
```ini
[BLOCKED_IPS]
192.168.1.50
10.0.0.99

[BLOCKED_APPS]
YouTube
TikTok

[BLOCKED_DOMAINS]
*.badwebsite.com
facebook

[BLOCKED_PORTS]
8080
```

---

## 🧪 Testing

A comprehensive suite of unit tests covers parsing, SNI extraction, rule filtering, multi-threading queues, and PCAP I/O:
```bash
python run_tests.py
```

---

## 📄 License
This project is open-source and available under the [MIT License](LICENSE).
