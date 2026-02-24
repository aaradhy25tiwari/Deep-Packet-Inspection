# Deep-Packet-Inspection
Deep Packet Inspection (DPI) is a technology used to examine the contents of network packets as they pass through a checkpoint.

## Table of Contents

1. [What is DPI?](#1-what-is-dpi)
2. [Requirements](#2-requirements)
    - [Hardware Requirements](#hardware-requirements)
    - [Software Requirements](#software-requirements)
3. [Usage](#3-usage)

---


## 1. What is DPI?

**Deep Packet Inspection (DPI)** is a technology used to examine the contents of network packets as they pass through a checkpoint. Unlike simple firewalls that only look at packet headers (source/destination IP), DPI looks *inside* the packet payload.

### Real-World Uses:
- **ISPs**: Throttle or block certain applications (e.g., BitTorrent)
- **Enterprises**: Block social media on office networks
- **Parental Controls**: Block inappropriate websites
- **Security**: Detect malware or intrusion attempts

### What Our DPI Engine Does:
```
User Traffic (PCAP) → [DPI Engine] → Filtered Traffic (PCAP)
                           ↓
                    - Identifies apps (YouTube, Facebook, etc.)
                    - Blocks based on rules
                    - Generates reports
```

---

## 2. Requirements

### Hardware Requirements

---
Requirement | Minimum	            | Recommended                       |
------------|-----------------------|-----------------------------------|
CPU	        | Any modern processor  | Multi-core for large PCAP files   |
RAM	        | 2 GB	                | 4 GB+ (for large packet captures) |
Disk Space	| 100 MB	            | Depends on PCAP file sizes        |
---

### Software Requirements

---
Python 3.7 or higher

## 3. Usage

```powershell
python dpi_engine.py <input.pcap> <output.pcap> [--block-ip IP] [--block-app APP] [--block-domain DOMAIN]
```
### Example
```powershell
python dpi_engine.py test_dpi.pcap output.pcap --block-app YouTube --block-ip 192.168.1.50
```

---
