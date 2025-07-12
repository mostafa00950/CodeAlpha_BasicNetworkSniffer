# CodeAlpha_BasicNetworkSniffer

##  Project: Basic Network Sniffer (Cyber Security Internship Task 1)

This Python-based network sniffer captures and analyzes Ethernet and IPv4 packets in real-time using raw sockets.

##  Features

- Captures live network traffic
- Parses Ethernet frames
- Extracts and analyzes IPv4 packet headers
- Displays:
  - Source and Destination MAC and IP addresses
  - Protocol type (TCP, UDP, ICMP, etc.)
  - TTL
  - Payload in Hex + ASCII format (like Wireshark)
  - Timestamp of each packet

##  Sample Output

```
   Ethernet Frame:
    - Version        : 4 (IPv4)
    - Header Length  : 20
    - TTL            : 64
    - Protocol       : 1 (ICMP)
    - Destination MAC: 00:0C:29:23:60:11
    - Destination IP : 192.168.1.6
    - Source MAC     : D8:E8:44:E5:8F:34
    - Source IP      : 8.8.8.8
    - Protocol       : 8
    - Timestamp      : 2025-07-12 15:15:19
    - Payload         :
    0000  00 00 22 e0 7d 7f 00 06 47 b4 72 28 00 00 00 00   ..".....G.rh....
    0010  d8 aa 0e 00 00 00 00 00 10 11 12 13 14 15 16 97   ................
    0040  18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25 26 27   ........ !"#$%&'
    0030  28 29 2a 2b 2d 2d 2e 2f 30 31 32 33 34 35 36 37   (-*+,-./09656667



```

##  How to Run

1. Clone the repo or download the script.
2. Make sure you're on a Linux machine (e.g. Kali Linux).
3. Run the script with sudo:

```bash
sudo python3 sniffer.py
```

4. In another terminal, generate traffic using:

```bash
ping 8.8.8.8
```

## 🎓 Created for:
CodeAlpha Cyber Security Internship  
Task:     Basic Network Sniffer  
Intern:   Mostafa Mohamed Elsayed Abdalshafy
