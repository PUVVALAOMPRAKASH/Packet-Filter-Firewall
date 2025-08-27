# Simple Firewall / Packet Filter

## Features
- Blocks traffic by **IP**, **Port**, or **Protocol**
- Uses **Scapy + NetfilterQueue**
- Rules configurable via `rules.json`

## Setup
1. Install dependencies: `pip install -r requirements.txt`
2. Add iptables rule:
   sudo iptables -I FORWARD -j NFQUEUE --queue-num 1
3. Run firewall:
   sudo python3 main.py
