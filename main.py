from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP, UDP, ICMP
import json, logging

# Load rules
with open("rules.json") as f:
    rules = json.load(f)

# Configure logging
logging.basicConfig(
    filename="firewall.log",
    level=logging.INFO,
    format="%(asctime)s - %(message)s",
)

def log_and_drop(pkt, reason):
    logging.info(reason)
    print(reason)
    pkt.drop()

def packet_filter(pkt):
    scapy_pkt = IP(pkt.get_payload())

    if scapy_pkt.src in rules["block_ips"] or scapy_pkt.dst in rules["block_ips"]:
        log_and_drop(pkt, f"[DROP] IP Block: {scapy_pkt.src} -> {scapy_pkt.dst}")
        return

    if TCP in scapy_pkt or UDP in scapy_pkt:
        sport, dport = scapy_pkt.sport, scapy_pkt.dport
        if sport in rules["block_ports"] or dport in rules["block_ports"]:
            log_and_drop(pkt, f"[DROP] Port Block: {sport} or {dport}")
            return

    if ICMP in scapy_pkt and "ICMP" in rules["block_protocols"]:
        log_and_drop(pkt, f"[DROP] Protocol Block: ICMP {scapy_pkt.summary()}")
        return

    pkt.accept()

def main():
    nfqueue = NetfilterQueue()
    nfqueue.bind(1, packet_filter)
    try:
        print("[*] Firewall started... Logs -> firewall.log (Ctrl+C to stop)")
        nfqueue.run()
    except KeyboardInterrupt:
        print("\n[!] Stopping firewall")
    finally:
        nfqueue.unbind()

if __name__ == "__main__":
    main()
