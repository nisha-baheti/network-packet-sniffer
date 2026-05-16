"""
Packet Sniffer — Educational Project
Built with Python + Scapy

What this does:
  - Captures live network packets on your machine
  - Identifies the protocol (TCP, UDP, ICMP)
  - Shows source and destination IPs and ports
  - Highlights DNS queries (websites being looked up)

Run with:
  sudo python3 sniffer.py
  sudo python3 sniffer.py --filter "udp port 53"   # DNS only
  sudo python3 sniffer.py --count 20               # stop after 20 packets

Requires: pip install scapy
"""

import argparse
from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, DNSQR

# ── Colour codes for terminal output ──────────────────────────────────────────
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
RESET  = "\033[0m"
DIM    = "\033[2m"

packet_count = 0

# ── Handle each captured packet ────────────────────────────────────────────────
def handle_packet(pkt):
    global packet_count
    packet_count += 1

    # Skip packets with no IP layer (e.g. ARP)
    if not pkt.haslayer(IP):
        return

    src = pkt[IP].src
    dst = pkt[IP].dst

    # Figure out which protocol and port
    if pkt.haslayer(TCP):
        proto = "TCP"
        port  = pkt[TCP].dport
        color = CYAN
    elif pkt.haslayer(UDP):
        proto = "UDP"
        port  = pkt[UDP].dport
        color = GREEN
    elif pkt.haslayer(ICMP):
        proto = "ICMP"
        port  = "-"
        color = YELLOW
    else:
        proto = "OTHER"
        port  = "-"
        color = DIM

    # Print the basic packet line
    print(f"  {DIM}#{packet_count:<4}{RESET} {color}{proto:5}{RESET}  "
          f"{src:>18} → {dst:<18}  port {port}")

    # DNS highlight — show the domain being looked up
    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
        domain = pkt[DNSQR].qname.decode().rstrip(".")
        print(f"         {RED}↳ DNS query: {domain}{RESET}")

# ── Entry point ────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Simple packet sniffer")
    parser.add_argument("--filter", default=None,
                        help="BPF filter e.g. 'tcp', 'port 53', 'host 8.8.8.8'")
    parser.add_argument("--count",  default=0, type=int,
                        help="Stop after N packets (default: run forever)")
    args = parser.parse_args()

    print(f"\n  {'─'*52}")
    print(f"  Python Packet Sniffer")
    print(f"  Filter : {args.filter or 'none (all traffic)'}")
    print(f"  Count  : {args.count or 'unlimited'}")
    print(f"  {'─'*52}\n")
    print(f"  Press Ctrl+C to stop.\n")

    try:
        sniff(filter=args.filter, count=args.count, prn=handle_packet)
    except KeyboardInterrupt:
        print(f"\n  Stopped. Total packets captured: {packet_count}\n")
    except PermissionError:
        print("\n  Error: run with sudo — raw sockets need root access.\n")

if __name__ == "__main__":
    main()