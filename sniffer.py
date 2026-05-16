import argparse
import json
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, DNSQR

# Colour codes for terminal output
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
RESET  = "\033[0m"
DIM    = "\033[2m"

packet_count = 0
log_file     = None   # plain text file handle
json_records = []     # list of dicts, saved as JSON on exit

#Handle each captured packet 
def handle_packet(pkt):
    global packet_count
    packet_count += 1

    # Skip anything without an IP layer
    if not pkt.haslayer(IP):
        return

    src = pkt[IP].src
    dst = pkt[IP].dst
    ts  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Identify protocol and port
    if pkt.haslayer(TCP):
        proto, port, color = "TCP", pkt[TCP].dport, CYAN
    elif pkt.haslayer(UDP):
        proto, port, color = "UDP", pkt[UDP].dport, GREEN
    elif pkt.haslayer(ICMP):
        proto, port, color = "ICMP", "-", YELLOW
    else:
        proto, port, color = "OTHER", "-", DIM

    dns_query = None
    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
        dns_query = pkt[DNSQR].qname.decode().rstrip(".")

    #Print to terminal
    print(f"  {DIM}#{packet_count:<5}{RESET}{color}{proto:5}{RESET}"
          f"  {src:>18} → {dst:<18}  port {port}")
    if dns_query:
        print(f"           {RED}↳ DNS query: {dns_query}{RESET}")

    #Write to plain text log
    log_file.write(f"[{ts}] #{packet_count:<5} {proto:5}"
                   f"  {src:>18} → {dst:<18}  port {port}\n")
    if dns_query:
        log_file.write(f"            ↳ DNS query: {dns_query}\n")
    log_file.flush()   # write immediately, don't wait for buffer

    #Append to JSON records
    record = {
        "num":       packet_count,
        "timestamp": ts,
        "protocol":  proto,
        "src":       src,
        "dst":       dst,
        "port":      port,
    }
    if dns_query:
        record["dns_query"] = dns_query

    json_records.append(record)


def main():
    global log_file

    parser = argparse.ArgumentParser(description="Simple packet sniffer")
    parser.add_argument("--filter", default=None,
                        help="BPF filter e.g. 'tcp', 'port 53', 'host 8.8.8.8'")
    parser.add_argument("--count",  default=0, type=int,
                        help="Stop after N packets (default: run forever)")
    args = parser.parse_args()

    # Each run gets its own timestamped files — no overwriting old captures
    run_id    = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_path  = f"capture_{run_id}.log"
    json_path = f"capture_{run_id}.json"

    log_file = open(log_path, "w", encoding="utf-8")

    # Write header into the log
    header = (f"Packet Sniffer — started {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
              f"Filter : {args.filter or 'none (all traffic)'}\n"
              f"Count  : {args.count or 'unlimited'}\n"
              + "-" * 60 + "\n")
    log_file.write(header)

    print(f"\n  {'─'*52}")
    print(f"  Python Packet Sniffer")
    print(f"  Filter : {args.filter or 'none (all traffic)'}")
    print(f"  Count  : {args.count or 'unlimited'}")
    print(f"  Log    : {log_path}")
    print(f"  JSON   : {json_path}")
    print(f"  {'─'*52}\n")
    print(f"  Press Ctrl+C to stop.\n")

    try:
        sniff(filter=args.filter, count=args.count, prn=handle_packet)
    except KeyboardInterrupt:
        pass
    except PermissionError:
        print("\n  Error: run as Administrator (Windows) or with sudo (Linux/Mac).\n")

    #Save JSON on exit
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(json_records, f, indent=2)

    #Close log with a footer
    log_file.write("-" * 60 + "\n")
    log_file.write(f"Capture ended. Total packets captured: {packet_count}\n")
    log_file.close()

    print(f"\n  Stopped. {packet_count} packets captured.")
    print(f"  Log  saved → {log_path}")
    print(f"  JSON saved → {json_path}\n")

if __name__ == "__main__":
    main()