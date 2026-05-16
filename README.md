# Packet Sniffer

A beginner-friendly network packet sniffer built with Python and Scapy.
Captures live traffic on your machine, identifies protocols, and highlights DNS queries — revealing which websites your device is looking up in real time.

Built as part of learning network security fundamentals.

---

## What it does

- Captures live packets from your network interface
- Identifies protocol: TCP, UDP, ICMP
- Shows source IP → destination IP and port number
- Highlights DNS queries — you can see every domain your machine looks up, even on "secure" HTTPS connections (because DNS itself is unencrypted by default)

---

## Sample output

```
  ────────────────────────────────────────────────────
  Python Packet Sniffer
  Filter : none (all traffic)
  Count  : unlimited
  ────────────────────────────────────────────────────

  #1    TCP    192.168.1.5 → 142.250.74.46   port 443
  #2    UDP    192.168.1.5 → 8.8.8.8         port 53
         ↳ DNS query: youtube.com
  #3    UDP    192.168.1.5 → 8.8.8.8         port 53
         ↳ DNS query: instagram.com
  #4    TCP    192.168.1.5 → 93.184.216.34   port 80
  #5    ICMP   192.168.1.5 → 8.8.8.8         port -
```

---

## How it works

Every message you send over a network is broken into **packets** — small chunks of data, each with a header (who it's from, where it's going) and a payload (the actual content).

This tool puts your network card into **promiscuous mode**, which lets it capture all packets flowing through the interface — not just the ones addressed to your machine.

Each packet is structured in layers (like an onion):

```
[ Ethernet ]  ←  hardware-level addressing (MAC addresses)
    [ IP ]    ←  network-level addressing (IP addresses)
      [ TCP / UDP ]  ←  port numbers, connection type
          [ Data ]   ←  the actual content
```

The sniffer reads each layer and prints what it finds.

---

## The DNS insight

Even when a website uses HTTPS (encrypted), your machine still has to ask a DNS server "what's the IP address of youtube.com?" — and that DNS query travels in plain text by default.

This means anyone on your network can see *which websites you're visiting*, even if they can't read the content. Run this sniffer and open a few websites — you'll see exactly this happening live.

---

## Setup

**Requirements:** Python , Scapy

```bash
pip install scapy
```

**Run:**

```bash
# Capture all traffic
python sniffer.py

# DNS queries only
python sniffer.py --filter "udp port 53"

# Traffic to/from a specific host
python sniffer.py --filter "host 8.8.8.8"

# Stop after 50 packets
python sniffer.py --count 50
```

---

## What I learned

- How network packets are structured across the OSI layers
- What promiscuous mode is and why sniffers need it
- How DNS works and why it exposes browsing metadata even over HTTPS
- How to use Scapy to capture and dissect live traffic

---

## Ethical note

Packet sniffing your **own** network or machine is legal and is how network engineers debug issues every day. Capturing traffic on a network you don't own or administer is illegal in most countries. This project is for educational use only.

---

## Next steps / ideas

- [ ] Save captures to `.pcap` files (readable by Wireshark)
- [ ] Detect ARP spoofing attempts
- [ ] Add a web dashboard showing live traffic stats
- [ ] Log unencrypted HTTP payloads