#!/usr/bin/env python3
from scapy.all import *

conf.verb = 0

def http_post(host, port=60, path="/", form="username=f007b2s&password=work"):
    sport = RandShort()
    ip = IP(dst=host)

    # 1) SYN -> SYN/ACK
    syn  = TCP(sport=sport, dport=port, flags="S", seq=1)
    synack = sr1(ip/syn, timeout=2)
    if not synack:
        print("No SYN-ACK (closed/filtered).")
        return

    # 2) ACK
    ack = TCP(sport=sport, dport=port, flags="A",
              seq=synack.ack, ack=synack.seq + 1)
    send(ip/ack)

    # 3) HTTP request
    req = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: Scapy\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(form)}\r\n"
        f"Connection: close\r\n\r\n"
        f"{form}"
    ).encode("ascii")

    psh = TCP(sport=sport, dport=port, flags="PA",
              seq=synack.ack, ack=synack.seq + 1)

    # send payload, wait for first reply packet
    resp = sr1(ip/psh/Raw(req), timeout=3)
    if resp and Raw in resp:
        print(resp[Raw].load.decode(errors="ignore"))
    else:
        print("No HTTP response (maybe different port/protocol or filtered).")

# ---- run it ----
http_post("192.168.60.4", port=60, path="/")