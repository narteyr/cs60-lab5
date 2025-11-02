#!/usr/bin/env python3
"""
TCP SYN port scanner.

Usage:
    python3 port_scan.py <target_ip> <port_spec>

Used ChatGPT for method formatting and control flow.
"""
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List
from scapy.all import IP, TCP, sr1, send, conf

conf.verb = 0  # silence scapy verbose output

# === Globals you can edit ===
TIMEOUT = 0.2   # seconds to wait for sr1() reply per probe
DELAY   = 0.00  # seconds to sleep before each probe (throttle)
THREADS = 20     # number of worker threads to use
# ============================

def parse_ports(spec: str) -> List[int]:
    ports = set()
    for token in spec.split(','):
        token = token.strip()
        if not token:
            continue
        if '-' in token:
            parts = token.split('-', 1)
            try:
                start = int(parts[0])
                end = int(parts[1])
            except ValueError:
                raise ValueError(f"Invalid range token: {token}")
            if start > end or start < 1 or end > 65535:
                raise ValueError(f"Invalid range: {token}")
            for p in range(start, end + 1):
                ports.add(p)
        else:
            try:
                p = int(token)
            except ValueError:
                raise ValueError(f"Invalid port token: {token}")
            if not (1 <= p <= 65535):
                raise ValueError(f"Port out of range: {p}")
            ports.add(p)
    return sorted(ports)

def is_synack(pkt) -> bool:
    if pkt is None:
        return False
    try:
        if pkt.haslayer(TCP):
            flags = pkt[TCP].flags
            return int(flags) & 0x12 == 0x12  # SYN (0x02) + ACK (0x10) -> 0x12
    except Exception:
        return False
    return False

def probe_port(target_ip: str, port: int, timeout: float, delay: float):
    """
    Probe a single port: returns (port, True/False, error-string-or-None)
    True indicates open (SYN-ACK received).
    """
    # Respect per-probe delay (helps throttle even under concurrency)
    if delay > 0:
        time.sleep(delay)
    syn = IP(dst=target_ip) / TCP(dport=port, flags='S')
    try:
        resp = sr1(syn, timeout=timeout, verbose=0)
    except Exception as e:
        return (port, False, f"send/recv error: {e}")

    if is_synack(resp):
        # send RST to politely close the half-open connection
        try:
            rst = IP(dst=target_ip) / TCP(dport=port, flags='R')
            send(rst, verbose=0)
        except Exception:
            pass
        return (port, True, None)
    # either RST or no reply -> treat as closed/filtered
    return (port, False, None)

def port_scan(target_ip: str, ports: List[int], timeout: float, delay: float, threads: int) -> List[int]:
    open_ports = []
    futures = []
    try:
        with ThreadPoolExecutor(max_workers=threads) as ex:
            for p in ports:
                futures.append(ex.submit(probe_port, target_ip, p, timeout, delay))
            for fut in as_completed(futures):
                try:
                    port, is_open, err = fut.result()
                except Exception as e:
                    print(f"[!] Worker exception: {e}", file=sys.stderr)
                    continue

                if is_open:
                    open_ports.append(port)
                    print(f"[+] Open: {target_ip}:{port}")
                elif err:
                    print(f"[!] Error probing {target_ip}:{port} -> {err}", file=sys.stderr)

    except KeyboardInterrupt:
        print("\nKeyboard interrupt received. Attempting to stop worker threads...")
        # Executor context will exit and wait for tasks to finish; results so far are returned.
    return sorted(open_ports)

def main():
    if len(sys.argv) != 3:
        print("Usage: python3 port_scan.py <target_ip> <port_spec>")
        print("Example: python3 port_scan.py 192.168.60.5 1-1024,8080")
        sys.exit(1)

    target_ip = sys.argv[1]
    port_spec = sys.argv[2]

    try:
        ports = parse_ports(port_spec)
    except ValueError as e:
        print("Error parsing ports:", e, file=sys.stderr)
        sys.exit(1)

    # Ensure 8080 is included per assignment requirement
    if 8080 not in ports:
        ports.append(8080)
    ports = sorted(set(ports))

    print(f"Scanning {target_ip} ports: {ports[0]} ... {ports[-1]} (total {len(ports)})")
    print(f"Configuration (globals): TIMEOUT={TIMEOUT}s DELAY={DELAY}s THREADS={THREADS}")

    try:
        open_ports = port_scan(target_ip, ports, timeout=TIMEOUT, delay=DELAY, threads=THREADS)
    except KeyboardInterrupt:
        print("\nKeyboard interrupt received in main. Exiting.")
        open_ports = []

    # Print only open ports <= 1024 and also 8080 if open
    print("\nScan result (reported ports are <=1024 and/or 8080):")
    reported = []
    for p in sorted(open_ports):
        if p <= 1024 or p == 8080:
            reported.append(p)
            print(f"{target_ip}:{p} open")

    if not reported:
        print("(no open ports <=1024 or 8080 found)")

if __name__ == "__main__":
    main()
