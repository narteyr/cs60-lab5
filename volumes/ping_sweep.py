#!/usr/bin/env python3
"""
ping_sweep.py
Send ICMP pings to all hosts in a given subnet (CIDR notation)
Usage: python3 ping_sweep.py 192.168.60.0/24
Note: Running inside Docker containers often runs as root by default (no sudo needed).
On regular hosts you may need raw-socket capability (e.g., run with appropriate privileges).
"""

import sys
from scapy.all import ICMP, IP, sr1, conf
import ipaddress
import time

def ping_sweep(subnet_cidr):
    # Convert the subnet string to an ip_network object
    try:
        network = ipaddress.ip_network(subnet_cidr, strict=False)
    except ValueError:
        print(f"Invalid subnet: {subnet_cidr}")
        sys.exit(1)

    print(f"Scanning subnet: {subnet_cidr}")
    alive_hosts = []

    try:
        # Iterate over all usable hosts in the subnet
        for host in network.hosts():  # Excludes network and broadcast addresses
            ip_str = str(host)
            # Build ICMP packet
            pkt = IP(dst=ip_str) / ICMP()
            try:
                # Send packet and wait for reply (timeout = 1 second)
                reply = sr1(pkt, timeout=1, verbose=0)
            except KeyboardInterrupt:
                # If user hits Ctrl+C during sr1, break out to print summary
                print("\nKeyboard interrupt received. Stopping scan...")
                break
            except Exception as e:
                # Catch other scapy/network errors, continue scanning
                print(f"[!] Error scanning {ip_str}: {e}")
                continue

            if reply:
                print(f"[+] Host alive: {ip_str}")
                alive_hosts.append(ip_str)

            # Optional: small delay to avoid flooding network
            try:
                time.sleep(0.01)
            except KeyboardInterrupt:
                print("\nKeyboard interrupt received. Stopping scan...")
                break

    except KeyboardInterrupt:
        # Extra safety: catch any KeyboardInterrupt that bubbles up
        print("\nKeyboard interrupt received. Stopping scan...")

    # Print summary
    print("\nPing sweep complete. Alive hosts:")
    if alive_hosts:
        for host in alive_hosts:
            print(host)
    else:
        print("(none found so far)")
    return alive_hosts

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 ping_sweep.py <subnet_cidr>")
        sys.exit(1)

    subnet_cidr = sys.argv[1]
    # Ensure scapy uses your interface's default route
    conf.verb = 0

    try:
        ping_sweep(subnet_cidr)
    except KeyboardInterrupt:
        # Final catch in case Ctrl+C happens outside the scan loop
        print("\nKeyboard interrupt received. Exiting.")
        sys.exit(0)
