#!/usr/bin/env python3
"""
get_subnet.py - return subnet ID for default interface as CIDR
prints e.g. 192.168.60.0/24
"""

import subprocess
import ipaddress
import sys

def get_default_iface():
    out = subprocess.check_output(["ip", "route", "show", "default"], text=True)
    # line looks like: "default via 172.17.0.1 dev eth0 proto dhcp metric 100"
    for token_i, token in enumerate(out.split()):
        if token == "dev" and token_i+1 < len(out.split()):
            return out.split()[token_i+1]
    raise RuntimeError("Could not determine default interface")

def get_addr_with_prefix(iface):
    out = subprocess.check_output(["ip", "-4", "addr", "show", "dev", iface], text=True)
    # find first 'inet X.X.X.X/YY'
    import re
    m = re.search(r'\binet\s+(\d+\.\d+\.\d+\.\d+/\d+)\b', out)
    if not m:
        raise RuntimeError(f"No IPv4 address found on {iface}")
    return m.group(1)

def get_subnet_cidr():
    iface = get_default_iface()
    ip_and_prefix = get_addr_with_prefix(iface)
    network = ipaddress.ip_interface(ip_and_prefix).network
    return str(network.with_prefixlen)

if __name__ == "__main__":
    try:
        print(get_subnet_cidr())
    except Exception as e:
        print("Error:", e, file=sys.stderr)
        sys.exit(1)
