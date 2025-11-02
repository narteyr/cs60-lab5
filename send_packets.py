from scapy.all import IP, sr1, ICMP, conf


def send_icmp_request(ip_address,timeout = 5):
    pkt = IP(dst=ip_address)/ICMP()

    reply = sr1(pkt, timeout=timeout)
    if reply is None:
        print("no reply from {ip_address}")
    else:
        print(f"received a reply: {reply.src}")


if __name__ == "__main__":
    send_icmp_request("192.168.60.2")
