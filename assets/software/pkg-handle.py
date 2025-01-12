from scapy.all import IP, UDP, Raw, sendp

def send_macless_packet(dst_ip, src_ip, src_port, dst_port, payload, iface):
    ip = IP(src=src_ip, dst=dst_ip)
    udp = UDP(sport=src_port, dport=dst_port)
    raw_payload = Raw(load=payload)
    pkt = ip / udp / raw_payload

    # Send packet at Layer 2 (without Ethernet headers)
    sendp(pkt, iface=iface, iface_hint=False)
    print(pkt.show())


send_macless_packet('192.168.1.1', '192.168.1.134', 12345, 80, 'Hello, World!', 'Wi-Fi')
