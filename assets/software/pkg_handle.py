from scapy.all import IP, UDP, Raw

def form_udp(
    src_port: int,
    dst_port: int,
    src_ip: str,
    dst_ip: str,
    data: str,
    ttl: int = 64,
    ihl: int = 5,
    version: int = 4,
    tos: int = 0,
    flags: int = 0,
    frag: int = 0,
    proto: int = 17,
    id: int = 1,
):
    # No IP options passed, just set to None
    packet = IP(src=src_ip, dst=dst_ip, ttl=ttl, ihl=ihl, version=version, tos=tos, flags=flags, frag=frag, proto=proto, id=id) / \
             UDP(sport=src_port, dport=dst_port) / \
             Raw(data)
    packet.build()  # Build the packet
    return packet  # Return the raw bytes of the packet