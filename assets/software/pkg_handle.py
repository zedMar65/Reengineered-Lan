from scapy.all import IP, UDP, Raw, TCP
from errors import raiseError

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
) -> bytes:
    # No IP options passed, just set to None
    try:
        packet = IP(src=src_ip, dst=dst_ip, ttl=ttl, ihl=ihl, version=version, tos=tos, flags=flags, frag=frag, proto=proto, id=id) / \
                 UDP(sport=src_port, dport=dst_port) / \
                 Raw(data)
        packet.build()  # Build the packet
        return packet  # Return the raw bytes of the packet
    except Exception as e:
        raiseError(2)
# managing tcp sockets, Yai!
class tcp_session:
    def __init__(self, src_port: int, dst_port: int, src_ip: str, dst_ip: str):
        self.src_port = src_port
        self.dst_port = dst_port
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.seq = 0
        self.ack = 0
        self.sync()
    def sync(self):
        syn_packet = IP(src=self.src_ip, dst=self.dst_ip) / TCP(sport=self.src_port, dport=self.dst_port, flags="S", seq=self.seq)
        syn_response = sr1(syn_packet) # Send the SYN packet and wait for a response
        if syn_response is None:
            raise Exception("No response to SYN packet")
