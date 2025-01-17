from scapy.all import IP, UDP, Raw, TCP, sr1, send, sniff
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
        raiseError(2, e)
# managing tcp sockets, Yai!
class tcp_session:
    """
    Initialize a TCP session
    src_port: source port
    dst_port: destination port
    src_ip: source IP address
    dst_ip: destination IP address
    iface: network interface to use
    """
    def __init__(self, src_port: int, src_ip: str, iface: str, dst_port: int = None, dst_ip: str = None,  mode: str = "C") -> None:
        self.src_port = src_port
        self.dst_port = dst_port
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.seq = 0
        self.ack = 0
        self.iface = iface
        self.is_active = False
        self.mode = mode
    # usable functions, for session control
    """
    Accept a session request from any source
    return 1 if the session is accepted
    Primaraily used in server mode
    """
    def listen_accept(self):
        # wait for a syn packet
        syn_packet = sniff(
        filter="tcp", 
        prn=None,
        lfilter=lambda pkt: IP in pkt and TCP in pkt and pkt[TCP].flags == "S", count=1
        )
        if not syn_packet:
            return 0
        self.src_ip = syn_packet[0][IP].dst
        self.dst_ip = syn_packet[0][IP].src
        self.src_port = syn_packet[0][TCP].dport
        self.dst_port = syn_packet[0][TCP].sport
        self.seq = syn_packet[0].ack
        self.ack = syn_packet[0].seq + 1
        SA_packet = IP(src=self.src_ip, dst=self.dst_ip) / TCP(sport=self.src_port, dport=self.dst_port, flags="SA", seq=self.seq, ack=self.ack)
        SA_response = sr1(SA_packet, iface=self.iface)
        if SA_response is None:
            raiseError(1)
        if SA_response[TCP].flags != "A":
            raiseError(3)
        self.seq = SA_response.ack
        self.ack = SA_response.seq + 1
        self.is_active = True
        return 1
    """
    Wait for a session request
    return 1 if the session is accepted
    """
    def await_accept(self, timeout=None) -> int:
        # wait for a syn packet
        syn_packet = sniff(
        filter="tcp", 
        prn=None,
        lfilter=lambda pkt: IP in pkt and TCP in pkt and pkt[IP].src == self.dst_ip and pkt[IP].dst == self.src_ip and pkt[TCP].sport == self.dst_port and pkt[TCP].dport == self.src_port and pkt[TCP].flags == "S", count=1,
        timeout=timeout
        )
        if not syn_packet:
            return 0
        self.seq = syn_packet[0].ack
        self.ack = syn_packet[0].seq + 1
        SA_packet = IP(src=self.src_ip, dst=self.dst_ip) / TCP(sport=self.src_port, dport=self.dst_port, flags="SA", seq=self.seq, ack=self.ack)
        SA_response = sr1(SA_packet, iface=self.iface)
        if SA_response is None:
            raiseError(1)
        if SA_response[TCP].flags != "A":
            raiseError(3)
        self.seq = SA_response.ack
        self.ack = SA_response.seq + 1
        self.is_active = True
        return 1
    """
    Activate the session, if it's closed
    return 1 if the session is reactivated successfully
    """
    def connect(self) -> int:
        if self.is_active:
            return 1
        self.seq = 0
        self.ack = 0
        if self._sync() != 1:
            raiseError(4)
        self.is_active = True
        return 1
    # close the session
    """
    Close the session
    return 1 if the session is closed successfully
    """
    def close(self) -> int:
        if not self.is_active:
            return 1
        fin_packet = IP(src=self.src_ip, dst=self.dst_ip) / TCP(sport=self.src_port, dport=self.dst_port, flags="FA", seq=self.seq, ack=self.ack)
        fin_response = sr1(fin_packet, iface=self.iface)
        if fin_response == None:
            raiseError(1)
        if fin_response[TCP].flags != "A":
            raiseError(3)
        self.seq = fin_response.ack
        self.ack = fin_response.seq + 1
        fin_ack_packet = IP(src=self.src_ip, dst=self.dst_ip) / TCP(sport=self.src_port, dport=self.dst_port, flags="A", seq=self.seq, ack=self.ack)
        send(fin_ack_packet, iface=self.iface)
        self.is_active = False
        return 1
    """
    Send data to the destination
    data: data to send
    return 1 if the data is sent successfully
    """
    def send(self, data: str) -> int:
        if not self.is_active:
            return 0
        packet = IP(src=self.src_ip, dst=self.dst_ip) / TCP(sport=self.src_port, dport=self.dst_port, flags="PA", seq=self.seq, ack=self.ack) / Raw(data)
        response = sr1(packet, iface=self.iface)
        if response is None:
            raiseError(1)
        if response[TCP].flags != "A":
            raiseError(3)
        self.seq = response.ack
        self.ack = response.seq + 1
        return 1
    """
    Listen for incoming data
    timeout: time to wait for incoming data
    return the incoming data
    """
    def listen(self, timeout=None) -> str:
        # Capture packets matching the filter
        packet = sniff(filter="tcp", prn=None, timeout=timeout, lfilter=self._packet_filter, count=1)
        if not packet:
            return None
        
        self.ack = packet[0].seq + 1
        self.seq = packet[0].ack
        self._acknoladge()
        return packet[Raw].load.decode()
    # private functions
    # packet filter
    """
    Filter packets
    pkt: packet to filter
    return True if the packet matches the filter
    """
    def _packet_filter(self, pkt):
        return (
            IP in pkt and TCP in pkt and
            pkt[IP].src == self.dst_ip and pkt[IP].dst == self.src_ip and
            pkt[TCP].sport == self.dst_port and pkt[TCP].dport == self.src_port
        )
    # TCP handshake
    """
    Perform the TCP handshake
    return 1 if the handshake is successful
    """
    def _sync(self) -> int:
        syn_packet = IP(src=self.src_ip, dst=self.dst_ip) / TCP(sport=self.src_port, dport=self.dst_port, flags="S", seq=self.seq)
        syn_response = sr1(syn_packet, iface = self.iface) # Send the SYN packet and wait for a response
        if syn_response is None:
            raiseError(1)
        if syn_response[TCP].flags != "SA":
            raiseError(3)
        self.seq = syn_response.ack
        self.ack = syn_response.seq + 1
        
        self._acknoladge()
        self.is_active = True
        return 1
    """
    Acknowledge the packet
    return 1 if the packet is acknowledged successfully
    """
    def _acknoladge(self) -> int:
        try:
            ack_packet = IP(src=self.src_ip, dst=self.dst_ip) / TCP(sport=self.src_port, dport=self.dst_port, flags="A", seq=self.seq, ack=self.ack)
            send(ack_packet, iface=self.iface)
        except Exception as e:
            raiseError(4, e)
        return 1