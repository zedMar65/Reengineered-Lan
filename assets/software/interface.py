import serial, time

"""
A tempurary interface for the software
It should mimic the functions of Scapy,
thou not with internet ports, but with
UART ports(simple serial ports(which are
simple USB ports(which are not simple))))
"""

"""
encapsulation functions for the class
"""
def send():
    Interface.send()
def sr1():
    Interface.sr1()
def sniff():
    Interface.sniff()

"""
A static class for the interface
which contains the functions
these functions should act just like the Scapy equivalents, just with UART ports, and not internet ports
they should have capabilities for args, like lfilter, iface, etc.
send - sends data a singular time to a destination serial port, encoded in utf-8
sr1 - sends data a singular time to a destination serial port, encoded in utf-8, and waits for a response, returns it
sniff - listens for incoming data on a serial port, returns it
"""
class Interface:
    # the UART port to send/listen data to
    UARTPORT = None

    @staticmethod
    def sendp(self, data: str, iface: str = UARTPORT) -> int:
        ser = serial.Serial(iface, 9600, timeout=1)
        ser.write(data.encode('utf-8'))
        ser.close()
        return 1

    @staticmethod
    def sr1(self, data: str, iface: str = UARTPORT) -> str:
        ser = serial.Serial(iface, 9600, timeout=1)
        ser.write(data.encode('utf-8'))
        response = ser.read(1024).decode('utf-8')
        ser.close()
        return response

    @staticmethod
    def sniff(self, iface: str = UARTPORT, lfilter = None, filter: str = None, prn = None, timeout = None, count = 1) -> str:
        ser = serial.Serial(iface, 9600, timeout=timeout)
        packets = []
        start_time = time.time()

        while len(packets) < count:
            if timeout and (time.time() - start_time) > timeout:
                break
            data = ser.read(1024).decode('utf-8')
            if data:
                if lfilter is None or lfilter(data):
                    packets.append(data)
                if prn:
                    prn(data)

        ser.close()
        return packets