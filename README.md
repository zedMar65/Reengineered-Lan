# Reengineered-LAN: A Framework for MAC-less LAN Communication

This project aims to enhance LAN security by eliminating the ARP protocol and the need for MAC-based routing. By doing so, it addresses certain security vulnerabilities associated with using MAC addresses in LAN environments.

## Features
### Already Available
- **Custom UDP Packet Creation**: Easily craft and send UDP packets without relying on MAC addresses.
- **TCP Session Management**: Establish, manage, and terminate TCP sessions programmatically.
- **Error Handling**: Provides comprehensive error reporting for robust application development.

### Soon to Be Added
- **Custom NIC Drivers**: Enable sending MAC-less packets at the hardware level.
- **Raspberry Pi Firmware**: Dedicated firmware to facilitate MAC-less communication.
- **Example Applications**: Practical implementations demonstrating usage.
- **Comprehensive Documentation**: Expanded guides and tutorials for developers.
- **Regular Releases**: Periodic updates with bug fixes and new features.
- **Supporting Libraries**: Additional tools and libraries for extended functionality.

---

## Installation

Ensure you have the required dependencies installed:

```bash
pip install scapy
```

Clone the repository and ensure the following scripts are in your working directory:

```bash
git clone <repository-url>
cd reengineered-lan
```

- `main.py`: Contains the core logic for MAC-less communication.
- `errors.py`: Manages error codes and exceptions.

---

## Usage

### 1. UDP Packet Creation
Use the `form_udp` function to create a custom UDP packet.

#### Function Signature:
```python
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
```

#### Example:
```python
from main import form_udp

packet = form_udp(
    src_port=12345,
    dst_port=80,
    src_ip="192.168.1.2",
    dst_ip="192.168.1.3",
    data="Hello, world!"
)

print(packet)
```

---

### 2. TCP Session Management
Manage TCP sessions using the `tcp_session` class. The class allows session setup, data transmission, and termination.

#### Example: Server Mode
```python
from main import tcp_session

# Initialize a TCP session in server mode
server_session = tcp_session(src_port=8080, src_ip="192.168.1.1", iface="eth0", mode="S")

# Wait for a connection
if server_session.listen_accept():
    print("Connection accepted!")

# Receive data
data = server_session.listen()
print(f"Received data: {data}")

# Close the session
server_session.close()
```

#### Example: Client Mode
```python
from main import tcp_session

# Initialize a TCP session in client mode
client_session = tcp_session(src_port=12345, src_ip="192.168.1.2", iface="eth0", dst_port=8080, dst_ip="192.168.1.1", mode="C")

# Connect to the server
if client_session.connect():
    print("Connected to server!")

# Send data
client_session.send("Hello, server!")

# Close the session
client_session.close()
```

---

## Error Handling
Errors in the framework are managed using the `errors.py` module. The `ReLanError` exception provides detailed error messages.

### Example:
```python
from errors import raiseError

try:
    raiseError(2, Exception("Custom error message"))
except Exception as e:
    print(e)
```

### Error Codes:
| Code | Description                                           |
|------|-------------------------------------------------------|
| 0    | No error                                              |
| 1    | No response to TCP packet                             |
| 2    | Exception occurred while building the packet          |
| 3    | Unexpected response to TCP packet                    |
| 4    | Unknown error during TCP handshake                   |

---

## Notes
1. **Objective**: The goal of this project is to explore MAC-less LAN communication for increased security.
2. **Dependencies**: Ensure that `scapy` and any required system configurations for raw packet sending are properly set up.
3. **Future Enhancements**: Planned features include:
   - Support for additional protocols.
   - Advanced security mechanisms.
   - Comprehensive testing frameworks.

---

## Contribution
Feel free to contribute by submitting pull requests or reporting issues. This project is in its early stages, and community feedback is highly appreciated.

---

## License
This project is licensed under the GNU GENERAL PUBLIC LICENSE v3 License. See `LICENSE` for details.