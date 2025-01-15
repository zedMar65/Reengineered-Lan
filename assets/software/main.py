from pkg_handle import form_udp

def main():
    src_port = 12345
    dst_port = 54321
    src_ip = "0.0.0.0"
    dst_ip = "1.1.1.1"
    data = "Hello, World!"
    packet = form_udp(src_port, dst_port, src_ip, dst_ip, data)
    print(packet)


if __name__ == "__main__":
    main()