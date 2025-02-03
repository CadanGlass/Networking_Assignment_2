# Parse Ethernet header
def parse_ethernet_header(hex_data):
    dest_mac = ':'.join(hex_data[i:i+2] for i in range(0, 12, 2))
    source_mac = ':'.join(hex_data[i:i+2] for i in range(12, 24, 2))
    ether_type = hex_data[24:28]

    print(f"Ethernet Header:")
    print(f"  {'Destination MAC:':<25} {hex_data[0:12]:<20} | {dest_mac}")
    print(f"  {'Source MAC:':<25} {hex_data[12:24]:<20} | {source_mac}")
    print(f"  {'EtherType:':<25} {ether_type:<20} | {int(ether_type, 16)}")

    payload = hex_data[28:]

    # Route payload based on EtherType
    if ether_type == "0806":  # ARP
        parse_arp_header(payload)
    else:
        print(f"  {'Unknown EtherType:':<25} {ether_type:<20} | {int(ether_type, 16)}")
        print("  No parser available for this EtherType.")

    return ether_type, payload


# Parse ARP header
def parse_arp_header(hex_data):
    hardware_type = int(hex_data[:4], 16)

    print(f"ARP Header:")
    print(f"  {'Hardware Type:':<25} {hex_data[:4]:<20} | {hardware_type}")


# IPv4 Header Parsing
def parse_ipv4_header(hex_data):
    version_ihl = hex_data[28:30]
    version = version_ihl[0]
    ihl = version_ihl[1]
    total_length = hex_data[32:36]
    protocol = hex_data[46:48]

    print(f"IPv4 Header:")
    print(f"  Version: {version}")
    print(f"  IHL: {ihl}")
    print(f"  Total Length: {total_length}")
    print(f"  Protocol: {protocol}")

    if protocol == '06':  # TCP
        parse_tcp_header(hex_data)
    elif protocol == '11':  # UDP
        parse_udp_header(hex_data)

# TCP Header Parsing
def parse_tcp_header(hex_data):
    src_port = hex_data[68:72]
    dest_port = hex_data[72:76]
    seq_num = hex_data[76:84]
    ack_num = hex_data[84:92]
    offset_reserved_flags = hex_data[92:96]
    flags = offset_reserved_flags[3:]  # Last byte contains the flags
    flags_binary = bin(int(flags, 16))[2:].zfill(8)  # Convert flags to binary

    print(f"TCP Header:")
    print(f"  Source Port: {int(src_port, 16)}")
    print(f"  Destination Port: {int(dest_port, 16)}")
    print(f"  Sequence Number: {int(seq_num, 16)}")
    print(f"  Acknowledgment Number: {int(ack_num, 16)}")
    print(f"  Flags: {flags_binary} (Binary)")

# UDP Header Parsing
def parse_udp_header(hex_data):
    src_port = hex_data[68:72]
    dest_port = hex_data[72:76]

    print(f"UDP Header:")
    print(f"  Source Port: {int(src_port, 16)}")
    print(f"  Destination Port: {int(dest_port, 16)}")