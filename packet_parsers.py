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


# Function to parse ARP header from hex data
def parse_arp_header(hex_data):
    """
    Parses an ARP header starting at offset 28 in hex_data.
    Prints raw hex on the left and interpreted values on the right.
    """

    # Extract ARP fields by hex offset
    hw_type    = hex_data[28:32]   # 2 bytes
    proto_type = hex_data[32:36]   # 2 bytes
    hw_size    = hex_data[36:38]   # 1 byte
    proto_size = hex_data[38:40]   # 1 byte
    opcode     = hex_data[40:44]   # 2 bytes

    sender_mac = hex_data[44:56]   # 6 bytes
    sender_ip  = hex_data[56:64]   # 4 bytes
    target_mac = hex_data[64:76]   # 6 bytes
    target_ip  = hex_data[76:84]   # 4 bytes

    # Convert raw hex MAC -> dash or colon separated
    # (Teacher’s example uses colons, so adjust as needed)
    sender_mac_readable = ':'.join(sender_mac[i:i+2] for i in range(0, 12, 2))
    target_mac_readable = ':'.join(target_mac[i:i+2] for i in range(0, 12, 2))

    # Convert raw hex IP -> dotted decimal
    sender_ip_readable = '.'.join(str(int(sender_ip[i:i+2], 16)) for i in range(0, 8, 2))
    target_ip_readable = '.'.join(str(int(target_ip[i:i+2], 16)) for i in range(0, 8, 2))

    print("ARP Header:")
    # Two-column style: hex on the left, decimal/meaning on the right
    print(f"  {'Hardware Type:':<20} {hw_type:<12} | {int(hw_type, 16)}")
    print(f"  {'Protocol Type:':<20} {proto_type:<12} | {int(proto_type, 16)}")
    print(f"  {'Hardware Size:':<20} {hw_size:<12} | {int(hw_size, 16)}")
    print(f"  {'Protocol Size:':<20} {proto_size:<12} | {int(proto_size, 16)}")
    print(f"  {'Opcode:':<20} {opcode:<12} | {int(opcode, 16)}")

    print(f"  {'Sender MAC:':<20} {sender_mac:<12} | {sender_mac_readable}")
    print(f"  {'Sender IP:':<20} {sender_ip:<12} | {sender_ip_readable}")
    print(f"  {'Target MAC:':<20} {target_mac:<12} | {target_mac_readable}")
    print(f"  {'Target IP:':<20} {target_ip:<12} | {target_ip_readable}")





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