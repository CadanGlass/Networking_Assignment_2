############################################################
# packet_parsers.py
############################################################

def parse_ethernet_header(hex_data):
    """
    Parses an Ethernet frame header and identifies the encapsulated protocol.
    Handles standard Ethernet II frames, VLAN tagged frames, and common protocols like ARP and IPv4.
    """
    # Split the header into its components
    dest_mac_hex = hex_data[0:12]
    src_mac_hex = hex_data[12:24]
    ether_type = hex_data[24:28]

    # Format MAC addresses into human readable format (e.g., AA:BB:CC:DD:EE:FF)
    dest_mac = ':'.join(dest_mac_hex[i:i + 2] for i in range(0, 12, 2))
    src_mac = ':'.join(src_mac_hex[i:i + 2] for i in range(0, 12, 2))
    ether_type_dec = int(ether_type, 16)

    print("Ethernet Header:")
    print(f"  {'Destination MAC:':<22} {dest_mac_hex:<12}   | {dest_mac}")
    print(f"  {'Source MAC:':<22} {src_mac_hex:<12}   | {src_mac}")
    print(f"  {'EtherType:':<22} {ether_type:<12}   | {ether_type_dec}")

    # -- Payload after Ethernet --
    payload = hex_data[28:]

    # -- Check EtherType --
    if ether_type.lower() == "8100":
        # VLAN
        if len(hex_data) < 36:
            print("Truncated VLAN header. Cannot parse further.")
            return ether_type, payload

        vlan_tag = hex_data[28:36]  # 4 bytes => 8 hex
        real_etype = hex_data[36:40]  # next 2 bytes => 4 hex
        real_dec = int(real_etype, 16)

        print(f"  VLAN Tag Detected:       {vlan_tag}")
        print(f"  Real EtherType:          {real_etype:<12} | {real_dec}")

        # Next protocol offset => 14 + 4 = 18 bytes
        if real_etype.lower() == "0806":
            parse_arp_header(hex_data, arp_offset=18)
        elif real_etype.lower() == "0800":
            parse_ipv4_header(hex_data, offset=18)
        else:
            print(f"  VLAN EtherType {real_etype} not handled.")

    elif ether_type.lower() == "0806":
        # ARP
        parse_arp_header(hex_data, arp_offset=14)

    elif ether_type.lower() == "0800":
        # IPv4
        parse_ipv4_header(hex_data, offset=14)

    else:
        print(f"  Unknown EtherType:       {ether_type:<12} | {ether_type_dec}")
        print("  No parser available.")

    return ether_type, payload


def parse_arp_header(hex_data, arp_offset=14):
    """
    Parses Address Resolution Protocol (ARP) packets used to map IP addresses to MAC addresses.
    arp_offset: where ARP header starts (14 bytes after start for normal Ethernet, 18 for VLAN)
    """
    # Make sure we have enough data for a complete ARP header
    min_len = (arp_offset + 28) * 2
    if len(hex_data) < min_len:
        print("Truncated ARP or unexpected format. Skipping.")
        return

    base = arp_offset * 2

    hw_type = hex_data[base: base + 4]  # 2 bytes
    proto_type = hex_data[base + 4: base + 8]  # 2 bytes
    hw_size = hex_data[base + 8: base + 10]  # 1 byte
    proto_size = hex_data[base + 10: base + 12]  # 1 byte
    opcode = hex_data[base + 12: base + 16]  # 2 bytes

    sender_mac = hex_data[base + 16: base + 28]  # 6 bytes
    sender_ip = hex_data[base + 28: base + 36]  # 4 bytes
    target_mac = hex_data[base + 36: base + 48]  # 6 bytes
    target_ip = hex_data[base + 48: base + 56]  # 4 bytes

    # Convert
    hw_type_dec = int(hw_type, 16)
    proto_type_dec = int(proto_type, 16)
    hw_size_dec = int(hw_size, 16)
    proto_size_dec = int(proto_size, 16)
    opcode_dec = int(opcode, 16)

    sender_mac_read = ':'.join(sender_mac[i:i + 2] for i in range(0, 12, 2))
    target_mac_read = ':'.join(target_mac[i:i + 2] for i in range(0, 12, 2))

    try:
        sender_ip_read = '.'.join(str(int(sender_ip[i:i + 2], 16)) for i in range(0, 8, 2))
        target_ip_read = '.'.join(str(int(target_ip[i:i + 2], 16)) for i in range(0, 8, 2))
    except ValueError:
        print("Invalid ARP IP fields.")
        return

    print("ARP Header:")
    print(f"  {'Hardware Type:':<22} {hw_type:<12}   | {hw_type_dec}")
    print(f"  {'Protocol Type:':<22} {proto_type:<12}   | {proto_type_dec}")
    print(f"  {'Hardware Size:':<22} {hw_size:<12}   | {hw_size_dec}")
    print(f"  {'Protocol Size:':<22} {proto_size:<12}   | {proto_size_dec}")
    print(f"  {'Opcode:':<22} {opcode:<12}   | {opcode_dec}")

    print(f"  {'Sender MAC:':<22} {sender_mac:<12}   | {sender_mac_read}")
    print(f"  {'Sender IP:':<22} {sender_ip:<12}   | {sender_ip_read}")
    print(f"  {'Target MAC:':<22} {target_mac:<12}   | {target_mac_read}")
    print(f"  {'Target IP:':<22} {target_ip:<12}   | {target_ip_read}")


def parse_ipv4_header(hex_data, offset=14):
    """
    Parses IPv4 headers and identifies the higher layer protocol (TCP, UDP, ICMP).
    offset: where IP header starts (14 bytes after start for normal Ethernet, 18 for VLAN)
    """
    base = offset * 2
    if len(hex_data) < base + 40:
        print("Truncated IP or unexpected format. Skipping.")
        return

    # Pull out the header fields we care about
    version_ihl_hex = hex_data[base: base + 2]
    total_len_hex = hex_data[base + 4: base + 8]
    flags_frag_hex = hex_data[base + 12: base + 16]
    proto_hex = hex_data[base + 18: base + 20]
    src_ip_hex = hex_data[base + 24: base + 32]
    dst_ip_hex = hex_data[base + 32: base + 40]

    # First byte contains both version (upper 4 bits) and header length (lower 4 bits)
    vi = int(version_ihl_hex, 16)
    version = (vi >> 4) & 0xF
    ihl = vi & 0xF
    ip_len_bytes = ihl * 4

    # Convert other fields
    total_len_dec = int(total_len_hex, 16)
    flags_frag = int(flags_frag_hex, 16)
    reserved = (flags_frag >> 15) & 0x1
    df_flag = (flags_frag >> 14) & 0x1
    mf_flag = (flags_frag >> 13) & 0x1
    frag_offset = flags_frag & 0x1FFF
    proto_dec = int(proto_hex, 16)

    # Convert IPs to dotted decimal
    src_ip = '.'.join(str(int(src_ip_hex[i:i + 2], 16)) for i in range(0, 8, 2))
    dst_ip = '.'.join(str(int(dst_ip_hex[i:i + 2], 16)) for i in range(0, 8, 2))

    print("IPv4 Header:")
    print(f"    Version:                4           | {version}")
    print(f"    Header Length:          5           | {ip_len_bytes} bytes")
    print(f"    Total Length:           {total_len_hex}        | {total_len_dec}")
    print(f"    Flags & Frag Offset:    {flags_frag_hex}        | {hex(flags_frag)[2:].zfill(4)}")
    print(f"        Reserved:           {reserved}")
    print(f"        DF (Do not Fragment): {df_flag}")
    print(f"        MF (More Fragments): {mf_flag}")
    print(f"        Fragment Offset:    0x{frag_offset:x} | {frag_offset}")
    print(f"    Protocol:               11          | {proto_dec}")
    print(f"    Source IP:              {src_ip_hex}    | {src_ip}")
    print(f"    Destination IP:         {dst_ip_hex}    | {dst_ip}")

    # Continue with next protocol parser if recognized
    next_off = offset + ip_len_bytes
    if proto_dec == 17:
        parse_udp_header(hex_data, offset=next_off)
    elif proto_dec == 6:
        parse_tcp_header(hex_data, offset=next_off)
    elif proto_dec == 1:  # Add this case for ICMP
        parse_icmp_header(hex_data, offset=next_off)
    else:
        print("    IP protocol not supported in this example.")


def parse_tcp_header(hex_data, offset=34):
    """
    Parses TCP headers, extracting ports, sequence numbers, flags and options.
    Shows the state of the TCP connection through various control flags.
    """
    base = offset * 2
    if len(hex_data) < base + 40:
        print("Truncated TCP header. Skipping.")
        return

    # Extract the main TCP header fields
    src_port_hex = hex_data[base: base + 4]
    dst_port_hex = hex_data[base + 4: base + 8]
    seq_hex = hex_data[base + 8: base + 16]
    ack_hex = hex_data[base + 16: base + 24]
    offset_flags_hex = hex_data[base + 24: base + 28]
    window_hex = hex_data[base + 28: base + 32]
    checksum_hex = hex_data[base + 32: base + 36]
    urgent_ptr_hex = hex_data[base + 36: base + 40]

    # Convert all values
    src_port = int(src_port_hex, 16)
    dst_port = int(dst_port_hex, 16)
    seq_num = int(seq_hex, 16)
    ack_num = int(ack_hex, 16)
    window = int(window_hex, 16)
    checksum = int(checksum_hex, 16)
    urgent_ptr = int(urgent_ptr_hex, 16)

    offset_flags = int(offset_flags_hex, 16)
    data_offset = (offset_flags >> 12) & 0xF
    data_offset_bytes = data_offset * 4

    flags = offset_flags & 0x1FF
    ns = (flags >> 8) & 0x1
    cwr = (flags >> 7) & 0x1
    ece = (flags >> 6) & 0x1
    urg = (flags >> 5) & 0x1
    ack = (flags >> 4) & 0x1
    psh = (flags >> 3) & 0x1
    rst = (flags >> 2) & 0x1
    syn = (flags >> 1) & 0x1
    fin = flags & 0x1

    print("TCP Header:")
    print(f"    {'Source Port:':<22} {src_port_hex.lower():<12} | {src_port}")
    print(f"    {'Destination Port:':<22} {dst_port_hex.lower():<12} | {dst_port}")
    print(f"    {'Sequence Number:':<22} {seq_hex.lower():<12} | {seq_num}")
    print(f"    {'Acknowledgment Number:':<22} {ack_hex.lower():<12} | {ack_num}")
    print(f"    {'Data Offset:':<22} {data_offset:<12} | {data_offset_bytes} bytes")
    print(f"    {'Reserved:':<22} {'0b0':<12} | 0")
    print(f"    {'Flags:':<22} {'0b' + bin(flags)[2:].zfill(9):<12} | {flags}")
    print(f"    {'    NS:':<22} {ns:<12} | {ns}")
    print(f"    {'    CWR:':<22} {cwr:<12} | {cwr}")
    print(f"    {'    ECE:':<22} {ece:<12} | {ece}")
    print(f"    {'    URG:':<22} {urg:<12} | {urg}")
    print(f"    {'    ACK:':<22} {ack:<12} | {ack}")
    print(f"    {'    PSH:':<22} {psh:<12} | {psh}")
    print(f"    {'    RST:':<22} {rst:<12} | {rst}")
    print(f"    {'    SYN:':<22} {syn:<12} | {syn}")
    print(f"    {'    FIN:':<22} {fin:<12} | {fin}")
    print(f"    {'Window Size:':<22} {window_hex.lower():<12} | {window}")
    print(f"    {'Checksum:':<22} {checksum_hex.lower():<12} | {checksum}")
    print(f"    {'Urgent Pointer:':<22} {urgent_ptr_hex.lower():<12} | {urgent_ptr}")

    payload_start = base + (data_offset * 8)
    if len(hex_data) > payload_start:
        payload = hex_data[payload_start:]
        print(f"    Payload (hex):          {payload.lower()}")

    # Check if this is DNS traffic (port 53)
    if src_port == 53 or dst_port == 53:
        # For TCP DNS, first 2 bytes indicate length
        dns_offset = offset + data_offset
        parse_dns_packet(hex_data, dns_offset)


def parse_udp_header(hex_data, offset):
    """
    Parses UDP headers - a simpler alternative to TCP for applications that don't need
    guaranteed delivery or connection state.
    """
    base = offset * 2
    if len(hex_data) < base + 16:
        print("Truncated UDP header. Skipping.")
        return

    # UDP has a simple 8-byte header with just ports, length, and checksum
    src_port_hex = hex_data[base: base + 4]
    dst_port_hex = hex_data[base + 4: base + 8]
    length_hex = hex_data[base + 8: base + 12]
    csum_hex = hex_data[base + 12: base + 16]

    # Convert hex -> decimal
    src_port_dec = int(src_port_hex, 16)
    dst_port_dec = int(dst_port_hex, 16)
    length_dec = int(length_hex, 16)
    csum_dec = int(csum_hex, 16)

    print("UDP Header:")
    print(f"    Source Port:            {src_port_hex.lower()}        | {src_port_dec}")
    print(f"    Destination Port:       {dst_port_hex.lower()}        | {dst_port_dec}")
    print(f"    Length:                 {length_hex.lower()}        | {length_dec}")
    print(f"    Checksum:               {csum_hex.lower()}        | {csum_dec}")

    # Check if this is DNS traffic (port 53)
    if src_port_dec == 53 or dst_port_dec == 53:
        # DNS starts immediately after UDP header
        parse_dns_packet(hex_data, offset + 8)

    # Remainder of packet is UDP payload
    payload_start = base + 16
    if len(hex_data) > payload_start:
        udp_payload_hex = hex_data[payload_start:]
        print(f"    Payload (hex):          {udp_payload_hex.lower()}")


def parse_icmp_header(hex_data, offset=34):
    """
    Parses ICMP messages used for network diagnostics and error reporting.
    Common types include echo request/reply (ping), destination unreachable, etc.
    """
    base = offset * 2
    if len(hex_data) < base + 16:
        print("Truncated ICMP header. Skipping.")
        return

    # ICMP header starts with type and code that indicate the message purpose
    type_hex = hex_data[base: base + 2]
    code_hex = hex_data[base + 2: base + 4]
    checksum_hex = hex_data[base + 4: base + 8]

    # Convert to decimal
    type_dec = int(type_hex, 16)
    code_dec = int(code_hex, 16)
    checksum_dec = int(checksum_hex, 16)

    # Get payload (rest of packet)
    payload = hex_data[base + 8:]

    print("ICMP Header:")
    print(f"    {'Type:':<22} {type_hex:<12} | {type_dec}")
    print(f"    {'Code:':<22} {code_hex:<12} | {code_dec}")
    print(f"    {'Checksum:':<22} {checksum_hex:<12} | {checksum_dec}")
    print(f"    {'Payload (hex):':<22} {payload.lower()}")


def parse_dns_packet(hex_data, offset):
    """
    Parses DNS packets, supporting both queries and responses.
    DNS packets can be carried over either UDP or TCP on port 53.
    """
    base = offset * 2
    if len(hex_data) < base + 24:  # Minimum DNS header size is 12 bytes
        print("Truncated DNS packet. Skipping.")
        return

    # Extract DNS header fields
    transaction_id = hex_data[base:base + 4]
    flags = int(hex_data[base + 4:base + 8], 16)
    questions = int(hex_data[base + 8:base + 12], 16)
    answers = int(hex_data[base + 12:base + 16], 16)
    authority = int(hex_data[base + 16:base + 20], 16)
    additional = int(hex_data[base + 20:base + 24], 16)

    # Parse DNS flags
    qr = (flags >> 15) & 0x1  # Query (0) or Response (1)
    opcode = (flags >> 11) & 0xF  # Operation code
    aa = (flags >> 10) & 0x1  # Authoritative Answer
    tc = (flags >> 9) & 0x1  # Truncation
    rd = (flags >> 8) & 0x1  # Recursion Desired
    ra = (flags >> 7) & 0x1  # Recursion Available
    z = (flags >> 4) & 0x7  # Reserved
    rcode = flags & 0xF  # Response code

    print("DNS Header:")
    print(f"    Transaction ID:         {transaction_id}        | {int(transaction_id, 16)}")
    print(f"    Flags:                  {hex(flags)[2:].zfill(4)}")
    print(f"        QR:                 {qr}           | {'Response' if qr else 'Query'}")
    print(f"        Opcode:             {opcode}")
    print(f"        AA:                 {aa}")
    print(f"        TC:                 {tc}")
    print(f"        RD:                 {rd}")
    print(f"        RA:                 {ra}")
    print(f"        Z:                  {z}")
    print(f"        RCODE:              {rcode}")
    print(f"    Questions:              {questions}")
    print(f"    Answer RRs:             {answers}")
    print(f"    Authority RRs:          {authority}")
    print(f"    Additional RRs:         {additional}")