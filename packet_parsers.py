############################################################
# packet_parsers.py
############################################################

def parse_ethernet_header(hex_data):
    """
    Parses the standard 14-byte (28 hex chars) Ethernet header from hex_data.

    - Destination MAC: bytes 0..5   (12 hex chars)
    - Source MAC:      bytes 6..11  (12 hex chars)
    - EtherType:       bytes 12..13 (4 hex chars)

    Also checks for VLAN tags (0x8100). If detected:
      - The next 4 bytes are the VLAN tag
      - Then the 'real' EtherType follows.

    Depending on the final EtherType:
      - 0x0806 => parse_arp_header
      - 0x0800 => parse_ipv4_header
      - else => unknown
    """

    # 1. Extract the 14 bytes (28 hex chars) for Ethernet
    dest_mac_hex = hex_data[0:12]   # 6 bytes => 12 hex
    src_mac_hex  = hex_data[12:24]  # 6 bytes => 12 hex
    ether_type   = hex_data[24:28]  # 2 bytes => 4 hex

    # Convert MACs to human-readable form
    dest_mac = ':'.join(dest_mac_hex[i:i+2] for i in range(0, 12, 2))
    src_mac  = ':'.join(src_mac_hex[i:i+2] for i in range(0, 12, 2))

    print("Ethernet Header:")
    print(f"  {'Destination MAC:':<25} {dest_mac_hex:<20} | {dest_mac}")
    print(f"  {'Source MAC:':<25} {src_mac_hex:<20}  | {src_mac}")
    print(f"  {'EtherType:':<25} {ether_type:<20}    | {int(ether_type, 16)}")

    # The payload after the Ethernet header
    payload = hex_data[28:]

    # 2. Check if EtherType == 0x8100 (VLAN)
    if ether_type.lower() == "8100":
        if len(hex_data) < 36:  # Must have at least 14 + 4 bytes
            print("Truncated VLAN header. Cannot parse further.")
            return ether_type, payload

        vlan_tag   = hex_data[28:36]    # 4 bytes => 8 hex chars
        real_etype = hex_data[36:40]    # next 2 bytes => 4 hex chars

        print(f"  VLAN Tag Detected:        {vlan_tag}")
        print(f"  Real EtherType:           {real_etype} | {int(real_etype, 16)}")

        # The ARP/IP header starts at offset 14 + 4 = 18 bytes => 36 hex chars
        if real_etype.lower() == "0806":
            parse_arp_header(hex_data, arp_offset=18)
        elif real_etype.lower() == "0800":
            parse_ipv4_header(hex_data, offset=18)
        else:
            print(f"  VLAN EtherType: {real_etype} not handled. No parser available.")

    # 3. If EtherType == 0x0806 => ARP (no VLAN)
    elif ether_type.lower() == "0806":
        parse_arp_header(hex_data, arp_offset=14)

    # 4. If EtherType == 0x0800 => IPv4 (no VLAN)
    elif ether_type.lower() == "0800":
        parse_ipv4_header(hex_data, offset=14)

    # 5. Otherwise, unknown
    else:
        print(f"  Unknown EtherType:        {ether_type}  | {int(ether_type,16)}")
        print("  No parser available for this EtherType.")

    return ether_type, payload


def parse_arp_header(hex_data, arp_offset=14):
    """
    Parses an ARP header starting at 'arp_offset' bytes in hex_data.
    By default, arp_offset=14 for a standard Ethernet frame (no VLAN).
    If VLAN is present, use arp_offset=18 (14 + 4).

    Prints raw hex on the left and interpreted values on the right.
    """
    min_arp_hex = (arp_offset + 28) * 2
    if len(hex_data) < min_arp_hex:
        print("Truncated ARP packet or unexpected format. Skipping parse.")
        return

    base = arp_offset * 2

    hw_type    = hex_data[base : base + 4]      # 2 bytes
    proto_type = hex_data[base + 4 : base + 8]  # 2 bytes
    hw_size    = hex_data[base + 8 : base + 10] # 1 byte
    proto_size = hex_data[base +10 : base + 12] # 1 byte
    opcode     = hex_data[base +12 : base + 16] # 2 bytes

    sender_mac = hex_data[base +16 : base + 28] # 6 bytes
    sender_ip  = hex_data[base +28 : base + 36] # 4 bytes
    target_mac = hex_data[base +36 : base + 48] # 6 bytes
    target_ip  = hex_data[base +48 : base + 56] # 4 bytes

    sender_mac_readable = ':'.join(sender_mac[i:i+2] for i in range(0, 12, 2))
    target_mac_readable = ':'.join(target_mac[i:i+2] for i in range(0, 12, 2))

    try:
        sender_ip_readable = '.'.join(str(int(sender_ip[i:i+2], 16)) for i in range(0, 8, 2))
        target_ip_readable = '.'.join(str(int(target_ip[i:i+2], 16)) for i in range(0, 8, 2))
    except ValueError:
        print("Invalid IP fields in ARP (possibly truncated or VLAN-tagged).")
        return

    print("ARP Header:")
    print(f"  {'Hardware Type:':<20} {hw_type:<12} | {int(hw_type, 16)}")
    print(f"  {'Protocol Type:':<20} {proto_type:<12} | {int(proto_type, 16)}")
    print(f"  {'Hardware Size:':<20} {hw_size:<12} | {int(hw_size, 16)}")
    print(f"  {'Protocol Size:':<20} {proto_size:<12} | {int(proto_size, 16)}")
    print(f"  {'Opcode:':<20}       {opcode:<12}    | {int(opcode, 16)}")

    print(f"  {'Sender MAC:':<20}   {sender_mac:<12} | {sender_mac_readable}")
    print(f"  {'Sender IP:':<20}    {sender_ip:<12}  | {sender_ip_readable}")
    print(f"  {'Target MAC:':<20}   {target_mac:<12} | {target_mac_readable}")
    print(f"  {'Target IP:':<20}    {target_ip:<12}  | {target_ip_readable}")


def parse_ipv4_header(hex_data, offset=14):
    """
    Parse an IPv4 header starting at 'offset' bytes into hex_data.
    Then, if Protocol = 6 (TCP) or 17 (UDP), call the appropriate parser.
    """
    base = offset * 2
    if len(hex_data) < base + 40:  # at least 20 bytes for minimal IP
        print("Truncated IP packet or unexpected format. Skipping parse.")
        return

    # First byte => version(4 bits) + IHL(4 bits)
    version_ihl_hex = hex_data[base : base + 2]
    version_ihl     = int(version_ihl_hex, 16)
    version         = (version_ihl >> 4) & 0xF
    ihl             = version_ihl & 0xF
    ip_header_length_bytes = ihl * 4  # e.g., if IHL=5 => 20 bytes

    # protocol is byte [9] => offset+9 => in hex => base + (9*2) => base+18..base+20
    protocol_hex = hex_data[base + 18 : base + 20]
    protocol     = int(protocol_hex, 16)

    print("IPv4 Header:")
    print(f"  Version:         {version}")
    print(f"  IHL:             {ihl} ({ip_header_length_bytes} bytes)")
    print(f"  Protocol:        {protocol}  (1=ICMP, 6=TCP, 17=UDP)")

    next_header_offset = offset + ip_header_length_bytes
    if protocol == 17:  # UDP
        parse_udp_header(hex_data, offset=next_header_offset)
    elif protocol == 6: # TCP
        parse_tcp_header(hex_data, offset=next_header_offset)
    else:
        print("IP protocol not supported in this example.")


def parse_tcp_header(hex_data, offset=34):
    """
    Minimal TCP parser: 14 (Ethernet) + 20 (IP) = 34 default,
    but real offset can vary if IP has options or VLAN is present.
    """
    base = offset * 2

    # Check we have at least 20 bytes of TCP
    if len(hex_data) < base + 40:
        print("Truncated TCP header, skipping parse.")
        return

    src_port_hex  = hex_data[base : base + 4]
    dest_port_hex = hex_data[base + 4 : base + 8]
    seq_num_hex   = hex_data[base + 8 : base + 16]
    ack_num_hex   = hex_data[base +16 : base + 24]
    offset_flags  = hex_data[base +24 : base + 28]  # data offset, flags
    window_hex    = hex_data[base +28 : base + 32]
    csum_hex      = hex_data[base +32 : base + 36]
    urg_ptr_hex   = hex_data[base +36 : base + 40]

    src_port_dec  = int(src_port_hex, 16)
    dest_port_dec = int(dest_port_hex, 16)
    seq_num_dec   = int(seq_num_hex, 16)
    ack_num_dec   = int(ack_num_hex, 16)

    # data_offset is top 4 bits of offset_flags => offset_flags >> 12
    offset_int    = int(offset_flags, 16)
    data_offset   = (offset_int >> 12) & 0xF
    flags_9       = offset_int & 0x1FF  # or 0x3F if you only consider 6 bits
    flags_binary  = bin(flags_9)[2:].zfill(9)

    window_dec    = int(window_hex, 16)
    csum_dec      = int(csum_hex, 16)
    urg_ptr_dec   = int(urg_ptr_hex, 16)

    print("TCP Header:")
    print(f"  {'Source Port:':<20} {src_port_hex:<6} | {src_port_dec}")
    print(f"  {'Destination Port:':<20} {dest_port_hex:<6} | {dest_port_dec}")
    print(f"  {'Sequence Number:':<20} {seq_num_hex:<8} | {seq_num_dec}")
    print(f"  {'Acknowledgment:':<20} {ack_num_hex:<8} | {ack_num_dec}")
    print(f"  {'Data Offset:':<20}          | {data_offset}")
    print(f"  {'Flags (binary):':<20} {offset_flags:<4} | {flags_binary}")
    print(f"  {'Window:':<20} {window_hex:<6} | {window_dec}")
    print(f"  {'Checksum:':<20} {csum_hex:<6} | {csum_dec}")
    print(f"  {'Urgent Ptr:':<20} {urg_ptr_hex:<6} | {urg_ptr_dec}")


def parse_udp_header(hex_data, offset):
    """
    Parse a UDP header at 'offset' bytes in `hex_data`.
    8 bytes for the UDP header => 16 hex chars.
    Then show leftover payload.
    """
    base = offset * 2
    if len(hex_data) < base + 16:
        print("Truncated UDP header, skipping parse.")
        return

    src_port_hex  = hex_data[base : base+4]
    dest_port_hex = hex_data[base+4 : base+8]
    length_hex    = hex_data[base+8 : base+12]
    csum_hex      = hex_data[base+12: base+16]

    src_port_dec  = int(src_port_hex, 16)
    dest_port_dec = int(dest_port_hex, 16)
    length_dec    = int(length_hex, 16)
    checksum_dec  = int(csum_hex, 16)

    print("UDP Header:")
    print(f"  {'Source Port:':<20} {src_port_hex:<6} | {src_port_dec}")
    print(f"  {'Destination Port:':<20} {dest_port_hex:<6} | {dest_port_dec}")
    print(f"  {'Length:':<20} {length_hex:<6}  | {length_dec}")
    print(f"  {'Checksum:':<20} {csum_hex:<6}  | {checksum_dec}")

    # Optional: Dump leftover payload
    payload_start = base + 16
    if len(hex_data) > payload_start:
        udp_payload_hex = hex_data[payload_start:]
        print(f"  {'Payload (hex):':<20} {udp_payload_hex}")
