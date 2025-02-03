############################################################
# packet_parsers.py
# Fully aligned, neat formatting for Ethernet, ARP, IPv4, TCP, UDP
############################################################

def parse_ethernet_header(hex_data):
    """
    Parses the standard 14-byte (28 hex chars) Ethernet header.
    Checks VLAN (0x8100), ARP (0x0806), or IPv4 (0x0800).
    """
    # -- Extract fields --
    dest_mac_hex = hex_data[0:12]   # 6 bytes => 12 hex
    src_mac_hex  = hex_data[12:24]  # 6 bytes => 12 hex
    ether_type   = hex_data[24:28]  # 2 bytes => 4 hex

    # -- Convert to readable strings --
    dest_mac = ':'.join(dest_mac_hex[i:i+2] for i in range(0, 12, 2))
    src_mac  = ':'.join(src_mac_hex[i:i+2] for i in range(0, 12, 2))
    ether_type_dec = int(ether_type, 16)

    print("Ethernet Header:")
    print(f"  {'Destination MAC:':<22} {dest_mac_hex:<12} | {dest_mac}")
    print(f"  {'Source MAC:':<22} {src_mac_hex:<12} | {src_mac}")
    print(f"  {'EtherType:':<22} {ether_type:<12} | {ether_type_dec}")

    # -- Payload after Ethernet --
    payload = hex_data[28:]

    # -- Check EtherType --
    if ether_type.lower() == "8100":
        # VLAN
        if len(hex_data) < 36:
            print("Truncated VLAN header. Cannot parse further.")
            return ether_type, payload

        vlan_tag   = hex_data[28:36]   # 4 bytes => 8 hex
        real_etype = hex_data[36:40]   # next 2 bytes => 4 hex
        real_dec   = int(real_etype, 16)

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
    ARP header = 28 bytes => 56 hex.
    Prints columns: field label, raw hex, interpreted value.
    """
    min_len = (arp_offset + 28) * 2
    if len(hex_data) < min_len:
        print("Truncated ARP or unexpected format. Skipping.")
        return

    base = arp_offset * 2

    hw_type    = hex_data[base     : base + 4]    # 2 bytes
    proto_type = hex_data[base + 4 : base + 8]    # 2 bytes
    hw_size    = hex_data[base + 8 : base + 10]   # 1 byte
    proto_size = hex_data[base +10 : base + 12]   # 1 byte
    opcode     = hex_data[base +12 : base + 16]   # 2 bytes

    sender_mac = hex_data[base +16 : base + 28]   # 6 bytes
    sender_ip  = hex_data[base +28 : base + 36]   # 4 bytes
    target_mac = hex_data[base +36 : base + 48]   # 6 bytes
    target_ip  = hex_data[base +48 : base + 56]   # 4 bytes

    # Convert
    hw_type_dec    = int(hw_type, 16)
    proto_type_dec = int(proto_type, 16)
    hw_size_dec    = int(hw_size, 16)
    proto_size_dec = int(proto_size, 16)
    opcode_dec     = int(opcode, 16)

    sender_mac_read = ':'.join(sender_mac[i:i+2] for i in range(0, 12, 2))
    target_mac_read = ':'.join(target_mac[i:i+2] for i in range(0, 12, 2))

    try:
        sender_ip_read = '.'.join(str(int(sender_ip[i:i+2], 16)) for i in range(0, 8, 2))
        target_ip_read = '.'.join(str(int(target_ip[i:i+2], 16)) for i in range(0, 8, 2))
    except ValueError:
        print("Invalid ARP IP fields.")
        return

    print("ARP Header:")
    print(f"  {'Hardware Type:':<22} {hw_type:<12} | {hw_type_dec}")
    print(f"  {'Protocol Type:':<22} {proto_type:<12} | {proto_type_dec}")
    print(f"  {'Hardware Size:':<22} {hw_size:<12} | {hw_size_dec}")
    print(f"  {'Protocol Size:':<22} {proto_size:<12} | {proto_size_dec}")
    print(f"  {'Opcode:':<22} {opcode:<12} | {opcode_dec}")

    print(f"  {'Sender MAC:':<22} {sender_mac:<12} | {sender_mac_read}")
    print(f"  {'Sender IP:':<22} {sender_ip:<12} | {sender_ip_read}")
    print(f"  {'Target MAC:':<22} {target_mac:<12} | {target_mac_read}")
    print(f"  {'Target IP:':<22} {target_ip:<12} | {target_ip_read}")


def parse_ipv4_header(hex_data, offset=14):
    """
    IPv4 header is min 20 bytes => 40 hex. Parse all standard fields including
    total length, flags, fragment offset, and IPs.
    """
    base = offset * 2
    if len(hex_data) < base + 40:
        print("Truncated IP or unexpected format. Skipping.")
        return

    # Extract all IPv4 fields
    version_ihl_hex = hex_data[base : base + 2]
    total_len_hex = hex_data[base + 4 : base + 8]
    flags_frag_hex = hex_data[base + 12 : base + 16]
    proto_hex = hex_data[base + 18 : base + 20]
    src_ip_hex = hex_data[base + 24 : base + 32]
    dst_ip_hex = hex_data[base + 32 : base + 40]

    # Parse version and IHL
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
    src_ip = '.'.join(str(int(src_ip_hex[i:i+2], 16)) for i in range(0, 8, 2))
    dst_ip = '.'.join(str(int(dst_ip_hex[i:i+2], 16)) for i in range(0, 8, 2))

    print("IPv4 Header:")
    print(f"    Version:                4         | {version}")
    print(f"    Header Length:          5         | {ip_len_bytes} bytes")
    print(f"    Total Length:           {total_len_hex}      | {total_len_dec}")
    print(f"    Flags & Frag Offset:    {flags_frag_hex}      | {hex(flags_frag)[2:].zfill(4)}")
    print(f"        Reserved:           {reserved}")
    print(f"        DF (Do not Fragment): {df_flag}")
    print(f"        MF (More Fragments): {mf_flag}")
    print(f"        Fragment Offset:    0x{frag_offset:x} | {frag_offset}")
    print(f"    Protocol:               11        | {proto_dec}")
    print(f"    Source IP:              {src_ip_hex}    | {src_ip}")
    print(f"    Destination IP:         {dst_ip_hex}    | {dst_ip}")

    # Continue with next protocol parser if recognized
    next_off = offset + ip_len_bytes
    if proto_dec == 17:
        parse_udp_header(hex_data, offset=next_off)
    elif proto_dec == 6:
        parse_tcp_header(hex_data, offset=next_off)
    else:
        print("    IP protocol not supported in this example.")


def parse_tcp_header(hex_data, offset=34):
    """
    Minimal TCP parse. Typically offset=14+IPheader, but can vary with VLAN or IP options.
    We'll print ports, seq, ack, offset, flags, etc.
    """
    base = offset * 2
    if len(hex_data) < base + 40:
        print("Truncated TCP header. Skipping.")
        return

    src_port_hex  = hex_data[base : base+4]
    dst_port_hex  = hex_data[base+4 : base+8]
    seq_hex       = hex_data[base+8 : base+16]
    ack_hex       = hex_data[base+16: base+24]
    offs_flags    = hex_data[base+24: base+28]
    win_hex       = hex_data[base+28: base+32]
    csum_hex      = hex_data[base+32: base+36]
    urgp_hex      = hex_data[base+36: base+40]

    # Convert
    sp_dec  = int(src_port_hex, 16)
    dp_dec  = int(dst_port_hex, 16)
    seq_dec = int(seq_hex, 16)
    ack_dec = int(ack_hex, 16)

    of_int      = int(offs_flags, 16)
    data_offset = (of_int >> 12) & 0xF
    flags_9     = of_int & 0x1FF
    flags_bin   = bin(flags_9)[2:].zfill(9)

    win_dec     = int(win_hex, 16)
    csum_dec    = int(csum_hex, 16)
    urgp_dec    = int(urgp_hex, 16)

    print("TCP Header:")
    print(f"  {'Source Port:':<22} {src_port_hex:<6} | {sp_dec}")
    print(f"  {'Destination Port:':<22} {dst_port_hex:<6} | {dp_dec}")
    print(f"  {'Sequence Number:':<22} {seq_hex:<8} | {seq_dec}")
    print(f"  {'Acknowledgment:':<22} {ack_hex:<8} | {ack_dec}")
    print(f"  {'Data Offset:':<22} {offs_flags:<4} | {data_offset}")
    print(f"  {'Flags (binary):':<22}        | {flags_bin}")
    print(f"  {'Window:':<22} {win_hex:<6} | {win_dec}")
    print(f"  {'Checksum:':<22} {csum_hex:<6} | {csum_dec}")
    print(f"  {'Urgent Ptr:':<22} {urgp_hex:<6} | {urgp_dec}")


def parse_udp_header(hex_data, offset):
    """
    Parse the UDP header (8 bytes -> 16 hex chars) starting at `offset` bytes in hex_data.
    """
    base = offset * 2
    if len(hex_data) < base + 16:
        print("Truncated UDP header. Skipping.")
        return

    # Extract the 4 fields (2 bytes each)
    src_port_hex = hex_data[base : base + 4]
    dst_port_hex = hex_data[base + 4 : base + 8]
    length_hex   = hex_data[base + 8 : base + 12]
    csum_hex     = hex_data[base + 12 : base + 16]

    # Convert hex -> decimal
    src_port_dec = int(src_port_hex, 16)
    dst_port_dec = int(dst_port_hex, 16)
    length_dec   = int(length_hex, 16)
    csum_dec     = int(csum_hex, 16)

    print("UDP Header:")
    print(f"    Source Port:            {src_port_hex.lower()}      | {src_port_dec}")
    print(f"    Destination Port:       {dst_port_hex.lower()}      | {dst_port_dec}")
    print(f"    Length:                 {length_hex.lower()}      | {length_dec}")
    print(f"    Checksum:               {csum_hex.lower()}      | {csum_dec}")

    # Remainder of packet is UDP payload
    payload_start = base + 16
    if len(hex_data) > payload_start:
        udp_payload_hex = hex_data[payload_start:]
        print(f"    Payload (hex):          {udp_payload_hex.lower()}")
