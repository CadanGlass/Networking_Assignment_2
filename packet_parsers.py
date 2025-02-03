############################################################
# packet_parsers.py
# Fully expanded to match the teacher's style with aligned columns
# for Ethernet, ARP, IPv4 (detailed), TCP, and UDP.
############################################################

def parse_ethernet_header(hex_data):
    """
    Parses the standard 14-byte (28 hex) Ethernet header.
    Supports VLAN (0x8100), ARP (0x0806), IPv4 (0x0800).
    """
    dest_mac_hex = hex_data[0:12]
    src_mac_hex  = hex_data[12:24]
    ether_type   = hex_data[24:28]

    dest_mac      = ':'.join(dest_mac_hex[i:i+2] for i in range(0,12,2))
    src_mac       = ':'.join(src_mac_hex[i:i+2] for i in range(0,12,2))
    ether_type_dec= int(ether_type,16)

    print("Ethernet Header:")
    print(f"  Destination MAC:  {dest_mac_hex:<12} | {dest_mac}")
    print(f"  Source MAC:       {src_mac_hex:<12} | {src_mac}")
    print(f"  EtherType:        {ether_type:<12} | {ether_type_dec}")

    # Payload beyond Ethernet
    payload = hex_data[28:]

    # Check EtherType
    et_lower = ether_type.lower()
    if et_lower == "8100":
        if len(hex_data) < 36:
            print("Truncated VLAN header. Cannot parse further.")
            return ether_type, payload

        vlan_tag   = hex_data[28:36]
        real_etype = hex_data[36:40]
        real_dec   = int(real_etype,16)
        print(f"  VLAN Tag Detected: {vlan_tag}")
        print(f"  Real EtherType:    {real_etype:<12} | {real_dec}")

        # VLAN offset => 14 + 4 = 18
        if real_etype.lower() == "0806":
            parse_arp_header(hex_data, arp_offset=18)
        elif real_etype.lower() == "0800":
            parse_ipv4_header(hex_data, offset=18)
        else:
            print(f"  VLAN EtherType {real_etype} not supported.")
    elif et_lower == "0806":
        parse_arp_header(hex_data, arp_offset=14)
    elif et_lower == "0800":
        parse_ipv4_header(hex_data, offset=14)
    else:
        print(f"  Unknown EtherType: {ether_type:<12} | {ether_type_dec}")
        print("  No parser available.")

    return ether_type, payload


def parse_arp_header(hex_data, arp_offset=14):
    """
    ARP is 28 bytes => 56 hex. Print each field in two columns (hex vs. interpreted).
    """
    min_len = (arp_offset + 28) * 2
    if len(hex_data) < min_len:
        print("Truncated ARP packet. Skipping.")
        return

    base = arp_offset * 2

    hw_type    = hex_data[base : base+4]
    proto_type = hex_data[base+4 : base+8]
    hw_size    = hex_data[base+8 : base+10]
    proto_size = hex_data[base+10: base+12]
    opcode     = hex_data[base+12: base+16]

    sender_mac = hex_data[base+16: base+28]
    sender_ip  = hex_data[base+28: base+36]
    target_mac = hex_data[base+36: base+48]
    target_ip  = hex_data[base+48: base+56]

    # Convert to decimal
    hw_type_dec    = int(hw_type,16)
    proto_type_dec = int(proto_type,16)
    hw_size_dec    = int(hw_size,16)
    proto_size_dec = int(proto_size,16)
    opcode_dec     = int(opcode,16)

    # Readable MAC
    s_mac_read = ':'.join(sender_mac[i:i+2] for i in range(0,12,2))
    t_mac_read = ':'.join(target_mac[i:i+2] for i in range(0,12,2))

    # Readable IP
    try:
        s_ip_read = '.'.join(str(int(sender_ip[i:i+2],16)) for i in range(0,8,2))
        t_ip_read = '.'.join(str(int(target_ip[i:i+2],16)) for i in range(0,8,2))
    except ValueError:
        print("Invalid ARP IP fields.")
        return

    print("ARP Header:")
    print(f"  Hardware Type:    {hw_type:<8} | {hw_type_dec}")
    print(f"  Protocol Type:    {proto_type:<8} | {proto_type_dec}")
    print(f"  Hardware Size:    {hw_size:<8} | {hw_size_dec}")
    print(f"  Protocol Size:    {proto_size:<8} | {proto_size_dec}")
    print(f"  Opcode:           {opcode:<8} | {opcode_dec}")

    print(f"  Sender MAC:       {sender_mac:<12} | {s_mac_read}")
    print(f"  Sender IP:        {sender_ip:<8}  | {s_ip_read}")
    print(f"  Target MAC:       {target_mac:<12} | {t_mac_read}")
    print(f"  Target IP:        {target_ip:<8}  | {t_ip_read}")


def parse_ipv4_header(hex_data, offset=14):
    """
    IPv4 is min 20 bytes => 40 hex.
    We detail fields: version, IHL, total length, flags, frag offset, etc.
    Then pass to TCP/UDP if recognized.
    """
    base = offset * 2
    if len(hex_data) < base + 40:
        print("Truncated IP header. Skipping.")
        return

    # Byte 0 => version + IHL
    version_ihl = int(hex_data[base : base+2],16)
    version = (version_ihl >> 4) & 0xF
    ihl     =  version_ihl & 0xF
    ip_header_len = ihl * 4

    # Bytes [2..3] => total length
    tot_len_hex = hex_data[base+4 : base+8]  # bytes 2-3
    tot_len_dec = int(tot_len_hex,16)

    # Bytes [6..7] => flags + fragment offset
    flags_frag_hex = hex_data[base+12 : base+16]  # bytes 6-7
    flags_frag_dec = int(flags_frag_hex,16)

    # Let's break it down:
    # 3 bits for flags, 13 bits for offset
    reserved = (flags_frag_dec >> 15) & 0x1
    df       = (flags_frag_dec >> 14) & 0x1
    mf       = (flags_frag_dec >> 13) & 0x1
    frag_off = flags_frag_dec & 0x1FFF

    # Byte [9] => protocol
    proto_hex = hex_data[base + 18 : base + 20]
    proto_dec = int(proto_hex,16)

    # Bytes [12..15] => source IP
    s_ip_hex  = hex_data[base + 24 : base + 32]
    # Bytes [16..19] => destination IP
    d_ip_hex  = hex_data[base + 32 : base + 40]

    # Convert IP to dotted decimal
    s_ip_read = '.'.join(str(int(s_ip_hex[i:i+2],16)) for i in range(0,8,2))
    d_ip_read = '.'.join(str(int(d_ip_hex[i:i+2],16)) for i in range(0,8,2))

    print("IPv4 Header:")
    print(f"  Version:         {version}")
    print(f"  Header Length:   {ihl}  | {ip_header_len} bytes")
    print(f"  Total Length:    {tot_len_hex:<4} | {tot_len_dec}")
    print(f"  Flags & Frag Offset: {flags_frag_hex:<4} | 0b{flags_frag_dec:b}")

    print(f"     Reserved:           {reserved}")
    print(f"     DF (Do not Fragment): {df}")
    print(f"     MF (More Fragments):  {mf}")
    print(f"     Fragment Offset:      0x{frag_off:x} | {frag_off}")

    print(f"  Protocol:        {proto_hex:<4} | {proto_dec} (1=ICMP,6=TCP,17=UDP)")
    print(f"  Source IP:       {s_ip_hex:<8} | {s_ip_read}")
    print(f"  Destination IP:  {d_ip_hex:<8} | {d_ip_read}")

    next_offset = offset + ip_header_len
    if proto_dec == 17:
        parse_udp_header(hex_data, offset=next_offset)
    elif proto_dec == 6:
        parse_tcp_header(hex_data, offset=next_offset)
    else:
        print("  IP protocol not supported (only TCP/UDP shown).")


def parse_tcp_header(hex_data, offset=34):
    """
    Minimal TCP parse showing Source/Dest Port, Seq, Ack, Flags, etc.
    """
    base = offset * 2
    if len(hex_data) < base + 40:
        print("Truncated TCP header. Skipping.")
        return

    src_port_hex = hex_data[base     : base+4]
    dst_port_hex = hex_data[base + 4 : base+8]
    seq_hex      = hex_data[base + 8 : base+16]
    ack_hex      = hex_data[base +16 : base+24]
    off_flags    = hex_data[base +24 : base+28]
    win_hex      = hex_data[base +28 : base+32]
    csum_hex     = hex_data[base +32 : base+36]
    urgp_hex     = hex_data[base +36 : base+40]

    sp_dec  = int(src_port_hex,16)
    dp_dec  = int(dst_port_hex,16)
    seq_dec = int(seq_hex,16)
    ack_dec = int(ack_hex,16)

    of_int   = int(off_flags,16)
    data_off = (of_int >> 12) & 0xF
    flags_9  = of_int & 0x1FF
    flags_bin= bin(flags_9)[2:].zfill(9)

    win_dec  = int(win_hex,16)
    csum_dec = int(csum_hex,16)
    urgp_dec = int(urgp_hex,16)

    print("TCP Header:")
    print(f"  Source Port:      {src_port_hex:<6} | {sp_dec}")
    print(f"  Destination Port: {dst_port_hex:<6} | {dp_dec}")
    print(f"  Sequence Number:  {seq_hex:<8} | {seq_dec}")
    print(f"  Acknowledgment:   {ack_hex:<8} | {ack_dec}")
    print(f"  Data Offset:      {off_flags:<4} | {data_off}")
    print(f"  Flags (binary):          | {flags_bin}")
    print(f"  Window:           {win_hex:<6} | {win_dec}")
    print(f"  Checksum:         {csum_hex:<6} | {csum_dec}")
    print(f"  Urgent Ptr:       {urgp_hex:<6} | {urgp_dec}")


def parse_udp_header(hex_data, offset):
    """
    8-byte UDP header. Like teacher's example:
      Source Port:      cd22  | 52514
      Destination Port: 01bb  | 443
      Length:           0025  | 37
      Checksum:         2de5  | 11749
      Payload (hex):    ...
    """
    base = offset * 2
    if len(hex_data) < base + 16:
        print("Truncated UDP header. Skipping.")
        return

    src_port_hex = hex_data[base     : base+4]
    dst_port_hex = hex_data[base + 4 : base+8]
    len_hex      = hex_data[base + 8 : base+12]
    sum_hex      = hex_data[base +12 : base+16]

    sp_dec = int(src_port_hex,16)
    dp_dec = int(dst_port_hex,16)
    l_dec  = int(len_hex,16)
    cs_dec = int(sum_hex,16)

    print("UDP Header:")
    print(f"  Source Port:      {src_port_hex:<6} | {sp_dec}")
    print(f"  Destination Port: {dst_port_hex:<6} | {dp_dec}")
    print(f"  Length:           {len_hex:<6} | {l_dec}")
    print(f"  Checksum:         {sum_hex:<6} | {cs_dec}")

    # If there's leftover payload
    payload_start = base + 16
    if len(hex_data) > payload_start:
        payload_hex = hex_data[payload_start:]
        print(f"  Payload (hex):    {payload_hex}")
