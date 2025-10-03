# Parse Ethernet header
def parse_ethernet_header(hex_data):
    print(f"Hex data: {hex_data}")

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
    elif ether_type == "0800":
        parse_ipv4_header(payload)
    elif ether_type == "86dd":
        parse_ipv6_header(payload)
    else:
        print(f"  {'Unknown EtherType:':<25} {ether_type:<20} | {int(ether_type, 16)}")
        print("  No parser available for this EtherType.")

    return ether_type, payload


# Parse ARP header
def parse_arp_header(hex_data):

    hardware_type = int(hex_data[:4], 16)
    protocol_type = int(hex_data[4:8], 16)
    hardware_size = int(hex_data[8:10], 16)
    protocol_size = int(hex_data[10:12], 16)
    operation = int(hex_data[12:16], 16)
    sender_mac = ':'.join(hex_data[i:i+2] for i in range(16, 28, 2))
    sender_ip = parse_ip_address(hex_data[28:36])
    target_mac = ':'.join(hex_data[i:i+2] for i in range(36, 48, 2))
    target_ip = parse_ip_address(hex_data[48:56])

    print(f"ARP Header:")
    print(f"  {'Hardware Type:':<25} {hex_data[:4]:<20} | {hardware_type}")
    print(f"  {'Protocol Type:':<25} {hex_data[4:8]:<20} | {protocol_type}")
    print(f"  {'Hardware Size:':<25} {hex_data[8:10]:<20} | {hardware_size}")
    print(f"  {'Protocol Size:':<25} {hex_data[10:12]:<20} | {protocol_size}")
    print(f"  {'Operation:':<25} {hex_data[12:16]:<20} | {operation}")
    print(f"  {'Sender MAC:':<25} {hex_data[16:28]:<20} | {sender_mac}")
    print(f"  {'Sender IP:':<25} {hex_data[28:36]:<20} | {sender_ip}")
    print(f"  {'Target MAC:':<25} {hex_data[36:48]:<20} | {target_mac}")
    print(f"  {'Target IP:':<25} {hex_data[48:56]:<20} | {target_ip}")

def parse_ip_address(hex_addr):
    ip_dec = []
    for part in range(0, len(hex_addr), 2):
        hex_part = hex_addr[part:part+2]
        dec_part = int(hex_part, 16)
        ip_dec.append(str(dec_part))
    return ".".join(ip_dec)

# Parse IPv4 header
def parse_ipv4_header(hex_data):

    version = int(hex_data[:1], 16)
    header_length = int(hex_data[1:2], 16) * 4 
    type_of_service = int(hex_data[2:4], 16)
    total_length = int(hex_data[4:8], 16)
    identification = int(hex_data[8:12], 16)
    flags = int(hex_data[12:16], 16)
    flags_bin = f"{flags:016b}"
    frag_offset = int(flags_bin[2:], 2)
    fragment_offet_hex = f"{frag_offset:x}"
    time_to_live = int(hex_data[16:18], 16)
    protocol = int(hex_data[18:20], 16)
    header_checksum = int(hex_data[20:24], 16)
    source_ip = parse_ip_address(hex_data[24:32])
    destination_ip = parse_ip_address(hex_data[32:40])

    print(f"IPv4 Header:")
    print(f"  {'Version:':<25} {hex_data[:1]:<20} | {version}")
    print(f"  {'Header Length:':<25} {hex_data[1:2]:<20} | {header_length} bytes")
    print(f"  {'Type of Service:':<25} {hex_data[2:4]:<20} | {type_of_service}")
    print(f"  {'Total Length:':<25} {hex_data[4:8]:<20} | {total_length}")
    print(f"  {'Identification:':<25} {hex_data[8:12]:<20} | {identification}")
    print(f"  {'Flags & Frag Offset:':<25} {hex_data[12:16]:<20} | 0b{flags_bin}")
    print(f"    {'Reserved:':<20} {flags_bin[0]}")
    print(f"    {'DF (Do not Fragment):':<10} {flags_bin[1]}")
    print(f"    {'MF (More Fragments):':<10} {flags_bin[2]}")
    print(f"    {'Fragment Offset:':<10} 0x{fragment_offet_hex} | {frag_offset}")
    print(f"  {'Time to Live:':<25} {hex_data[16:18]:<20} | {time_to_live}")
    print(f"  {'Protocol:':<25} {hex_data[18:20]:<20} | {protocol}")
    print(f"  {'Header Checksum:':<25} {hex_data[20:24]:<20} | {header_checksum}")
    print(f"  {'Source IP:':<25} {hex_data[24:32]:<20} | {source_ip}")
    print(f"  {'Destination IP:':<25} {hex_data[32:40]:<20} | {destination_ip}")
    
    payload = hex_data[40:]
    protocol = hex_data[18:20] # set back to hex

    if protocol == "11":  # UPD
        parse_udp_header(payload)
    elif protocol == "06": #TCP
        parse_tcp_header(payload)
    elif protocol == "01": #ICMP
        parse_icmp_header(payload)
    else:
        print(f"  {'Unknown Protocol:':<25} {protocol:<20} | {int(protocol, 16)}")
        print("  No parser available for this protocol.")

def parse_ipv6_header(hex_data):
    
    version = int(hex_data[:1], 16)
    traffic_class = int(hex_data[1:3], 16)
    flow_label = int(hex_data[3:8], 16)
    payload_len = int(hex_data[8:12], 16)
    next_header = int(hex_data[12:14], 16)
    hop_limit = int(hex_data[14:16], 16)
    source_address = ':'.join(hex_data[i:i+4] for i in range(16, 48, 4))
    destination_address = ':'.join(hex_data[i:i+4] for i in range(48, 80, 4))
    
    print(f"IPv6 Header:")
    print(f"  {'Version:':<25} {hex_data[:1]:<20} | {version}")
    print(f"  {'Traffic Class:':<25} {hex_data[1:3]:<20} | {traffic_class}")
    print(f"  {'Flow Label:':<25} {hex_data[3:8]:<20} | {flow_label}")
    print(f"  {'Payload Length:':<25} {hex_data[8:12]:<20} | {payload_len}")
    print(f"  {'Next Header:':<25} {hex_data[12:14]:<20} | {next_header}")
    print(f"  {'Hop Limit:':<25} {hex_data[14:16]:<20} | {hop_limit}")
    print(f"  {'Source Address:':<25} {hex_data[16:48]:<20} | {source_address}")
    print(f"  {'Destination Address:':<25} {hex_data[48:80]:<20} | {destination_address}")

    payload = hex_data[80:]
    next_header = hex_data[12:14] # set back to hex

    if next_header == "11":  # UPD
        parse_udp_header(payload)
    elif next_header == "06": #TCP
        parse_tcp_header(payload)
    elif next_header == "3a": #ICMPv6
        parse_icmpv6_header(payload)
    else:
        print(f"  {'Unknown Protocol:':<25} {next_header:<20} | {int(next_header, 16)}")
        print("  No parser available for this protocol.")

def parse_icmpv6_header(hex_data):
    type = int(hex_data[:2], 16)
    code = int(hex_data[2:4], 16)
    checksum = int(hex_data[4:8], 16)

    print(f"ICMPv6 Header:")
    print(f"  {'Type:':<25} {hex_data[:2]:<20} | {type}")
    print(f"  {'Code:':<25} {hex_data[2:4]:<20} | {code}")
    print(f"  {'Checksum:':<25} {hex_data[4:8]:<20} | {checksum}")
    print(f"  {'Message Body (hex):':<25} {hex_data[8:]:<20}")

def parse_dns_header(hex_data):
    
    transaction_id = int(hex_data[:4], 16)
    flags = int(hex_data[4:8], 16)
    flags_bin = f"{flags:016b}"
    question_count = int(hex_data[8:12], 16)
    answer_count = int(hex_data[12:16], 16)
    authority_count = int(hex_data[16:20], 16)
    additional_count = int(hex_data[20:24], 16)

    print(f"DNS Header:")
    print(f"  {'Transaction ID:':<25} {hex_data[:4]:<20} | {transaction_id}")
    print(f"  {'Flags:':<25} {hex_data[4:8]:<18} | {flags}")
    print(f"    {'Response:':<20} {flags_bin[0]}")
    print(f"    {'Opcode:':<20} {flags_bin[1:5]}")
    print(f"    {'Authoritative:':<20} {flags_bin[5]}")
    print(f"    {'Truncated:':<20} {flags_bin[6]}")
    print(f"    {'Recursion Desired:':<20} {flags_bin[7]}")
    print(f"    {'Recursion Available:':<20} {flags_bin[8]}")
    print(f"    {'Reserved:':<20} {flags_bin[9:12]}")
    print(f"    {'Reponse Code:':<20} {flags_bin[12:16]}")
    print(f"  {'Question Count:':<25} {hex_data[8:12]:<20} | {question_count}")
    print(f"  {'Answer Count:':<25} {hex_data[12:16]:<20} | {answer_count}")
    print(f"  {'Authority Count:':<25} {hex_data[16:20]:<20} | {authority_count}")
    print(f"  {'Additional Count:':<25} {hex_data[20:24]:<20} | {additional_count}")
    print(f"  {'Payload (hex):':<25} {hex_data[24:]:<20}")

def parse_udp_header(hex_data):

    source_port = int(hex_data[:4], 16)
    destination_port = int(hex_data[4:8], 16)
    length = int(hex_data[8:12], 16)
    checksum = int(hex_data[12:16], 16)
    
    print(f"UDP Header:")
    print(f"  {'Source Port:':<25} {hex_data[:4]:<20} | {source_port}")
    print(f"  {'Destination Port:':<25} {hex_data[4:8]:<20} | {destination_port}")
    print(f"  {'Length:':<25} {hex_data[8:12]:<20} | {length}")
    print(f"  {'Checksum:':<25} {hex_data[12:16]:<20} | {checksum}")
    print(f"  {'Payload (hex):':<25} {hex_data[16:]:<20}")

    if destination_port == 53 or source_port == 53:
        parse_dns_header(hex_data[16:])

def parse_tcp_header(hex_data):
    source_port = int(hex_data[:4], 16)
    destination_port = int(hex_data[4:8], 16)
    sequence_number = int(hex_data[8:16], 16)
    acknowledgment_number = int(hex_data[16:24], 16)
    data_offset = int(hex_data[24:25], 16) * 4
    reserved = int(hex_data[25:26], 16)
    flags = int(hex_data[25:28], 16)
    flags_bin = f"{flags:09b}"
    window_size = int(hex_data[28:32], 16)
    checksum = int(hex_data[32:36], 16)
    urgent_pointer = int(hex_data[36:40], 16)
    payload = hex_data[(data_offset * 2):]

    print(f"TCP Header:")
    print(f"  {'Source Port:':<25} {hex_data[:4]:<20} | {source_port}")
    print(f"  {'Destination Port:':<25} {hex_data[4:8]:<20} | {destination_port}")
    print(f"  {'Sequence Number:':<25} {hex_data[8:16]:<20} | {sequence_number}")
    print(f"  {'Acknowledgment Number:':<25} {hex_data[16:24]:<20} | {acknowledgment_number}")
    print(f"  {'Data Offset:':<25} {hex_data[24:25]:<20} | {data_offset} bytes")
    print(f"  {'Reserved:':<25} 0b{hex_data[25:26]:<18} | {reserved}")
    print(f"  {'Flags:':<25} 0b{f'{flags:09b}':<18} | {flags}")
    print(f"    {'NS:':<20} {flags_bin[0]}")
    print(f"    {'CWR:':<20} {flags_bin[1]}")
    print(f"    {'ECE:':<20} {flags_bin[2]}")
    print(f"    {'URG:':<20} {flags_bin[3]}")
    print(f"    {'ACK:':<20} {flags_bin[4]}")
    print(f"    {'PSH:':<20} {flags_bin[5]}")
    print(f"    {'RST:':<20} {flags_bin[6]}")
    print(f"    {'SYN:':<20} {flags_bin[7]}")
    print(f"    {'FIN:':<20} {flags_bin[8]}")
    print(f"  {'Window Size:':<25} {hex_data[28:32]:<20} | {window_size}")
    print(f"  {'Checksum:':<25} {hex_data[32:36]:<20} | {checksum}")
    print(f"  {'Urgent Pointer:':<25} {hex_data[36:40]:<20} | {urgent_pointer}")
    print(f"  {'Payload (hex):':<25} {payload:<20}")

    if destination_port == 53 or source_port == 53:
        if payload:
            parse_dns_header(payload[4:])

def parse_icmp_header(hex_data):
    type = int(hex_data[:2], 16)
    code = int(hex_data[2:4], 16)
    checksum = int(hex_data[4:8], 16)
    identifier = int(hex_data[8:12], 16)
    sequence_number = int(hex_data[12:16], 16)
    
    print(f"ICMP Header:")
    print(f"  {'Type:':<25} {hex_data[:2]:<20} | {type}")
    print(f"  {'Code:':<25} {hex_data[2:4]:<20} | {code}")
    print(f"  {'Checksum:':<25} {hex_data[4:8]:<20} | {checksum}")
    print(f"  {'Identifier:':<25} {hex_data[8:12]:<20} | {identifier}")
    print(f"  {'Sequence Number:':<25} {hex_data[12:16]:<20} | {sequence_number}")
    print(f"  {'Payload (hex):':<25} {hex_data[16:]:<20}")



