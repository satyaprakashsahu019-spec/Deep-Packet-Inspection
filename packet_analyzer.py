#!/usr/bin/env python3
"""
Packet Analyzer CLI.
Corresponds to src/main.cpp.
"""

from __future__ import annotations
import sys
import datetime
from dpi.pcap import PcapReader
from dpi.parser import PacketParser, ParsedPacket, EtherType, protocol_to_string, tcp_flags_to_string


def print_packet_summary(pkt: ParsedPacket, packet_num: int) -> None:
    dt = datetime.datetime.fromtimestamp(pkt.timestamp_sec)
    time_str = dt.strftime("%Y-%m-%d %H:%M:%S") + f".{pkt.timestamp_usec:06d}"

    print(f"\n========== Packet #{packet_num} ==========")
    print(f"Time: {time_str}\n")

    # Ethernet Layer
    print("[Ethernet]")
    print(f"  Source MAC:      {pkt.src_mac}")
    print(f"  Destination MAC: {pkt.dest_mac}")
    eth_type_str = f"0x{pkt.ether_type:04x}"
    if pkt.ether_type == EtherType.IPv4:
        eth_type_str += " (IPv4)"
    elif pkt.ether_type == EtherType.IPv6:
        eth_type_str += " (IPv6)"
    elif pkt.ether_type == EtherType.ARP:
        eth_type_str += " (ARP)"
    print(f"  EtherType:       {eth_type_str}\n")

    # IP Layer
    if pkt.has_ip:
        print(f"[IPv{pkt.ip_version}]")
        print(f"  Source IP:      {pkt.src_ip}")
        print(f"  Destination IP: {pkt.dest_ip}")
        print(f"  Protocol:       {protocol_to_string(pkt.protocol)}")
        print(f"  TTL:            {pkt.ttl}\n")

    # TCP Layer
    if pkt.has_tcp:
        print("[TCP]")
        print(f"  Source Port:      {pkt.src_port}")
        print(f"  Destination Port: {pkt.dest_port}")
        print(f"  Sequence Number:  {pkt.seq_number}")
        print(f"  Ack Number:       {pkt.ack_number}")
        print(f"  Flags:            {tcp_flags_to_string(pkt.tcp_flags)}\n")

    # UDP Layer
    if pkt.has_udp:
        print("[UDP]")
        print(f"  Source Port:      {pkt.src_port}")
        print(f"  Destination Port: {pkt.dest_port}\n")

    # Payload
    if pkt.payload_length > 0:
        print("[Payload]")
        print(f"  Length: {pkt.payload_length} bytes")
        preview_len = min(pkt.payload_length, 32)
        hex_preview = " ".join(f"{b:02x}" for b in pkt.payload_data[:preview_len])
        if pkt.payload_length > 32:
            hex_preview += " ..."
        print(f"  Preview: {hex_preview}")


def print_usage(prog_name: str) -> None:
    print(f"""Usage: {prog_name} <pcap_file> [max_packets] [-c <count>]

Arguments:
  pcap_file           - Path to a .pcap file captured by Wireshark
  max_packets, -c, -n - (Optional) Maximum number of packets to display

Example:
  {prog_name} capture.pcap
  {prog_name} capture.pcap 10
  {prog_name} capture.pcap -c 10
""")


def main() -> int:
    print("====================================")
    print("     Packet Analyzer v1.0")
    print("====================================\n")

    if len(sys.argv) < 2:
        print_usage(sys.argv[0])
        return 1

    filename: str | None = None
    max_packets = -1

    args = sys.argv[1:]
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in ("-c", "-n", "--count", "--max"):
            i += 1
            if i >= len(args):
                print(f"Error: {arg} requires a number argument", file=sys.stderr)
                return 1
            try:
                max_packets = int(args[i])
            except ValueError:
                print(f"Invalid max_packets: {args[i]}", file=sys.stderr)
                return 1
        elif arg.startswith(("-c=", "-n=", "--count=", "--max=")):
            val = arg.split("=", 1)[1]
            try:
                max_packets = int(val)
            except ValueError:
                print(f"Invalid max_packets: {val}", file=sys.stderr)
                return 1
        elif arg in ("-h", "--help"):
            print_usage(sys.argv[0])
            return 0
        elif filename is None:
            filename = arg
        elif max_packets < 0:
            try:
                max_packets = int(arg)
            except ValueError:
                print(f"Invalid max_packets: {arg}", file=sys.stderr)
                return 1
        else:
            print(f"Unknown argument: {arg}", file=sys.stderr)
            return 1
        i += 1

    if not filename:
        print_usage(sys.argv[0])
        return 1

    reader = PcapReader()
    if not reader.open(filename):
        return 1

    print("\n--- Reading packets ---")
    packet_count = 0
    parse_errors = 0

    for raw in reader:
        packet_count += 1
        parsed = PacketParser.parse(raw)
        if parsed:
            print_packet_summary(parsed, packet_count)
        else:
            print(f"Warning: Failed to parse packet #{packet_count}", file=sys.stderr)
            parse_errors += 1

        if max_packets > 0 and packet_count >= max_packets:
            print(f"\n(Stopped after {max_packets} packets)")
            break

    print("\n====================================")
    print("Summary:")
    print(f"  Total packets read:  {packet_count}")
    print(f"  Parse errors:        {parse_errors}")
    print("====================================")

    reader.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
