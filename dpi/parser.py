"""
Network packet parsing for Ethernet, IPv4, TCP, UDP layers.
Corresponds to include/packet_parser.h and src/packet_parser.cpp.
"""

from __future__ import annotations
import struct
from dataclasses import dataclass
from typing import Optional
from .pcap import RawPacket


class TCPFlags:
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20


class Protocol:
    ICMP = 1
    TCP = 6
    UDP = 17


class EtherType:
    IPv4 = 0x0800
    IPv6 = 0x86DD
    ARP = 0x0806


def mac_to_string(mac_bytes: bytes) -> str:
    """Format 6-byte MAC address to colon-separated hex."""
    return ":".join(f"{b:02x}" for b in mac_bytes[:6])


def ip_to_string(ip_bytes_or_int: bytes | int) -> str:
    """Format IPv4 address into dotted decimal string."""
    if isinstance(ip_bytes_or_int, (bytes, bytearray)):
        return ".".join(str(b) for b in ip_bytes_or_int[:4])
    ip = ip_bytes_or_int
    return f"{ip & 0xFF}.{(ip >> 8) & 0xFF}.{(ip >> 16) & 0xFF}.{(ip >> 24) & 0xFF}"


def protocol_to_string(proto: int) -> str:
    if proto == Protocol.ICMP:
        return "ICMP"
    elif proto == Protocol.TCP:
        return "TCP"
    elif proto == Protocol.UDP:
        return "UDP"
    return f"Unknown({proto})"


def tcp_flags_to_string(flags: int) -> str:
    parts = []
    if flags & TCPFlags.SYN:
        parts.append("SYN")
    if flags & TCPFlags.ACK:
        parts.append("ACK")
    if flags & TCPFlags.FIN:
        parts.append("FIN")
    if flags & TCPFlags.RST:
        parts.append("RST")
    if flags & TCPFlags.PSH:
        parts.append("PSH")
    if flags & TCPFlags.URG:
        parts.append("URG")
    return " ".join(parts) if parts else "none"


@dataclass
class ParsedPacket:
    """Full protocol breakdown of an inspected packet."""
    timestamp_sec: int = 0
    timestamp_usec: int = 0

    # Ethernet Layer
    src_mac: str = ""
    dest_mac: str = ""
    ether_type: int = 0

    # IP Layer
    has_ip: bool = False
    ip_version: int = 4
    src_ip: str = ""
    dest_ip: str = ""
    protocol: int = 0
    ttl: int = 0

    # Transport Layer
    has_tcp: bool = False
    has_udp: bool = False
    src_port: int = 0
    dest_port: int = 0

    # TCP Specific
    tcp_flags: int = 0
    seq_number: int = 0
    ack_number: int = 0

    # Payload
    payload_offset: int = 0
    payload_length: int = 0
    payload_data: bytes = b""


class PacketParser:
    """Parses raw packet bytes into Ethernet, IPv4, TCP/UDP headers and payload."""

    @staticmethod
    def parse(raw: RawPacket) -> Optional[ParsedPacket]:
        data = raw.data
        length = len(data)
        if length < 14:  # Minimum Ethernet header
            return None

        parsed = ParsedPacket(
            timestamp_sec=raw.header.ts_sec,
            timestamp_usec=raw.header.ts_usec,
        )

        # 1. Parse Ethernet Header (14 bytes)
        # Bytes 0-5: Destination MAC
        # Bytes 6-11: Source MAC
        # Bytes 12-13: EtherType (big-endian)
        parsed.dest_mac = mac_to_string(data[0:6])
        parsed.src_mac = mac_to_string(data[6:12])
        parsed.ether_type = struct.unpack(">H", data[12:14])[0]
        offset = 14

        # 2. Parse IPv4 Header
        if parsed.ether_type == EtherType.IPv4:
            if length < offset + 20:
                return parsed  # Truncated IP header

            version_ihl = data[offset]
            parsed.ip_version = (version_ihl >> 4) & 0x0F
            ihl = version_ihl & 0x0F
            ip_header_len = ihl * 4

            if parsed.ip_version != 4 or ip_header_len < 20 or length < offset + ip_header_len:
                return parsed

            parsed.has_ip = True
            parsed.ttl = data[offset + 8]
            parsed.protocol = data[offset + 9]

            # Source IP (bytes 12-15) and Destination IP (bytes 16-19)
            parsed.src_ip = ".".join(str(b) for b in data[offset + 12: offset + 16])
            parsed.dest_ip = ".".join(str(b) for b in data[offset + 16: offset + 20])
            offset += ip_header_len

            # 3. Parse Transport Layer
            if parsed.protocol == Protocol.TCP:
                if length >= offset + 20:
                    src_port, dest_port, seq, ack = struct.unpack(">HHII", data[offset: offset + 12])
                    parsed.src_port = src_port
                    parsed.dest_port = dest_port
                    parsed.seq_number = seq
                    parsed.ack_number = ack

                    data_offset = (data[offset + 12] >> 4) & 0x0F
                    tcp_header_len = data_offset * 4
                    parsed.tcp_flags = data[offset + 13]

                    if tcp_header_len >= 20 and length >= offset + tcp_header_len:
                        parsed.has_tcp = True
                        offset += tcp_header_len

            elif parsed.protocol == Protocol.UDP:
                if length >= offset + 8:
                    src_port, dest_port, udp_len = struct.unpack(">HHH", data[offset: offset + 6])
                    parsed.src_port = src_port
                    parsed.dest_port = dest_port
                    parsed.has_udp = True
                    offset += 8

        # 4. Payload extraction
        if offset < length:
            parsed.payload_offset = offset
            parsed.payload_length = length - offset
            parsed.payload_data = data[offset:]
        else:
            parsed.payload_offset = length
            parsed.payload_length = 0
            parsed.payload_data = b""

        return parsed
