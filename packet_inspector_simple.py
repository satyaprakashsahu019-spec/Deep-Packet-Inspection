#!/usr/bin/env python3
"""
Simple packet inspector with SNI extraction.
Corresponds to src/main_simple.cpp.
"""

from __future__ import annotations
import sys
from dpi.pcap import PcapReader
from dpi.parser import PacketParser
from dpi.extractors import SNIExtractor


def main() -> int:
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <pcap_file>")
        return 1

    filename = sys.argv[1]
    reader = PcapReader()
    if not reader.open(filename):
        return 1

    count = 0
    tls_count = 0

    print("Processing packets...")

    for raw in reader:
        count += 1
        parsed = PacketParser.parse(raw)
        if not parsed or not parsed.has_ip:
            continue

        sni_info = ""
        if parsed.has_tcp and parsed.dest_port == 443 and parsed.payload_length > 0:
            sni = SNIExtractor.extract(parsed.payload_data)
            if sni:
                sni_info = f" [SNI: {sni}]"
                tls_count += 1

        print(f"Packet {count}: {parsed.src_ip}:{parsed.src_port} -> {parsed.dest_ip}:{parsed.dest_port}{sni_info}")

    print(f"\nTotal packets: {count}")
    print(f"SNI extracted: {tls_count}")

    reader.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
