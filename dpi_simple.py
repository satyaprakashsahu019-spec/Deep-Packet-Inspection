#!/usr/bin/env python3
"""
Simple Single-Threaded DPI Engine.
Direct Python conversion of src/main_working.cpp.
"""

from __future__ import annotations
import sys
import argparse
from typing import Dict, List, Tuple
from dpi.pcap import PcapReader, PcapWriter, PcapPacketHeader, RawPacket
from dpi.parser import PacketParser, ParsedPacket
from dpi.extractors import SNIExtractor, HTTPHostExtractor
from dpi.types import (
    FiveTuple,
    AppType,
    app_type_to_string,
    sni_to_app_type,
)
from dpi.rules import BlockingRules
from dpi.connection_tracker import Flow


def print_usage(prog_name: str) -> None:
    print(f"""
DPI Engine - Deep Packet Inspection System (Simple Version)
===========================================================

Usage: {prog_name} <input.pcap> <output.pcap> [options]

Options:
  --block-ip <ip>        Block traffic from source IP
  --block-app <app>      Block application (YouTube, Facebook, etc.)
  --block-domain <dom>   Block domain (substring match)

Example:
  {prog_name} capture.pcap filtered.pcap --block-app YouTube --block-ip 192.168.1.50
""")


def main() -> int:
    if len(sys.argv) < 3:
        print_usage(sys.argv[0])
        return 1

    input_file = sys.argv[1]
    output_file = sys.argv[2]

    rules = BlockingRules()

    # Parse CLI options
    i = 3
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg == "--block-ip" and i + 1 < len(sys.argv):
            i += 1
            rules.block_ip(sys.argv[i])
        elif arg == "--block-app" and i + 1 < len(sys.argv):
            i += 1
            rules.block_app(sys.argv[i])
        elif arg == "--block-domain" and i + 1 < len(sys.argv):
            i += 1
            rules.block_domain(sys.argv[i])
        i += 1

    print("\n"
          "+==============================================================+\n"
          "|                    DPI ENGINE v1.0                           |\n"
          "+==============================================================+\n")

    reader = PcapReader()
    if not reader.open(input_file):
        return 1

    writer = PcapWriter(output_file, reader.global_header)

    flows: Dict[FiveTuple, Flow] = {}
    total_packets = 0
    forwarded = 0
    dropped = 0
    app_stats: Dict[AppType, int] = {}

    print("[DPI] Processing packets...")

    for raw in reader:
        total_packets += 1

        parsed = PacketParser.parse(raw)
        if not parsed or not parsed.has_ip or (not parsed.has_tcp and not parsed.has_udp):
            continue

        tuple_ = FiveTuple(
            src_ip=parsed.src_ip,
            dst_ip=parsed.dest_ip,
            src_port=parsed.src_port,
            dst_port=parsed.dest_port,
            protocol=parsed.protocol,
        )

        flow = flows.get(tuple_)
        if flow is None:
            flow = Flow(tuple=tuple_)
            flows[tuple_] = flow

        flow.packets += 1
        flow.bytes += len(raw.data)

        # 1. Try TLS SNI extraction
        if (flow.app_type in (AppType.UNKNOWN, AppType.HTTPS)) and not flow.sni and parsed.has_tcp and parsed.dest_port == 443:
            if parsed.payload_length > 5:
                sni = SNIExtractor.extract(parsed.payload_data)
                if sni:
                    flow.sni = sni
                    flow.app_type = sni_to_app_type(sni)

        # 2. Try HTTP Host extraction
        if (flow.app_type in (AppType.UNKNOWN, AppType.HTTP)) and not flow.sni and parsed.has_tcp and parsed.dest_port == 80:
            if parsed.payload_length > 10:
                host = HTTPHostExtractor.extract(parsed.payload_data)
                if host:
                    flow.sni = host
                    flow.app_type = sni_to_app_type(host)

        # 3. DNS Classification
        if flow.app_type == AppType.UNKNOWN and (parsed.dest_port == 53 or parsed.src_port == 53):
            flow.app_type = AppType.DNS

        # 4. Port-based fallback
        if flow.app_type == AppType.UNKNOWN:
            if parsed.dest_port == 443:
                flow.app_type = AppType.HTTPS
            elif parsed.dest_port == 80:
                flow.app_type = AppType.HTTP

        # 5. Check blocking rules
        if not flow.blocked:
            flow.blocked = rules.is_blocked(tuple_.src_ip, flow.app_type, flow.sni)
            if flow.blocked:
                detail = f": {flow.sni}" if flow.sni else ""
                print(f"[BLOCKED] {parsed.src_ip} -> {parsed.dest_ip} ({app_type_to_string(flow.app_type)}{detail})")

        # Update app statistics
        app_stats[flow.app_type] = app_stats.get(flow.app_type, 0) + 1

        # Forward or drop
        if flow.blocked:
            dropped += 1
        else:
            forwarded += 1
            writer.write_raw_packet(raw)

    reader.close()
    writer.close()

    # Print summary report
    print("\n"
          "+==============================================================+\n"
          "|                      PROCESSING REPORT                       |\n"
          "+==============================================================+\n"
          f"| Total Packets:      {total_packets:>10}                             |\n"
          f"| Forwarded:          {forwarded:>10}                             |\n"
          f"| Dropped:            {dropped:>10}                             |\n"
          f"| Active Flows:       {len(flows):>10}                             |\n"
          "+==============================================================+\n"
          "|                    APPLICATION BREAKDOWN                     |\n"
          "+==============================================================+")

    sorted_apps = sorted(app_stats.items(), key=lambda kv: kv[1], reverse=True)
    for app, count in sorted_apps:
        pct = (100.0 * count / total_packets) if total_packets > 0 else 0.0
        bar_len = int(pct / 5)
        bar = "#" * bar_len
        app_name = app_type_to_string(app)
        print(f"| {app_name:<15}{count:>8} {pct:>5.1f}% {bar:<20}  |")

    print("+==============================================================+")

    # List unique SNIs detected
    print("\n[Detected Applications/Domains]")
    unique_snis: Dict[str, AppType] = {}
    for flow in flows.values():
        if flow.sni:
            if flow.sni not in unique_snis or unique_snis[flow.sni] in (AppType.DNS, AppType.HTTPS, AppType.HTTP, AppType.UNKNOWN):
                unique_snis[flow.sni] = flow.app_type

    for sni, app in sorted(unique_snis.items(), key=lambda kv: kv[0]):
        print(f"  - {sni} -> {app_type_to_string(app)}")

    print(f"\nOutput written to: {output_file}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
