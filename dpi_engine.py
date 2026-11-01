#!/usr/bin/env python3
"""
DPI Engine - Deep Packet Inspection System CLI.
Corresponds to src/main_dpi.cpp.
"""

from __future__ import annotations
import sys
import argparse
from dpi.engine import DPIEngine, DPIConfig


def print_banner():
    print("""
+==============================================================+
|                    DPI ENGINE v1.0                           |
|               Deep Packet Inspection System                  |
+==============================================================+
""")


def parse_args():
    parser = argparse.ArgumentParser(
        description="DPI Engine - Deep Packet Inspection System in Python",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Supported Apps for Blocking:
  Google, YouTube, Facebook, Instagram, Twitter/X, Netflix, Amazon,
  Microsoft, Apple, WhatsApp, Telegram, TikTok, Spotify, Zoom, Discord, GitHub, Cloudflare

Examples:
  python dpi_engine.py capture.pcap filtered.pcap
  python dpi_engine.py capture.pcap filtered.pcap --block-app YouTube
  python dpi_engine.py capture.pcap filtered.pcap --block-ip 192.168.1.50 --block-domain *.tiktok.com
  python dpi_engine.py capture.pcap filtered.pcap --rules blocking_rules.txt
""",
    )
    parser.add_argument("input", help="Input PCAP file (captured user traffic)")
    parser.add_argument("output", help="Output PCAP file (filtered traffic)")
    parser.add_argument("--block-ip", action="append", default=[], help="Block packets from source IP")
    parser.add_argument("--block-app", action="append", default=[], help="Block application (e.g., YouTube, Facebook)")
    parser.add_argument("--block-domain", action="append", default=[], help="Block domain (supports wildcards: *.facebook.com)")
    parser.add_argument("--block-port", type=int, action="append", default=[], help="Block packets to destination port")
    parser.add_argument("--rules", "--load-rules", dest="rules", default="", help="Load blocking rules from file")
    parser.add_argument("--save-rules", default="", help="Save active blocking rules to file")
    parser.add_argument("--lbs", type=int, default=2, help="Number of load balancer threads (default: 2)")
    parser.add_argument("--fps", type=int, default=2, help="FP threads per LB (default: 2)")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    return parser.parse_args()


def main() -> int:
    if len(sys.argv) < 3:
        print_banner()
        print(f"Usage: {sys.argv[0]} <input.pcap> <output.pcap> [options]\n")
        print("Run with --help for all available options.")
        return 1

    args = parse_args()

    config = DPIConfig(
        num_load_balancers=args.lbs,
        fps_per_lb=args.fps,
        rules_file=args.rules,
        verbose=args.verbose,
    )

    engine = DPIEngine(config)
    if not engine.initialize():
        print("Failed to initialize DPI engine", file=sys.stderr)
        return 1

    # Apply command-line blocking rules
    for ip in args.block_ip:
        engine.block_ip(ip)

    for app in args.block_app:
        engine.block_app(app)

    for domain in args.block_domain:
        engine.block_domain(domain)

    for port in args.block_port:
        engine.block_port(port)

    # Save rules if requested
    if args.save_rules:
        engine.save_rules(args.save_rules)

    # Process PCAP
    if not engine.process_file(args.input, args.output):
        print("Failed to process file", file=sys.stderr)
        return 1

    print("\nProcessing complete!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
