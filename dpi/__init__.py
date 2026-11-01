"""
DPI Engine - Deep Packet Inspection System in Python
Converts and extends the C++ Deep Packet Inspection System.
"""

from .types import (
    FiveTuple,
    AppType,
    ConnectionState,
    PacketAction,
    Connection,
    PacketJob,
    DPIStats,
    app_type_to_string,
    string_to_app_type,
    sni_to_app_type,
)
from .pcap import PcapReader, PcapWriter, PcapGlobalHeader, PcapPacketHeader, RawPacket
from .parser import PacketParser, ParsedPacket, TCPFlags, Protocol, EtherType
from .extractors import SNIExtractor, HTTPHostExtractor, DNSExtractor, QUICSNIExtractor
from .rules import RuleManager, BlockingRules, BlockReason
from .connection_tracker import ConnectionTracker, GlobalConnectionTable, Flow
from .engine import DPIEngine

__all__ = [
    "FiveTuple",
    "AppType",
    "ConnectionState",
    "PacketAction",
    "Connection",
    "PacketJob",
    "DPIStats",
    "app_type_to_string",
    "string_to_app_type",
    "sni_to_app_type",
    "PcapReader",
    "PcapWriter",
    "PcapGlobalHeader",
    "PcapPacketHeader",
    "RawPacket",
    "PacketParser",
    "ParsedPacket",
    "TCPFlags",
    "Protocol",
    "EtherType",
    "SNIExtractor",
    "HTTPHostExtractor",
    "DNSExtractor",
    "QUICSNIExtractor",
    "RuleManager",
    "BlockingRules",
    "BlockReason",
    "ConnectionTracker",
    "GlobalConnectionTable",
    "Flow",
    "DPIEngine",
]
