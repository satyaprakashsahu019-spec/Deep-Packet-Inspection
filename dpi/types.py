"""
Data types and definitions for Deep Packet Inspection (DPI) system.
Corresponds to include/types.h and src/types.cpp.
"""

from __future__ import annotations
import enum
import time
import threading
from dataclasses import dataclass, field
from typing import Optional


def ip_str_to_int(ip: str) -> int:
    """Convert IPv4 dotted string to 32-bit unsigned integer (network / little-endian friendly)."""
    octets = [int(x) for x in ip.split(".")]
    if len(octets) != 4:
        raise ValueError(f"Invalid IPv4 address: {ip}")
    # Little-endian octet packing as used in original C++ implementation:
    # result |= (octet << shift) where shift goes 0, 8, 16, 24
    return (octets[0]) | (octets[1] << 8) | (octets[2] << 16) | (octets[3] << 24)


def ip_int_to_str(ip: int) -> str:
    """Convert 32-bit integer back to IPv4 dotted string."""
    return f"{ip & 0xFF}.{(ip >> 8) & 0xFF}.{(ip >> 16) & 0xFF}.{(ip >> 24) & 0xFF}"


# ============================================================================
# Five-Tuple: Uniquely identifies a connection/flow
# ============================================================================
@dataclass(frozen=True)
class FiveTuple:
    """
    Identifies a unidirectional or bidirectional network flow.
    src_ip and dst_ip can be dotted-quad strings ("192.168.1.1").
    """
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int  # TCP=6, UDP=17

    def reverse(self) -> FiveTuple:
        """Create reverse tuple (for matching bidirectional flows)."""
        return FiveTuple(
            src_ip=self.dst_ip,
            dst_ip=self.src_ip,
            src_port=self.dst_port,
            dst_port=self.src_port,
            protocol=self.protocol,
        )

    def canonical(self) -> FiveTuple:
        """Return canonical orientation for bidirectional matching."""
        if (self.src_ip, self.src_port) <= (self.dst_ip, self.dst_port):
            return self
        return self.reverse()

    @property
    def src_ip_int(self) -> int:
        return ip_str_to_int(self.src_ip)

    @property
    def dst_ip_int(self) -> int:
        return ip_str_to_int(self.dst_ip)

    def to_string(self) -> str:
        proto_str = "TCP" if self.protocol == 6 else ("UDP" if self.protocol == 17 else f"?({self.protocol})")
        return f"{self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port} ({proto_str})"

    def __str__(self) -> str:
        return self.to_string()


# ============================================================================
# Application Classification
# ============================================================================
class AppType(enum.IntEnum):
    UNKNOWN = 0
    HTTP = 1
    HTTPS = 2
    DNS = 3
    TLS = 4
    QUIC = 5
    # Specific applications (detected via SNI)
    GOOGLE = 6
    FACEBOOK = 7
    YOUTUBE = 8
    TWITTER = 9
    INSTAGRAM = 10
    NETFLIX = 11
    AMAZON = 12
    MICROSOFT = 13
    APPLE = 14
    WHATSAPP = 15
    TELEGRAM = 16
    TIKTOK = 17
    SPOTIFY = 18
    ZOOM = 19
    DISCORD = 20
    GITHUB = 21
    CLOUDFLARE = 22
    APP_COUNT = 23


_APP_NAME_MAP = {
    AppType.UNKNOWN: "Unknown",
    AppType.HTTP: "HTTP",
    AppType.HTTPS: "HTTPS",
    AppType.DNS: "DNS",
    AppType.TLS: "TLS",
    AppType.QUIC: "QUIC",
    AppType.GOOGLE: "Google",
    AppType.FACEBOOK: "Facebook",
    AppType.YOUTUBE: "YouTube",
    AppType.TWITTER: "Twitter/X",
    AppType.INSTAGRAM: "Instagram",
    AppType.NETFLIX: "Netflix",
    AppType.AMAZON: "Amazon",
    AppType.MICROSOFT: "Microsoft",
    AppType.APPLE: "Apple",
    AppType.WHATSAPP: "WhatsApp",
    AppType.TELEGRAM: "Telegram",
    AppType.TIKTOK: "TikTok",
    AppType.SPOTIFY: "Spotify",
    AppType.ZOOM: "Zoom",
    AppType.DISCORD: "Discord",
    AppType.GITHUB: "GitHub",
    AppType.CLOUDFLARE: "Cloudflare",
}

_NAME_TO_APP_MAP = {
    name.lower(): app for app, name in _APP_NAME_MAP.items()
}
# Add alternative alias names for convenience
_NAME_TO_APP_MAP.update({
    "twitter": AppType.TWITTER,
    "x": AppType.TWITTER,
    "meta": AppType.FACEBOOK,
})


def app_type_to_string(app: AppType) -> str:
    """Return human-readable application name."""
    return _APP_NAME_MAP.get(app, "Unknown")


def string_to_app_type(name: str) -> AppType:
    """Convert string to AppType enum value."""
    cleaned = name.strip().lower()
    return _NAME_TO_APP_MAP.get(cleaned, AppType.UNKNOWN)


def _match_domain_or_subdomain(sni: str, domain: str) -> bool:
    """Check if sni equals domain or is a subdomain of domain."""
    return sni == domain or sni.endswith("." + domain)


def sni_to_app_type(sni: str) -> AppType:
    """
    Map SNI / domain name to application type.
    """
    if not sni:
        return AppType.UNKNOWN

    lower_sni = sni.lower()

    # YouTube (check before Google as YouTube is more specific)
    if any(k in lower_sni for k in ("youtube", "ytimg", "yt3.ggpht")) or _match_domain_or_subdomain(lower_sni, "youtu.be"):
        return AppType.YOUTUBE

    # Google
    if any(k in lower_sni for k in ("google", "gstatic", "googleapis", "ggpht", "gvt1")):
        return AppType.GOOGLE

    # Facebook / Meta
    if any(k in lower_sni for k in ("facebook", "fbcdn", "fbsbx", "meta.com")) or _match_domain_or_subdomain(lower_sni, "fb.com"):
        return AppType.FACEBOOK

    # Instagram
    if any(k in lower_sni for k in ("instagram", "cdninstagram")):
        return AppType.INSTAGRAM

    # WhatsApp
    if "whatsapp" in lower_sni or _match_domain_or_subdomain(lower_sni, "wa.me"):
        return AppType.WHATSAPP

    # Netflix (check before Twitter to avoid netflix.com matching x.com)
    if any(k in lower_sni for k in ("netflix", "nflxvideo", "nflximg")):
        return AppType.NETFLIX

    # Microsoft (check before Twitter to avoid microsoft.com matching t.co)
    if any(k in lower_sni for k in ("microsoft", "msn.com", "office", "azure", "live.com", "outlook", "bing")):
        return AppType.MICROSOFT

    # Amazon
    if any(k in lower_sni for k in ("amazon", "amazonaws", "cloudfront", "aws")):
        return AppType.AMAZON

    # Twitter / X (use subdomain match for short domains x.com and t.co)
    if (any(k in lower_sni for k in ("twitter", "twimg")) or
        _match_domain_or_subdomain(lower_sni, "x.com") or
        _match_domain_or_subdomain(lower_sni, "t.co")):
        return AppType.TWITTER

    # Apple
    if any(k in lower_sni for k in ("apple", "icloud", "mzstatic", "itunes")):
        return AppType.APPLE

    # Telegram
    if any(k in lower_sni for k in ("telegram", "t.me")):
        return AppType.TELEGRAM

    # TikTok
    if any(k in lower_sni for k in ("tiktok", "tiktokcdn", "musical.ly", "bytedance")):
        return AppType.TIKTOK

    # Spotify
    if any(k in lower_sni for k in ("spotify", "scdn.co")):
        return AppType.SPOTIFY

    # Zoom
    if "zoom" in lower_sni:
        return AppType.ZOOM

    # Discord
    if any(k in lower_sni for k in ("discord", "discordapp")):
        return AppType.DISCORD

    # GitHub
    if any(k in lower_sni for k in ("github", "githubusercontent")):
        return AppType.GITHUB

    # Cloudflare
    if any(k in lower_sni for k in ("cloudflare", "cf-")):
        return AppType.CLOUDFLARE

    # If SNI is present but unrecognized, classify as general HTTPS
    return AppType.HTTPS


# ============================================================================
# Connection State
# ============================================================================
class ConnectionState(enum.Enum):
    NEW = 0
    ESTABLISHED = 1
    CLASSIFIED = 2
    BLOCKED = 3
    CLOSED = 4


# ============================================================================
# Packet Action
# ============================================================================
class PacketAction(enum.Enum):
    FORWARD = 0
    DROP = 1
    INSPECT = 2
    LOG_ONLY = 3


# ============================================================================
# Connection Entry (tracked per flow)
# ============================================================================
@dataclass
class Connection:
    tuple: FiveTuple
    state: ConnectionState = ConnectionState.NEW
    app_type: AppType = AppType.UNKNOWN
    sni: str = ""
    packets_in: int = 0
    packets_out: int = 0
    bytes_in: int = 0
    bytes_out: int = 0
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    action: PacketAction = PacketAction.FORWARD
    syn_seen: bool = False
    syn_ack_seen: bool = False
    fin_seen: bool = False


# ============================================================================
# Packet wrapper for queue passing
# ============================================================================
@dataclass
class PacketJob:
    packet_id: int
    tuple: FiveTuple
    data: bytes
    eth_offset: int = 0
    ip_offset: int = 0
    transport_offset: int = 0
    payload_offset: int = 0
    payload_length: int = 0
    tcp_flags: int = 0
    ts_sec: int = 0
    ts_usec: int = 0

    @property
    def payload_data(self) -> bytes:
        if self.payload_length > 0:
            return self.data[self.payload_offset: self.payload_offset + self.payload_length]
        return b""


# ============================================================================
# Statistics (thread-safe counters)
# ============================================================================
class DPIStats:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.total_packets: int = 0
        self.total_bytes: int = 0
        self.forwarded_packets: int = 0
        self.dropped_packets: int = 0
        self.tcp_packets: int = 0
        self.udp_packets: int = 0
        self.other_packets: int = 0
        self.active_connections: int = 0

    def add_packet(self, size: int, is_tcp: bool, is_udp: bool) -> None:
        with self._lock:
            self.total_packets += 1
            self.total_bytes += size
            if is_tcp:
                self.tcp_packets += 1
            elif is_udp:
                self.udp_packets += 1
            else:
                self.other_packets += 1

    def record_forward(self) -> None:
        with self._lock:
            self.forwarded_packets += 1

    def record_drop(self) -> None:
        with self._lock:
            self.dropped_packets += 1

    def to_dict(self) -> dict:
        with self._lock:
            return {
                "total_packets": self.total_packets,
                "total_bytes": self.total_bytes,
                "forwarded_packets": self.forwarded_packets,
                "dropped_packets": self.dropped_packets,
                "tcp_packets": self.tcp_packets,
                "udp_packets": self.udp_packets,
                "other_packets": self.other_packets,
                "active_connections": self.active_connections,
            }
