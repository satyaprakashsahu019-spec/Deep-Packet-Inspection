"""
Protocol deep inspection extractors (TLS SNI, HTTP Host, DNS Query, QUIC).
Corresponds to include/sni_extractor.h and src/sni_extractor.cpp.
"""

from __future__ import annotations
import struct
import re
from typing import List, Optional, Tuple


class SNIExtractor:
    """
    Parses TLS Client Hello messages to extract the Server Name Indication (SNI).
    """

    CONTENT_TYPE_HANDSHAKE = 0x16
    HANDSHAKE_CLIENT_HELLO = 0x01
    EXTENSION_SNI = 0x0000
    SNI_TYPE_HOSTNAME = 0x00

    @classmethod
    def is_tls_client_hello(cls, payload: bytes) -> bool:
        """Check if payload starts with a valid TLS Client Hello record."""
        length = len(payload)
        if length < 9:
            return False

        # Byte 0: Content Type (0x16 = Handshake)
        if payload[0] != cls.CONTENT_TYPE_HANDSHAKE:
            return False

        # Bytes 1-2: Record TLS Version (0x0300 to 0x0304)
        version = (payload[1] << 8) | payload[2]
        if version < 0x0300 or version > 0x0304:
            return False

        # Bytes 3-4: Record length
        record_length = (payload[3] << 8) | payload[4]
        if record_length > length - 5:
            return False

        # Byte 5: Handshake Type (0x01 = Client Hello)
        if payload[5] != cls.HANDSHAKE_CLIENT_HELLO:
            return False

        return True

    @classmethod
    def extract(cls, payload: bytes) -> Optional[str]:
        """Extract SNI hostname from TLS Client Hello payload."""
        if not cls.is_tls_client_hello(payload):
            return None

        length = len(payload)
        # Skip TLS record header (5 bytes)
        offset = 5

        # Skip handshake header:
        # Byte 0: Handshake type (1 byte, Client Hello)
        # Bytes 1-3: Handshake length (3 bytes)
        if offset + 4 > length:
            return None
        offset += 4

        # Client Hello body:
        # Bytes 0-1: Client version (2 bytes)
        # Bytes 2-33: Random (32 bytes)
        offset += 2 + 32
        if offset >= length:
            return None

        # Session ID
        session_id_length = payload[offset]
        offset += 1 + session_id_length
        if offset + 2 > length:
            return None

        # Cipher suites
        cipher_suites_length = (payload[offset] << 8) | payload[offset + 1]
        offset += 2 + cipher_suites_length
        if offset >= length:
            return None

        # Compression methods
        compression_methods_length = payload[offset]
        offset += 1 + compression_methods_length
        if offset + 2 > length:
            return None

        # Extensions
        extensions_length = (payload[offset] << 8) | payload[offset + 1]
        offset += 2

        extensions_end = min(offset + extensions_length, length)

        # Parse extensions to find SNI
        while offset + 4 <= extensions_end:
            ext_type = (payload[offset] << 8) | payload[offset + 1]
            ext_len = (payload[offset + 2] << 8) | payload[offset + 3]
            offset += 4

            if offset + ext_len > extensions_end:
                break

            if ext_type == cls.EXTENSION_SNI:
                # Structure:
                #   SNI List Length (2 bytes)
                #   SNI Type (1 byte, 0x00 for hostname)
                #   SNI Length (2 bytes)
                #   SNI Value (hostname bytes)
                if ext_len < 5:
                    break

                sni_list_len = (payload[offset] << 8) | payload[offset + 1]
                if sni_list_len < 3:
                    break

                sni_type = payload[offset + 2]
                sni_len = (payload[offset + 3] << 8) | payload[offset + 4]

                if sni_type == cls.SNI_TYPE_HOSTNAME and sni_len <= ext_len - 5:
                    hostname_bytes = payload[offset + 5: offset + 5 + sni_len]
                    try:
                        return hostname_bytes.decode("utf-8")
                    except UnicodeDecodeError:
                        return hostname_bytes.decode("latin1", errors="replace")

            offset += ext_len

        return None

    @classmethod
    def extract_extensions(cls, payload: bytes) -> List[Tuple[int, bytes]]:
        """Extract all extensions as (type, data) pairs for inspection."""
        if not cls.is_tls_client_hello(payload):
            return []

        length = len(payload)
        offset = 5 + 4 + 2 + 32  # Skip record, handshake header, version, random
        if offset >= length:
            return []

        session_id_length = payload[offset]
        offset += 1 + session_id_length
        if offset + 2 > length:
            return []

        cipher_suites_length = (payload[offset] << 8) | payload[offset + 1]
        offset += 2 + cipher_suites_length
        if offset >= length:
            return []

        compression_methods_length = payload[offset]
        offset += 1 + compression_methods_length
        if offset + 2 > length:
            return []

        extensions_length = (payload[offset] << 8) | payload[offset + 1]
        offset += 2
        extensions_end = min(offset + extensions_length, length)

        extensions: List[Tuple[int, bytes]] = []
        while offset + 4 <= extensions_end:
            ext_type = (payload[offset] << 8) | payload[offset + 1]
            ext_len = (payload[offset + 2] << 8) | payload[offset + 3]
            offset += 4
            if offset + ext_len > extensions_end:
                break
            extensions.append((ext_type, payload[offset: offset + ext_len]))
            offset += ext_len

        return extensions


class HTTPHostExtractor:
    """
    Extracts the Host header from unencrypted HTTP requests.
    """

    HTTP_METHODS = (b"GET ", b"POST", b"PUT ", b"HEAD", b"DELE", b"PATC", b"OPTI")

    @classmethod
    def is_http_request(cls, payload: bytes) -> bool:
        if len(payload) < 4:
            return False
        return any(payload.startswith(m) for m in cls.HTTP_METHODS)

    @classmethod
    def extract(cls, payload: bytes) -> Optional[str]:
        if not cls.is_http_request(payload):
            return None

        # Search for Host: header case-insensitively
        pattern = re.compile(rb"(?i)\r?\nHost:\s*([^\r\n:]+)")
        # In case Host is the first line:
        match = re.search(rb"(?i)(?:^|\r?\n)Host:\s*([^\r\n:]+)", payload)
        if match:
            host_bytes = match.group(1).strip()
            try:
                return host_bytes.decode("utf-8")
            except UnicodeDecodeError:
                return host_bytes.decode("latin1", errors="replace")
        return None


class DNSExtractor:
    """
    Extracts the queried domain name from DNS requests.
    """

    @staticmethod
    def is_dns_query(payload: bytes) -> bool:
        if len(payload) < 12:
            return False
        # QR bit (byte 2, bit 7) - should be 0 for standard query
        flags = payload[2]
        if flags & 0x80:
            return False
        # QDCOUNT (bytes 4-5) should be > 0
        qdcount = (payload[4] << 8) | payload[5]
        return qdcount > 0

    @classmethod
    def extract_query(cls, payload: bytes) -> Optional[str]:
        if not cls.is_dns_query(payload):
            return None

        offset = 12
        labels: List[str] = []
        length = len(payload)

        while offset < length:
            label_len = payload[offset]
            if label_len == 0:
                break  # End of query name
            if label_len > 63:
                break  # Compression pointer or invalid
            offset += 1
            if offset + label_len > length:
                break
            try:
                label = payload[offset: offset + label_len].decode("utf-8")
            except UnicodeDecodeError:
                label = payload[offset: offset + label_len].decode("latin1", errors="replace")
            labels.append(label)
            offset += label_len

        return ".".join(labels) if labels else None


class QUICSNIExtractor:
    """
    Extracts SNI from QUIC Initial packets (HTTP/3).
    """

    @staticmethod
    def is_quic_initial(payload: bytes) -> bool:
        if len(payload) < 5:
            return False
        # QUIC long header starts with form bit (0x80) set
        return (payload[0] & 0x80) != 0

    @classmethod
    def extract(cls, payload: bytes) -> Optional[str]:
        if not cls.is_quic_initial(payload):
            return None

        # Search for TLS Client Hello pattern inside the QUIC packet
        length = len(payload)
        for i in range(length - 50):
            # Check for Handshake Client Hello (0x01)
            if payload[i] == 0x01:
                # Try extracting SNI as TLS record if possible
                if i >= 5:
                    result = SNIExtractor.extract(payload[i - 5:])
                    if result:
                        return result
        return None
