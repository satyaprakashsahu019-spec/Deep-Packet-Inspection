"""
PCAP file reader and writer.
Corresponds to include/pcap_reader.h and src/pcap_reader.cpp.
"""

from __future__ import annotations
import struct
from dataclasses import dataclass
from typing import BinaryIO, Iterator, Optional, Union

PCAP_MAGIC_NATIVE = 0xA1B2C3D4   # Standard little-endian
PCAP_MAGIC_SWAPPED = 0xD4C3B2A1  # Swapped byte order
PCAP_MAGIC_NS_NATIVE = 0xA1B23C4D  # Nanosecond timestamps
PCAP_MAGIC_NS_SWAPPED = 0x4D3CB2A1


@dataclass
class PcapGlobalHeader:
    """PCAP Global Header (24 bytes)."""
    magic_number: int = PCAP_MAGIC_NATIVE
    version_major: int = 2
    version_minor: int = 4
    thiszone: int = 0
    sigfigs: int = 0
    snaplen: int = 65535
    network: int = 1  # 1 = Ethernet


@dataclass
class PcapPacketHeader:
    """PCAP Packet Header (16 bytes)."""
    ts_sec: int
    ts_usec: int
    incl_len: int
    orig_len: int


@dataclass
class RawPacket:
    """Represents a single captured packet with its PCAP header and raw payload."""
    header: PcapPacketHeader
    data: bytes


class PcapReader:
    """
    Reads network packets from standard .pcap files.
    Handles both native and swapped byte-orders automatically.
    """

    def __init__(self, filename: Optional[str] = None) -> None:
        self.filename = filename
        self._file: Optional[BinaryIO] = None
        self.global_header: Optional[PcapGlobalHeader] = None
        self.endian: str = "<"  # '<' for little-endian, '>' for big-endian
        self.needs_byte_swap: bool = False

        if filename:
            self.open(filename)

    def open(self, filename: str) -> bool:
        self.close()
        self.filename = filename
        try:
            self._file = open(filename, "rb")
        except OSError as e:
            print(f"Error: Could not open file: {filename} ({e})")
            return False

        header_bytes = self._file.read(24)
        if len(header_bytes) < 24:
            print("Error: Could not read PCAP global header")
            self.close()
            return False

        # Check magic number
        raw_magic = struct.unpack("=I", header_bytes[:4])[0]
        if raw_magic == PCAP_MAGIC_NATIVE:
            self.endian = "<"
            self.needs_byte_swap = False
        elif raw_magic == PCAP_MAGIC_SWAPPED:
            self.endian = ">"
            self.needs_byte_swap = True
        else:
            # Try unpacking as big-endian
            be_magic = struct.unpack(">I", header_bytes[:4])[0]
            if be_magic == PCAP_MAGIC_NATIVE:
                self.endian = ">"
                self.needs_byte_swap = True
            elif be_magic == PCAP_MAGIC_SWAPPED:
                self.endian = "<"
                self.needs_byte_swap = False
            else:
                print(f"Error: Invalid PCAP magic number: {hex(raw_magic)}")
                self.close()
                return False

        fmt = f"{self.endian}IHHIIII"
        magic, v_maj, v_min, thiszone, sigfigs, snaplen, network = struct.unpack(fmt, header_bytes)
        self.global_header = PcapGlobalHeader(
            magic_number=magic,
            version_major=v_maj,
            version_minor=v_min,
            thiszone=thiszone,
            sigfigs=sigfigs,
            snaplen=snaplen,
            network=network,
        )
        return True

    def close(self) -> None:
        if self._file and not self._file.closed:
            self._file.close()
        self._file = None

    @property
    def is_open(self) -> bool:
        return self._file is not None and not self._file.closed

    def read_next_packet(self) -> Optional[RawPacket]:
        """Read the next packet. Returns None when EOF is reached."""
        if not self.is_open or self._file is None:
            return None

        hdr_bytes = self._file.read(16)
        if len(hdr_bytes) < 16:
            return None  # End of file

        fmt = f"{self.endian}IIII"
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(fmt, hdr_bytes)

        if self.global_header and incl_len > self.global_header.snaplen:
            # Sanity check
            print(f"Warning: packet length {incl_len} exceeds snaplen {self.global_header.snaplen}")

        data = self._file.read(incl_len)
        if len(data) < incl_len:
            print(f"Warning: truncated packet data, expected {incl_len} got {len(data)}")
            return None

        header = PcapPacketHeader(
            ts_sec=ts_sec,
            ts_usec=ts_usec,
            incl_len=incl_len,
            orig_len=orig_len,
        )
        return RawPacket(header=header, data=data)

    def __iter__(self) -> Iterator[RawPacket]:
        while True:
            pkt = self.read_next_packet()
            if pkt is None:
                break
            yield pkt

    def __enter__(self) -> PcapReader:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()


class PcapWriter:
    """
    Writes raw packets to a .pcap file.
    """

    def __init__(self, filename: Optional[str] = None, global_header: Optional[PcapGlobalHeader] = None) -> None:
        self.filename = filename
        self._file: Optional[BinaryIO] = None
        self.global_header = global_header or PcapGlobalHeader()
        if filename:
            self.open(filename, self.global_header)

    def open(self, filename: str, global_header: Optional[PcapGlobalHeader] = None) -> bool:
        self.close()
        self.filename = filename
        if global_header:
            self.global_header = global_header

        try:
            self._file = open(filename, "wb")
        except OSError as e:
            print(f"Error: Could not open output file: {filename} ({e})")
            return False

        # Write 24-byte PCAP header
        header_bytes = struct.pack(
            "<IHHIIII",
            self.global_header.magic_number,
            self.global_header.version_major,
            self.global_header.version_minor,
            self.global_header.thiszone,
            self.global_header.sigfigs,
            self.global_header.snaplen,
            self.global_header.network,
        )
        self._file.write(header_bytes)
        return True

    def write_packet(self, data: bytes, ts_sec: int = 0, ts_usec: int = 0, orig_len: Optional[int] = None) -> None:
        """Write a packet given raw byte payload and timestamp."""
        if not self._file or self._file.closed:
            raise RuntimeError("PcapWriter is not open")

        if orig_len is None:
            orig_len = len(data)

        hdr_bytes = struct.pack("<IIII", ts_sec, ts_usec, len(data), orig_len)
        self._file.write(hdr_bytes)
        self._file.write(data)

    def write_raw_packet(self, raw: RawPacket) -> None:
        """Write a RawPacket directly."""
        self.write_packet(
            data=raw.data,
            ts_sec=raw.header.ts_sec,
            ts_usec=raw.header.ts_usec,
            orig_len=raw.header.orig_len,
        )

    def close(self) -> None:
        if self._file and not self._file.closed:
            self._file.flush()
            self._file.close()
        self._file = None

    def __enter__(self) -> PcapWriter:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()
