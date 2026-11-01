import unittest
import tempfile
import os
from dpi.pcap import PcapReader, PcapWriter, PcapGlobalHeader, RawPacket, PcapPacketHeader


class TestPcap(unittest.TestCase):
    def test_write_and_read(self):
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            # Write a small PCAP file
            writer = PcapWriter(tmp_path)
            test_packet_1 = b"\x00\x11\x22\x33\x44\x55" + b"\xaa\xbb\xcc\xdd\xee\xff" + b"\x08\x00" + b"Hello World!"
            test_packet_2 = b"\x00\x11\x22\x33\x44\x55" + b"\xaa\xbb\xcc\xdd\xee\xff" + b"\x08\x00" + b"Second Packet!"

            writer.write_packet(test_packet_1, ts_sec=1700000000, ts_usec=123456)
            writer.write_packet(test_packet_2, ts_sec=1700000001, ts_usec=654321)
            writer.close()

            # Read back
            reader = PcapReader(tmp_path)
            self.assertTrue(reader.is_open)
            self.assertEqual(reader.global_header.version_major, 2)
            self.assertEqual(reader.global_header.version_minor, 4)

            packets = list(reader)
            self.assertEqual(len(packets), 2)

            self.assertEqual(packets[0].data, test_packet_1)
            self.assertEqual(packets[0].header.ts_sec, 1700000000)
            self.assertEqual(packets[0].header.ts_usec, 123456)

            self.assertEqual(packets[1].data, test_packet_2)
            self.assertEqual(packets[1].header.ts_sec, 1700000001)
            self.assertEqual(packets[1].header.ts_usec, 654321)

            reader.close()
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)


if __name__ == "__main__":
    unittest.main()
