import unittest
import tempfile
import os
from dpi.engine import DPIEngine, DPIConfig
from dpi.pcap import PcapReader
from dpi.types import AppType


class TestDPIEngine(unittest.TestCase):
    def setUp(self):
        # Locate test_dpi.pcap in workspace
        candidates = [
            "test_dpi.pcap",
            "Packet_analyzer-main/test_dpi.pcap",
            "../test_dpi.pcap",
        ]
        self.pcap_path = None
        for c in candidates:
            if os.path.exists(c):
                self.pcap_path = os.path.abspath(c)
                break
        self.assertIsNotNone(self.pcap_path, "Could not find test_dpi.pcap")

    def test_full_pipeline_forward_all(self):
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
            out_pcap = tmp.name

        try:
            config = DPIConfig(num_load_balancers=2, fps_per_lb=2)
            engine = DPIEngine(config)
            self.assertTrue(engine.initialize())
            self.assertTrue(engine.process_file(self.pcap_path, out_pcap))

            reader = PcapReader(out_pcap)
            forwarded_packets = list(reader)
            reader.close()

            # Input has 77 packets, all should be forwarded when no rules block
            self.assertEqual(len(forwarded_packets), 77)
            self.assertEqual(engine.stats.dropped_packets, 0)
            self.assertEqual(engine.stats.forwarded_packets, 77)
        finally:
            if os.path.exists(out_pcap):
                os.remove(out_pcap)

    def test_pipeline_blocking_ip(self):
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
            out_pcap = tmp.name

        try:
            config = DPIConfig(num_load_balancers=2, fps_per_lb=2)
            engine = DPIEngine(config)
            engine.block_ip("192.168.1.50")
            self.assertTrue(engine.process_file(self.pcap_path, out_pcap))

            reader = PcapReader(out_pcap)
            forwarded_packets = list(reader)
            reader.close()

            # 5 packets from 192.168.1.50 should be dropped
            self.assertEqual(engine.stats.dropped_packets, 5)
            self.assertEqual(len(forwarded_packets), 72)
        finally:
            if os.path.exists(out_pcap):
                os.remove(out_pcap)

    def test_pipeline_blocking_app(self):
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
            out_pcap = tmp.name

        try:
            config = DPIConfig(num_load_balancers=2, fps_per_lb=2)
            engine = DPIEngine(config)
            engine.block_app(AppType.YOUTUBE)
            self.assertTrue(engine.process_file(self.pcap_path, out_pcap))

            self.assertGreater(engine.stats.dropped_packets, 0)
        finally:
            if os.path.exists(out_pcap):
                os.remove(out_pcap)


if __name__ == "__main__":
    unittest.main()
