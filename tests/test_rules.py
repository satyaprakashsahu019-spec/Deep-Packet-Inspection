import unittest
import tempfile
import os
from dpi.rules import RuleManager, BlockingRules
from dpi.types import AppType


class TestRules(unittest.TestCase):
    def test_rule_manager_ip(self):
        rm = RuleManager()
        rm.block_ip("192.168.1.50")
        self.assertTrue(rm.is_ip_blocked("192.168.1.50"))
        self.assertFalse(rm.is_ip_blocked("192.168.1.51"))

        reason = rm.should_block("192.168.1.50", 443, AppType.HTTPS, "example.com")
        self.assertIsNotNone(reason)
        self.assertEqual(reason.reason_type, "IP")
        self.assertEqual(reason.detail, "192.168.1.50")

    def test_rule_manager_app(self):
        rm = RuleManager()
        rm.block_app(AppType.YOUTUBE)
        self.assertTrue(rm.is_app_blocked(AppType.YOUTUBE))
        self.assertFalse(rm.is_app_blocked(AppType.FACEBOOK))

        reason = rm.should_block("10.0.0.1", 443, AppType.YOUTUBE, "www.youtube.com")
        self.assertIsNotNone(reason)
        self.assertEqual(reason.reason_type, "APP")

    def test_rule_manager_domain_wildcard(self):
        rm = RuleManager()
        rm.block_domain("*.tiktok.com")
        rm.block_domain("facebook.com")

        self.assertTrue(rm.is_domain_blocked("www.tiktok.com"))
        self.assertTrue(rm.is_domain_blocked("tiktok.com"))
        self.assertTrue(rm.is_domain_blocked("api.tiktok.com"))
        self.assertFalse(rm.is_domain_blocked("nottiktok.com.br"))

        self.assertTrue(rm.is_domain_blocked("www.facebook.com"))
        self.assertFalse(rm.is_domain_blocked("google.com"))

    def test_rule_persistence(self):
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            rm1 = RuleManager()
            rm1.block_ip("1.2.3.4")
            rm1.block_app(AppType.TWITTER)
            rm1.block_domain("*.badsite.org")
            rm1.block_port(8080)
            self.assertTrue(rm1.save_rules(tmp_path))

            rm2 = RuleManager()
            self.assertTrue(rm2.load_rules(tmp_path))
            self.assertTrue(rm2.is_ip_blocked("1.2.3.4"))
            self.assertTrue(rm2.is_app_blocked(AppType.TWITTER))
            self.assertTrue(rm2.is_domain_blocked("sub.badsite.org"))
            self.assertTrue(rm2.is_port_blocked(8080))
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_blocking_rules_compat(self):
        br = BlockingRules()
        br.block_app("YouTube")
        br.block_ip("192.168.1.10")
        br.block_domain("netflix")

        self.assertTrue(br.is_blocked("192.168.1.10", AppType.HTTP, ""))
        self.assertTrue(br.is_blocked("192.168.1.1", AppType.YOUTUBE, "www.youtube.com"))
        self.assertTrue(br.is_blocked("192.168.1.1", AppType.HTTPS, "www.netflix.com"))
        self.assertFalse(br.is_blocked("192.168.1.1", AppType.GOOGLE, "www.google.com"))


if __name__ == "__main__":
    unittest.main()
