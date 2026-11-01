import unittest
from dpi.extractors import SNIExtractor, HTTPHostExtractor, DNSExtractor
from dpi.types import sni_to_app_type, AppType


class TestExtractors(unittest.TestCase):
    def test_sni_app_mapping(self):
        self.assertEqual(sni_to_app_type("www.youtube.com"), AppType.YOUTUBE)
        self.assertEqual(sni_to_app_type("youtu.be"), AppType.YOUTUBE)
        self.assertEqual(sni_to_app_type("www.google.com"), AppType.GOOGLE)
        self.assertEqual(sni_to_app_type("www.facebook.com"), AppType.FACEBOOK)
        self.assertEqual(sni_to_app_type("instagram.com"), AppType.INSTAGRAM)
        self.assertEqual(sni_to_app_type("twitter.com"), AppType.TWITTER)
        self.assertEqual(sni_to_app_type("x.com"), AppType.TWITTER)
        self.assertEqual(sni_to_app_type("github.com"), AppType.GITHUB)
        self.assertEqual(sni_to_app_type("discord.com"), AppType.DISCORD)
        self.assertEqual(sni_to_app_type("open.spotify.com"), AppType.SPOTIFY)
        self.assertEqual(sni_to_app_type("randomdomain.net"), AppType.HTTPS)
        self.assertEqual(sni_to_app_type(""), AppType.UNKNOWN)

    def test_http_host_extractor(self):
        req = b"GET /index.html HTTP/1.1\r\nHost: example.com:8080\r\nUser-Agent: test\r\n\r\n"
        host = HTTPHostExtractor.extract(req)
        self.assertEqual(host, "example.com")

        req2 = b"POST /api HTTP/1.1\r\nhost:   myapi.org   \r\n\r\n"
        host2 = HTTPHostExtractor.extract(req2)
        self.assertEqual(host2, "myapi.org")

        non_http = b"HELLO THIS IS NOT HTTP"
        self.assertIsNone(HTTPHostExtractor.extract(non_http))

    def test_dns_extractor(self):
        # Query for "example.com"
        txid = b"\x12\x34"
        flags = b"\x01\x00"  # Standard query
        counts = b"\x00\x01\x00\x00\x00\x00\x00\x00"
        query = b"\x07example\x03com\x00\x00\x01\x00\x01"
        payload = txid + flags + counts + query

        domain = DNSExtractor.extract_query(payload)
        self.assertEqual(domain, "example.com")

        # Response packet (QR bit set) should be ignored
        resp_payload = txid + b"\x81\x80" + counts + query
        self.assertIsNone(DNSExtractor.extract_query(resp_payload))


if __name__ == "__main__":
    unittest.main()
