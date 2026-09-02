"""
Unit tests for the pipeline penetration tester modules.
Run with: python -m pytest tests/ -v
"""

import unittest
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestConfig(unittest.TestCase):
    """Test configuration loading."""

    def test_config_creation(self):
        from src.core.config import Config
        config = Config()
        self.assertIsNotNone(config)

    def test_default_values(self):
        from src.core.config import Config
        config = Config()
        self.assertEqual(config.get("pipeline", "parallel_workers", default=10), 10)
        self.assertEqual(config.get("network", "timeout", default=15), 15)

    def test_yaml_loading(self):
        """Test loading from the actual config file."""
        from src.core.config import Config
        config_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "config", "config.yaml"
        )
        if os.path.exists(config_path):
            config = Config(config_path)
            self.assertEqual(config.get("target", "url"), "http://testphp.vulnweb.com")


class TestPayloads(unittest.TestCase):
    """Test payload database."""

    def test_sqli_payloads_exist(self):
        from src.utils.payloads import SQLI_PAYLOADS
        self.assertGreater(len(SQLI_PAYLOADS), 10)
        self.assertIn("'", SQLI_PAYLOADS)

    def test_xss_payloads_exist(self):
        from src.utils.payloads import XSS_PAYLOADS
        self.assertGreater(len(XSS_PAYLOADS), 10)
        self.assertIn("<script>alert(1)</script>", XSS_PAYLOADS)

    def test_lfi_payloads_exist(self):
        from src.utils.payloads import LFI_PAYLOADS
        self.assertGreater(len(LFI_PAYLOADS), 5)
        self.assertIn("../../../etc/passwd", LFI_PAYLOADS)

    def test_sqli_patterns_exist(self):
        from src.utils.payloads import SQLI_ERROR_PATTERNS
        self.assertGreater(len(SQLI_ERROR_PATTERNS), 5)
        self.assertIn("sql syntax", SQLI_ERROR_PATTERNS)

    def test_cmd_injection_payloads(self):
        from src.utils.payloads import CMD_INJECTION_PAYLOADS
        self.assertGreater(len(CMD_INJECTION_PAYLOADS), 10)

    def test_ssrf_payloads(self):
        from src.utils.payloads import SSRF_PAYLOADS
        self.assertGreater(len(SSRF_PAYLOADS), 5)
        self.assertIn("http://127.0.0.1", SSRF_PAYLOADS)

    def test_default_creds(self):
        from src.utils.payloads import DEFAULT_CREDS
        self.assertGreater(len(DEFAULT_CREDS), 5)
        self.assertIn(("admin", "admin"), DEFAULT_CREDS)


class TestUrlParser(unittest.TestCase):
    """Test URL parsing utilities."""

    def test_extract_parameters(self):
        from src.utils.url_parser import extract_parameters
        params = extract_parameters("http://example.com/page?id=1&name=test")
        self.assertEqual(params["id"], "1")
        self.assertEqual(params["name"], "test")

    def test_replace_parameter(self):
        from src.utils.url_parser import replace_parameter
        new_url = replace_parameter("http://example.com/page?id=1", "id", "999")
        self.assertIn("id=999", new_url)

    def test_extract_base_url(self):
        from src.utils.url_parser import extract_base_url
        base = extract_base_url("http://example.com/page?id=1")
        self.assertEqual(base, "http://example.com")

    def test_is_valid_url(self):
        from src.utils.url_parser import is_valid_url
        self.assertTrue(is_valid_url("http://example.com"))
        self.assertTrue(is_valid_url("https://example.com/page"))
        self.assertFalse(is_valid_url("not_a_url"))
        self.assertFalse(is_valid_url(""))

    def test_normalize_url(self):
        from src.utils.url_parser import normalize_url
        self.assertEqual(
            normalize_url("http://example.com/page/"),
            "http://example.com/page"
        )
        self.assertEqual(
            normalize_url("http://example.com/"),
            "http://example.com/"
        )

    def test_parse_html_forms(self):
        from src.utils.url_parser import parse_html_forms
        html = '<form action="/login" method="post"><input name="user" type="text"><input name="pass" type="password"></form>'
        forms = parse_html_forms(html, "http://example.com")
        self.assertEqual(len(forms), 1)
        self.assertEqual(forms[0]["action"], "http://example.com/login")
        self.assertEqual(forms[0]["method"], "POST")
        self.assertEqual(len(forms[0]["inputs"]), 2)

    def test_extract_links(self):
        from src.utils.url_parser import extract_links
        html = '<a href="/page1">Link 1</a><a href="http://example.com/page2">Link 2</a><a href="#anchor">Skip</a>'
        links = extract_links(html, "http://example.com")
        self.assertIn("http://example.com/page1", links)
        self.assertIn("http://example.com/page2", links)
        self.assertNotIn("#anchor", links)


class TestModels(unittest.TestCase):
    """Test data models."""

    def test_finding_creation(self):
        from src.core.models import Finding
        f = Finding(
            title="Test Vuln",
            severity="high",
            description="A test vulnerability",
            url="http://example.com",
            cwe_id="CWE-79",
        )
        self.assertEqual(f.title, "Test Vuln")
        self.assertEqual(f.severity, "high")

    def test_scan_result(self):
        from src.core.models import ScanResult, Finding
        result = ScanResult(target_url="http://example.com")
        self.assertEqual(result.target_url, "http://example.com")
        self.assertEqual(len(result.findings), 0)

        f = Finding(title="Test", severity="critical",
                    description="Test", url="http://example.com")
        result.add_finding(f)
        self.assertTrue(result.has_critical())
        self.assertEqual(result.get_summary()["critical"], 1)
        self.assertEqual(result.get_summary()["total"], 1)

    def test_finding_to_dict(self):
        from src.core.models import Finding
        f = Finding(title="Test", severity="high",
                    description="Test", url="http://example.com")
        d = f.to_dict()
        self.assertEqual(d["title"], "Test")
        self.assertEqual(d["severity"], "high")


class TestHTTPClient(unittest.TestCase):
    """Test HTTP client (basic tests without network)."""

    def test_client_creation(self):
        from src.core.http_client import HTTPClient
        from src.core.logger import Logger
        logger = Logger("DEBUG", "output/test.log", console=False)
        client = HTTPClient({
            "user_agent": "Test",
            "timeout": 5,
            "delay": 0,
            "max_retries": 1,
            "verify_ssl": False,
            "follow_redirects": True,
        }, logger)
        self.assertIsNotNone(client)
        client.close()

    def test_is_same_domain(self):
        from src.core.http_client import HTTPClient
        self.assertTrue(HTTPClient.is_same_domain(
            "http://example.com/a", "http://example.com/b"
        ))
        self.assertFalse(HTTPClient.is_same_domain(
            "http://example.com/a", "http://other.com/b"
        ))

    def test_get_domain(self):
        from src.core.http_client import HTTPClient
        self.assertEqual(
            HTTPClient.get_domain("http://sub.example.com/path"),
            "sub.example.com"
        )


if __name__ == "__main__":
    unittest.main()
