"""
Vulnerability Scanner Module
Tests for SQL Injection, XSS, IDOR, SSRF, LFI, Command Injection, and XXE.
"""

import time
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urljoin

from src.core.config import Config
from src.core.logger import Logger
from src.core.http_client import HTTPClient
from src.core.models import Finding
from src.utils.url_parser import replace_parameter, set_all_params, normalize_url
from src.utils.payloads import (
    SQLI_PAYLOADS, SQLI_ERROR_PATTERNS,
    XSS_PAYLOADS,
    CMD_INJECTION_PAYLOADS, CMD_INJECTION_PATTERNS,
    LFI_PAYLOADS, LFI_PATTERNS,
    SSRF_PAYLOADS,
    XXE_PAYLOADS, XXE_PATTERNS,
    IDOR_ID_PATTERNS,
)


class VulnerabilityScanner:
    """Main vulnerability scanner that orchestrates all injection tests."""

    def __init__(self, http_client: HTTPClient, logger: Logger, config: Config):
        self.http_client = http_client
        self.logger = logger
        self.config = config
        self.time_threshold = config.get("vulnerability_scan", "time_threshold",
                                          default=5)
        self.max_payloads = config.get("vulnerability_scan", "max_payloads",
                                         default=100)

    def scan(self, base_url: str, endpoints: List[str],
             forms: List[Dict], params: Dict, recon_data: Dict) -> List[Finding]:
        """
        Run all vulnerability scans against the target.
        Returns a list of findings.
        """
        findings: List[Finding] = []

        # Collect all testable targets (URLs with params + forms)
        testable_urls = self._collect_testable_urls(base_url, endpoints)
        self.logger.info(f"Testing {len(testable_urls)} URLs and {len(forms)} forms "
                         f"for vulnerabilities")

        # SQL Injection
        if self.config.get("vulnerability_scan", "sqli", default=True):
            self.logger.info("Testing for SQL Injection...")
            findings.extend(self._test_sqli(testable_urls, forms))

        # XSS
        if self.config.get("vulnerability_scan", "xss", default=True):
            self.logger.info("Testing for Cross-Site Scripting (XSS)...")
            findings.extend(self._test_xss(testable_urls, forms))

        # Command Injection
        if self.config.get("vulnerability_scan", "command_injection", default=True):
            self.logger.info("Testing for Command Injection...")
            findings.extend(self._test_cmd_injection(testable_urls, forms))

        # LFI
        if self.config.get("vulnerability_scan", "lfi", default=True):
            self.logger.info("Testing for Local File Inclusion (LFI)...")
            findings.extend(self._test_lfi(testable_urls, forms))

        # SSRF
        if self.config.get("vulnerability_scan", "ssrf", default=True):
            self.logger.info("Testing for SSRF...")
            findings.extend(self._test_ssrf(testable_urls, forms))

        # IDOR
        if self.config.get("vulnerability_scan", "idor", default=True):
            self.logger.info("Testing for IDOR...")
            findings.extend(self._test_idor(testable_urls, forms))

        # XXE
        if self.config.get("vulnerability_scan", "xxe", default=True):
            self.logger.info("Testing for XXE...")
            findings.extend(self._test_xxe(testable_urls, forms))

        self.logger.success(f"Vulnerability scan complete. Found {len(findings)} issues.")
        return findings

    def _collect_testable_urls(self, base_url: str, endpoints: List[str]) -> List[str]:
        """Collect URLs that have query parameters for injection testing."""
        testable = []
        for url in endpoints:
            parsed = urlparse(url)
            if parsed.query:
                testable.append(url)

        # Also add base URL with common parameter names
        common_params = ["id", "page", "q", "search", "file", "url", "redirect",
                        "next", "path", "input", "name", "user", "username",
                        "cat", "category", "item", "product", "pid", "uid"]

        for param in common_params:
            test_url = f"{urlparse(base_url).path}?{param}=1"
            test_url = urljoin(base_url, test_url)
            if test_url not in testable:
                testable.append(test_url)

        return testable[:50]  # Limit for performance

    def _get_params(self, url: str) -> Dict[str, str]:
        """Extract parameters from a URL."""
        parsed = urlparse(url)
        return {k: v[0] if isinstance(v, list) else v
                for k, v in parse_qs(parsed.query).items()}

    def _test_sqli(self, urls: List[str], forms: List[Dict]) -> List[Finding]:
        """Test for SQL Injection vulnerabilities."""
        findings = []

        for url in urls:
            params = self._get_params(url)
            if not params:
                continue

            for param_name, original_value in params.items():
                found = False
                for payload in SQLI_PAYLOADS[:self.max_payloads]:
                    test_url = replace_parameter(url, param_name, payload)
                    response, error = self.http_client.get(test_url)

                    if error or not response:
                        continue

                    # Check for SQL error messages
                    text_lower = response.text.lower()
                    for pattern in SQLI_ERROR_PATTERNS:
                        if pattern.lower() in text_lower:
                            findings.append(Finding(
                                title=f"SQL Injection - Error Based ({param_name})",
                                severity="critical",
                                description=(
                                    f"SQL injection vulnerability detected in parameter "
                                    f"'{param_name}'. The application returns SQL error "
                                    f"messages, confirming the parameter is injectable."
                                ),
                                url=url,
                                parameter=param_name,
                                payload=payload,
                                evidence=f"SQL Error Pattern: {pattern}",
                                cwe_id="CWE-89",
                                owasp_category="A03:2021-Injection",
                                remediation=(
                                    "Use parameterized queries / prepared statements. "
                                    "Validate and sanitize all input. Never concatenate "
                                    "user input into SQL queries."
                                ),
                                references=[
                                    "https://owasp.org/www-community/attacks/SQL_Injection",
                                    "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                                ],
                            ))
                            found = True
                            break

                    if found:
                        break

                    # Time-based blind SQLi
                    if "sleep" in payload.lower() or "waitfor" in payload.lower():
                        start_time = time.time()
                        resp, _ = self.http_client.get(test_url)
                        elapsed = time.time() - start_time

                        if elapsed >= self.time_threshold:
                            findings.append(Finding(
                                title=f"SQL Injection - Time Based Blind ({param_name})",
                                severity="critical",
                                description=(
                                    f"Time-based blind SQL injection detected in parameter "
                                    f"'{param_name}'. Response was delayed by {elapsed:.1f}s "
                                    f"with payload that triggers a {self.time_threshold}s sleep."
                                ),
                                url=url,
                                parameter=param_name,
                                payload=payload,
                                evidence=f"Response time: {elapsed:.2f}s (threshold: {self.time_threshold}s)",
                                cwe_id="CWE-89",
                                owasp_category="A03:2021-Injection",
                                remediation=(
                                    "Use parameterized queries. Validate all input. "
                                    "Implement WAF rules for SQL injection patterns."
                                ),
                                references=[
                                    "https://portswigger.net/web-security/sql-injection/blind",
                                ],
                            ))
                            found = True
                            break

                if found:
                    break

        return findings

    def _test_xss(self, urls: List[str], forms: List[Dict]) -> List[Finding]:
        """Test for Cross-Site Scripting (XSS) vulnerabilities."""
        findings = []

        for url in urls:
            params = self._get_params(url)
            if not params:
                continue

            for param_name, original_value in params.items():
                found = False
                for payload in XSS_PAYLOADS[:self.max_payloads]:
                    test_url = replace_parameter(url, param_name, payload)
                    response, error = self.http_client.get(test_url)

                    if error or not response:
                        continue

                    # Check if payload is reflected unencoded in response
                    if payload in response.text:
                        # Verify it's not HTML-encoded
                        encoded = payload.replace("<", "&lt;").replace(">", "&gt;")
                        if encoded not in response.text:
                            findings.append(Finding(
                                title=f"Reflected XSS ({param_name})",
                                severity="high",
                                description=(
                                    f"Reflected XSS vulnerability detected in parameter "
                                    f"'{param_name}'. The payload is reflected in the "
                                    f"response without proper encoding."
                                ),
                                url=url,
                                parameter=param_name,
                                payload=payload,
                                evidence=f"Payload '{payload}' found unencoded in response body",
                                cwe_id="CWE-79",
                                owasp_category="A03:2021-Injection",
                                remediation=(
                                    "Encode all user input before rendering in HTML. "
                                    "Use Content-Security-Policy headers. "
                                    "Use framework's built-in output encoding."
                                ),
                                references=[
                                    "https://owasp.org/www-community/attacks/xss/",
                                    "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                                ],
                            ))
                            found = True
                            break

                if found:
                    break

        # Test forms for POST-based XSS
        for form in forms[:20]:
            action = form["action"]
            method = form["method"]
            for inp in form["inputs"]:
                if inp["type"] in ("submit", "button", "reset", "image"):
                    continue
                param_name = inp["name"]
                for payload in XSS_PAYLOADS[:20]:
                    data = {i["name"]: i["value"] for i in form["inputs"]
                            if i["name"]}
                    data[param_name] = payload

                    if method == "POST":
                        response, error = self.http_client.post(action, data=data)
                    else:
                        response, error = self.http_client.get(action, params=data)

                    if error or not response:
                        continue

                    if payload in response.text:
                        encoded = payload.replace("<", "&lt;").replace(">", "&gt;")
                        if encoded not in response.text:
                            findings.append(Finding(
                                title=f"Reflected XSS in Form ({param_name})",
                                severity="high",
                                description=(
                                    f"Reflected XSS via form submission in field "
                                    f"'{param_name}' at {action}."
                                ),
                                url=action,
                                parameter=param_name,
                                payload=payload,
                                evidence=f"Payload reflected in POST response",
                                cwe_id="CWE-79",
                                owasp_category="A03:2021-Injection",
                                remediation="Encode all output. Use CSP headers.",
                            ))
                            break

        return findings

    def _test_cmd_injection(self, urls: List[str], forms: List[Dict]) -> List[Finding]:
        """Test for OS Command Injection."""
        findings = []

        for url in urls:
            params = self._get_params(url)
            if not params:
                continue

            for param_name in params:
                found = False
                for payload in CMD_INJECTION_PAYLOADS[:30]:
                    test_url = replace_parameter(url, param_name, payload)
                    response, error = self.http_client.get(test_url)

                    if error or not response:
                        continue

                    text = response.text
                    for pattern in CMD_INJECTION_PATTERNS:
                        if pattern in text:
                            # Check if it was in original response
                            orig_response, _ = self.http_client.get(url)
                            if orig_response and pattern not in orig_response.text:
                                findings.append(Finding(
                                    title=f"OS Command Injection ({param_name})",
                                    severity="critical",
                                    description=(
                                        f"OS command injection detected in parameter "
                                        f"'{param_name}'. The payload executed system "
                                        f"commands and returned output."
                                    ),
                                    url=url,
                                    parameter=param_name,
                                    payload=payload,
                                    evidence=f"Pattern '{pattern}' found in response after injection",
                                    cwe_id="CWE-78",
                                    owasp_category="A03:2021-Injection",
                                    remediation=(
                                        "Use parameterized APIs instead of shell commands. "
                                        "Validate input against allowlist. "
                                        "Escape shell metacharacters if shell is necessary."
                                    ),
                                    references=[
                                        "https://owasp.org/www-community/attacks/Command_Injection",
                                    ],
                                ))
                                found = True
                                break
                    if found:
                        break
                if found:
                    break

        return findings

    def _test_lfi(self, urls: List[str], forms: List[Dict]) -> List[Finding]:
        """Test for Local File Inclusion."""
        findings = []

        for url in urls:
            params = self._get_params(url)
            if not params:
                continue

            for param_name in params:
                found = False
                for payload in LFI_PAYLOADS[:20]:
                    test_url = replace_parameter(url, param_name, payload)
                    response, error = self.http_client.get(test_url)

                    if error or not response:
                        continue

                    for pattern in LFI_PATTERNS:
                        if pattern in response.text:
                            # Verify not in original
                            orig_response, _ = self.http_client.get(url)
                            if orig_response and pattern not in orig_response.text:
                                findings.append(Finding(
                                    title=f"Local File Inclusion ({param_name})",
                                    severity="critical",
                                    description=(
                                        f"Local File Inclusion vulnerability in parameter "
                                        f"'{param_name}'. Successfully read system files "
                                        f"using path traversal."
                                    ),
                                    url=url,
                                    parameter=param_name,
                                    payload=payload,
                                    evidence=f"Pattern '{pattern}' found in response",
                                    cwe_id="CWE-22",
                                    owasp_category="A01:2021-Broken Access Control",
                                    remediation=(
                                        "Validate and sanitize file paths. Use allowlist. "
                                        "Store files outside webroot. Use chroot jails."
                                    ),
                                    references=[
                                        "https://owasp.org/www-community/attacks/Path_Traversal",
                                    ],
                                ))
                                found = True
                                break
                    if found:
                        break
                if found:
                    break

        return findings

    def _test_ssrf(self, urls: List[str], forms: List[Dict]) -> List[Finding]:
        """Test for Server-Side Request Forgery."""
        findings = []

        # SSRF is typically found in URL-type parameters
        ssrf_prone_params = ["url", "redirect", "next", "path", "file",
                           "image", "callback", "proxy", "fetch", "host",
                           "site", "uri", "reference", "return", "target"]

        for url in urls:
            params = self._get_params(url)
            if not params:
                continue

            for param_name in params:
                if param_name.lower() not in ssrf_prone_params:
                    continue

                for payload in SSRF_PAYLOADS[:10]:
                    test_url = replace_parameter(url, param_name, payload)
                    response, error = self.http_client.get(test_url)

                    if error or not response:
                        continue

                    # Check for signs of successful SSRF
                    text_lower = response.text.lower()
                    indicators = [
                        "root:x:",          # /etc/passwd
                        "root:0:0:",        # passwd format
                        "[extensions]",     # win.ini
                        "[fonts]",          # win.ini
                        "instance-id",      # AWS metadata
                        "ami-id",           # AWS metadata
                        "security-credentials", # AWS metadata
                        "computeMetadata",  # GCP metadata
                    ]

                    for indicator in indicators:
                        if indicator in text_lower:
                            findings.append(Finding(
                                title=f"Server-Side Request Forgery ({param_name})",
                                severity="critical",
                                description=(
                                    f"SSRF vulnerability in parameter '{param_name}'. "
                                    f"The server made an external/internal request "
                                    f"based on user input."
                                ),
                                url=url,
                                parameter=param_name,
                                payload=payload,
                                evidence=f"Indicator '{indicator}' found in response",
                                cwe_id="CWE-918",
                                owasp_category="A10:2021-SSRF",
                                remediation=(
                                    "Validate and sanitize URLs. Use allowlist of "
                                    "permitted domains/IPs. Block internal IPs and "
                                    "cloud metadata endpoints."
                                ),
                                references=[
                                    "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
                                ],
                            ))
                            break

        return findings

    def _test_idor(self, urls: List[str], forms: List[Dict]) -> List[Finding]:
        """Test for Insecure Direct Object Reference (IDOR)."""
        findings = []

        for url in urls:
            params = self._get_params(url)
            if not params:
                continue

            for param_name, original_value in params.items():
                # Only test numeric or ID-like parameters
                if param_name.lower() not in ("id", "uid", "pid", "user",
                    "user_id", "userid", "account", "doc", "docid",
                    "order", "orderid", "item", "itemid", "page", "p"):
                    continue

                # Get baseline response
                baseline_response, _ = self.http_client.get(url)
                if not baseline_response:
                    continue
                baseline_status = baseline_response.status_code
                baseline_length = len(baseline_response.text)

                # Try different IDs
                for test_id in IDOR_ID_PATTERNS:
                    if str(test_id) == str(original_value):
                        continue

                    test_url = replace_parameter(url, param_name, str(test_id))
                    response, error = self.http_client.get(test_url)

                    if error or not response:
                        continue

                    # If we get a 200 with different content, it might be IDOR
                    if (response.status_code == 200 and
                        len(response.text) > 100 and
                        len(response.text) != baseline_length and
                        abs(len(response.text) - baseline_length) > 50):

                        findings.append(Finding(
                            title=f"IDOR - {param_name} ({url})",
                            severity="high",
                            description=(
                                f"Potential IDOR in parameter '{param_name}'. "
                                f"Changing value from '{original_value}' to '{test_id}' "
                                f"returned a different valid response (200 OK with "
                                f"different content length)."
                            ),
                            url=url,
                            parameter=param_name,
                            payload=str(test_id),
                            evidence=(
                                f"Original length: {baseline_length}, "
                                f"Modified length: {len(response.text)}, "
                                f"Both returned HTTP 200"
                            ),
                            cwe_id="CWE-639",
                            owasp_category="A01:2021-Broken Access Control",
                            remediation=(
                                "Implement proper authorization checks. Verify that "
                                "the current user has permission to access the requested "
                                "resource. Use indirect reference maps."
                            ),
                            references=[
                                "https://owasp.org/www-project-vulnerable-web-applications-directory/idor/",
                            ],
                        ))
                        break

        return findings

    def _test_xxe(self, urls: List[str], forms: List[Dict]) -> List[Finding]:
        """Test for XML External Entity (XXE) injection."""
        findings = []

        # XXE typically occurs in XML POST endpoints
        # Test endpoints that accept XML content type
        for url in urls[:15]:
            for payload in XXE_PAYLOADS[:5]:
                headers = {"Content-Type": "application/xml", "Accept": "*/*"}

                response, error = self.http_client.post(
                    url, data=payload, headers=headers
                )

                if error or not response:
                    continue

                for pattern in XXE_PATTERNS:
                    if pattern in response.text:
                        findings.append(Finding(
                            title=f"XML External Entity (XXE) Injection",
                            severity="critical",
                            description=(
                                f"XXE vulnerability detected at {url}. "
                                f"The XML parser processes external entities, "
                                f"allowing file reading and SSRF."
                            ),
                            url=url,
                            payload=payload,
                            evidence=f"Pattern '{pattern}' found in XML response",
                            cwe_id="CWE-611",
                            owasp_category="A05:2021-Security Misconfiguration",
                            remediation=(
                                "Disable external entity processing in XML parser. "
                                "Use JSON instead of XML where possible. "
                                "Validate XML against schema."
                            ),
                            references=[
                                "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
                            ],
                        ))
                        break

        return findings
