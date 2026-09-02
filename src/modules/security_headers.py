"""
Security Headers Checker Module
Tests for missing or misconfigured security headers.
Also checks for common misconfigurations like CORS, HTTP methods, etc.
"""

from typing import List
from urllib.parse import urljoin

from src.core.config import Config
from src.core.logger import Logger
from src.core.http_client import HTTPClient
from src.core.models import Finding


class SecurityHeadersChecker:
    """Check security headers and common misconfigurations."""

    # Security headers to check with their severity if missing
    SECURITY_HEADERS = {
        "Content-Security-Policy": {
            "severity": "medium",
            "cwe": "CWE-693",
            "description": "Missing Content-Security-Policy header. CSP prevents "
                          "XSS, clickjacking, and other code injection attacks by "
                          "restricting resource sources.",
            "remediation": "Implement a strict Content-Security-Policy header that "
                          "restricts script sources and prevents inline scripts.",
        },
        "Strict-Transport-Security": {
            "severity": "medium",
            "cwe": "CWE-319",
            "description": "Missing HSTS header. Without HSTS, the connection is "
                          "vulnerable to SSL stripping attacks.",
            "remediation": "Set 'Strict-Transport-Security: max-age=31536000; "
                          "includeSubDomains; preload'.",
        },
        "X-Frame-Options": {
            "severity": "low",
            "cwe": "CWE-1021",
            "description": "Missing X-Frame-Options header. The page can be embedded "
                          "in an iframe, enabling clickjacking attacks.",
            "remediation": "Set 'X-Frame-Options: DENY' or 'SAMEORIGIN'. "
                          "Or use CSP 'frame-ancestors' directive.",
        },
        "X-Content-Type-Options": {
            "severity": "low",
            "cwe": "CWE-79",
            "description": "Missing X-Content-Type-Options header. Without it, "
                          "browsers may MIME-sniff content types.",
            "remediation": "Set 'X-Content-Type-Options: nosniff'.",
        },
        "Referrer-Policy": {
            "severity": "low",
            "cwe": "CWE-200",
            "description": "Missing Referrer-Policy header. The full URL may be "
                          "leaked to external sites via the Referer header.",
            "remediation": "Set 'Referrer-Policy: strict-origin-when-cross-origin'.",
        },
        "Permissions-Policy": {
            "severity": "low",
            "cwe": "CWE-693",
            "description": "Missing Permissions-Policy header. Browser features "
                          "(camera, microphone, etc.) can be accessed by the page.",
            "remediation": "Set 'Permissions-Policy: camera=(), microphone=(), "
                          "geolocation=()'.",
        },
    }

    def __init__(self, http_client: HTTPClient, logger: Logger, config: Config):
        self.http_client = http_client
        self.logger = logger
        self.config = config

    def check(self, target_url: str) -> List[Finding]:
        """Run security header checks and misconfiguration tests."""
        findings = []
        self.logger.info("Checking security headers...")

        # Get response to check headers
        response, error = self.http_client.get(target_url)
        if error or not response:
            self.logger.warning(f"Cannot check headers - connection error: {error}")
            return findings

        headers = response.headers

        # Check each security header
        for header_name, info in self.SECURITY_HEADERS.items():
            if self.config.get("security_headers",
                               f"check_{header_name.lower().replace('-', '_')}",
                               default=True):
                if header_name not in headers:
                    findings.append(Finding(
                        title=f"Missing Security Header: {header_name}",
                        severity=info["severity"],
                        description=info["description"],
                        url=target_url,
                        cwe_id=info["cwe"],
                        owasp_category="A05:2021-Security Misconfiguration",
                        remediation=info["remediation"],
                        references=[
                            "https://owasp.org/www-project-secure-headers/",
                        ],
                    ))
                    self.logger.finding(info["severity"],
                                        f"Missing header: {header_name}")
                else:
                    self.logger.debug(f"Header present: {header_name}")

        # Check for information disclosure headers
        info_disclosure_headers = {
            "Server": "Server version disclosed",
            "X-Powered-By": "Technology stack disclosed",
            "X-AspNet-Version": "ASP.NET version disclosed",
            "X-AspNetMvc-Version": "ASP.NET MVC version disclosed",
            "Via": "Proxy/CDN information disclosed",
        }

        for header, desc in info_disclosure_headers.items():
            if header in headers:
                findings.append(Finding(
                    title=f"Information Disclosure: {header}",
                    severity="info",
                    description=f"{desc}. Value: '{headers[header]}'. This helps "
                                f"attackers target specific vulnerabilities.",
                    url=target_url,
                    evidence=f"{header}: {headers[header]}",
                    cwe_id="CWE-200",
                    owasp_category="A05:2021-Security Misconfiguration",
                    remediation=f"Remove or obscure the '{header}' header.",
                ))
                self.logger.finding("info", f"Info disclosure: {header}: {headers[header]}")

        # Check for cookie security
        findings.extend(self._check_cookies(target_url, response))

        # Check CORS configuration
        findings.extend(self._check_cors(target_url))

        # Check allowed HTTP methods
        findings.extend(self._check_http_methods(target_url))

        # Check for directory listing
        findings.extend(self._check_directory_listing(target_url))

        # Check for .git exposure
        findings.extend(self._check_git_exposure(target_url))

        # Check for .env exposure
        findings.extend(self._check_env_exposure(target_url))

        self.logger.success(f"Security headers check complete. "
                            f"Found {len(findings)} issues.")
        return findings

    def _check_cookies(self, url: str, response) -> List[Finding]:
        """Check cookie security flags."""
        findings = []
        for cookie in response.cookies:
            issues = []
            if not cookie.secure:
                issues.append("Secure flag not set")
            if not cookie.has_nonstandard_attr("HttpOnly"):
                issues.append("HttpOnly flag not set")
            if not cookie.has_nonstandard_attr("SameSite"):
                issues.append("SameSite flag not set")

            if issues:
                findings.append(Finding(
                    title=f"Insecure Cookie: {cookie.name}",
                    severity="medium" if "HttpOnly" in " ".join(issues) else "low",
                    description=f"Cookie '{cookie.name}' has security issues: "
                                f"{', '.join(issues)}.",
                    url=url,
                    evidence=f"Cookie: {cookie.name}, Issues: {', '.join(issues)}",
                    cwe_id="CWE-614",
                    owasp_category="A05:2021-Security Misconfiguration",
                    remediation="Set Secure, HttpOnly, and SameSite=Strict/ Lax "
                                "flags on all cookies.",
                ))
        return findings

    def _check_cors(self, url: str) -> List[Finding]:
        """Check CORS configuration."""
        findings = []

        # Test with Origin header
        headers = {"Origin": "https://evil.com"}
        response, error = self.http_client.get(url, headers=headers)

        if error or not response:
            return findings

        acao = response.headers.get("Access-Control-Allow-Origin", "")
        acac = response.headers.get("Access-Control-Allow-Credentials", "")

        if acao == "*" and acac.lower() == "true":
            findings.append(Finding(
                title="Dangerous CORS Configuration",
                severity="high",
                description="CORS is configured with 'Access-Control-Allow-Origin: *' "
                            "AND 'Access-Control-Allow-Credentials: true'. This allows "
                            "any website to read responses with credentials.",
                url=url,
                evidence=f"ACAO: {acao}, ACAC: {acac}",
                cwe_id="CWE-942",
                owasp_category="A05:2021-Security Misconfiguration",
                remediation="Use specific allowed origins. Do not use '*' with "
                            "credentials.",
            ))
        elif acao == "https://evil.com":
            findings.append(Finding(
                title="CORS Allows Arbitrary Origins",
                severity="high",
                description="CORS reflects the Origin header, allowing any origin to "
                            "access resources. This is a security risk.",
                url=url,
                evidence=f"ACAO reflected: {acao}",
                cwe_id="CWE-942",
                owasp_category="A05:2021-Security Misconfiguration",
                remediation="Validate Origin against an allowlist of trusted domains.",
            ))
        elif acao and acao != "":
            self.logger.debug(f"CORS configured with origin: {acao}")

        return findings

    def _check_http_methods(self, url: str) -> List[Finding]:
        """Check allowed HTTP methods using OPTIONS."""
        findings = []

        response, error = self.http_client.options(url)
        if error or not response:
            return findings

        allow = response.headers.get("Allow", "")
        if allow:
            dangerous_methods = []
            for method in ["PUT", "DELETE", "TRACE", "CONNECT", "PATCH"]:
                if method in allow.upper():
                    dangerous_methods.append(method)

            if dangerous_methods:
                findings.append(Finding(
                    title="Dangerous HTTP Methods Allowed",
                    severity="medium",
                    description=f"The server allows potentially dangerous HTTP methods: "
                                f"{', '.join(dangerous_methods)}.",
                    url=url,
                    evidence=f"Allow header: {allow}",
                    cwe_id="CWE-650",
                    owasp_category="A05:2021-Security Misconfiguration",
                    remediation="Disable unnecessary HTTP methods. Only allow GET, "
                                "POST, HEAD for standard web applications.",
                ))

            if "TRACE" in allow.upper():
                findings.append(Finding(
                    title="HTTP TRACE Method Enabled",
                    severity="medium",
                    description="HTTP TRACE method is enabled, which can be used for "
                                "Cross-Site Tracing (XST) attacks.",
                    url=url,
                    evidence=f"Allow: {allow}",
                    cwe_id="CWE-650",
                    remediation="Disable the TRACE method on the web server.",
                ))

        return findings

    def _check_directory_listing(self, url: str) -> List[Finding]:
        """Check for directory listing on common paths."""
        findings = []
        check_paths = ["/", "/uploads/", "/static/", "/assets/", "/files/",
                       "/images/", "/media/", "/data/"]

        for path in check_paths:
            test_url = urljoin(url + "/", path)
            response, error = self.http_client.get(test_url, timeout=5)
            if error or not response:
                continue

            if response.status_code == 200:
                text = response.text.lower()
                if "index of" in text or "directory listing" in text:
                    findings.append(Finding(
                        title=f"Directory Listing Enabled ({path})",
                        severity="medium",
                        description=f"Directory listing is enabled at {test_url}, "
                                    f"exposing all files in the directory.",
                        url=test_url,
                        evidence="'Index of' or 'Directory listing' found in response",
                        cwe_id="CWE-538",
                        owasp_category="A05:2021-Security Misconfiguration",
                        remediation="Disable directory listing on the web server. "
                                    "Add 'Options -Indexes' in Apache or equivalent.",
                    ))
                    break

        return findings

    def _check_git_exposure(self, url: str) -> List[Finding]:
        """Check for exposed .git directory."""
        findings = []

        git_paths = ["/.git/config", "/.git/HEAD"]
        for path in git_paths:
            test_url = urljoin(url, path)
            response, error = self.http_client.get(test_url, timeout=5)
            if error or not response:
                continue

            if response.status_code == 200:
                if "core" in response.text or "repositoryformatversion" in response.text:
                    findings.append(Finding(
                        title="Git Repository Exposed",
                        severity="critical",
                        description="The .git directory is accessible via web. "
                                    "This exposes the entire source code repository, "
                                    "including history, credentials, and secrets.",
                        url=test_url,
                        evidence=response.text[:200],
                        cwe_id="CWE-538",
                        owasp_category="A05:2021-Security Misconfiguration",
                        remediation="Block access to .git directory in web server "
                                    "configuration. Remove it from the webroot.",
                    ))
                    break

        return findings

    def _check_env_exposure(self, url: str) -> List[Finding]:
        """Check for exposed .env files."""
        findings = []

        env_paths = ["/.env", "/.env.local", "/.env.production",
                     "/config/.env", "/app/.env"]
        for path in env_paths:
            test_url = urljoin(url, path)
            response, error = self.http_client.get(test_url, timeout=5)
            if error or not response:
                continue

            if response.status_code == 200:
                if "=" in response.text and any(
                    kw in response.text.upper()
                    for kw in ["DB_", "APP_", "SECRET", "KEY", "PASSWORD", "TOKEN"]
                ):
                    findings.append(Finding(
                        title="Environment File Exposed",
                        severity="critical",
                        description="An .env file containing environment variables "
                                    "(potentially secrets, API keys, database "
                                    "credentials) is accessible via web.",
                        url=test_url,
                        evidence=response.text[:300],
                        cwe_id="CWE-538",
                        owasp_category="A05:2021-Security Misconfiguration",
                        remediation="Block access to .env files. Move them outside "
                                    "the webroot.",
                    ))
                    break

        return findings
