"""
Authentication & Session Testing Module
Tests for session fixation, weak password policies, default credentials,
session timeout, and authentication bypass.
"""

import time
import re
from typing import List, Dict
from urllib.parse import urljoin, urlparse

from src.core.config import Config
from src.core.logger import Logger
from src.core.http_client import HTTPClient
from src.core.models import Finding
from src.utils.url_parser import parse_html_forms
from src.utils.payloads import DEFAULT_CREDS


class AuthTestingModule:
    """Test authentication and session management security."""

    def __init__(self, http_client: HTTPClient, logger: Logger, config: Config):
        self.http_client = http_client
        self.logger = logger
        self.config = config

    def test(self, target_url: str, recon_data: Dict) -> List[Finding]:
        """Run all authentication and session tests."""
        findings = []
        self.logger.info("Testing authentication and session management...")

        # Find login forms
        login_forms = self._find_login_forms(target_url, recon_data)

        if self.config.get("auth_testing", "test_session_fixation", default=True):
            findings.extend(self._test_session_fixation(target_url))

        if self.config.get("auth_testing", "test_session_timeout", default=True):
            findings.extend(self._test_session_timeout(target_url))

        if self.config.get("auth_testing", "test_default_creds", default=True) and login_forms:
            findings.extend(self._test_default_credentials(login_forms))

        if self.config.get("auth_testing", "test_weak_password", default=True) and login_forms:
            findings.extend(self._test_weak_password_policy(login_forms))

        # Check for authentication bypass
        findings.extend(self._test_auth_bypass(target_url, login_forms))

        self.logger.success(f"Auth testing complete. Found {len(findings)} issues.")
        return findings

    def _find_login_forms(self, target_url: str, recon_data: Dict) -> List[Dict]:
        """Find login forms from recon data or by checking common paths."""
        login_forms = []

        # Check forms discovered during recon
        for form in recon_data.get("discovered_forms", []):
            inputs = form.get("inputs", [])
            input_names = [i["name"].lower() for i in inputs if i.get("name")]
            if any(k in " ".join(input_names) for k in ["user", "pass", "email", "login"]):
                login_forms.append(form)

        # Also check common login paths
        if not login_forms:
            login_paths = ["/login", "/login.php", "/admin", "/admin/login",
                           "/account/login", "/user/login", "/signin",
                           "/auth/login", "/wp-login.php", "/users/login"]

            for path in login_paths:
                login_url = urljoin(target_url + "/", path)
                response, error = self.http_client.get(login_url, timeout=5)
                if error or not response:
                    continue
                if response.status_code == 200 and response.text:
                    forms = parse_html_forms(response.text, login_url)
                    for form in forms:
                        inputs = form.get("inputs", [])
                        input_names = [i["name"].lower() for i in inputs if i.get("name")]
                        if any(k in " ".join(input_names)
                               for k in ["user", "pass", "email", "login"]):
                            form["login_url"] = login_url
                            login_forms.append(form)
                            break
                    if login_forms:
                        break

        if login_forms:
            self.logger.info(f"Found {len(login_forms)} login form(s)")
        else:
            self.logger.info("No login forms found, skipping cred-based tests")

        return login_forms

    def _test_session_fixation(self, target_url: str) -> List[Finding]:
        """Test for session fixation vulnerability."""
        findings = []

        # Get initial session cookie
        response1, error1 = self.http_client.get(target_url)
        if error1 or not response1:
            return findings

        cookies1 = response1.cookies.copy()
        if not cookies1:
            self.logger.debug("No session cookies found for session fixation test")
            return findings

        # Try to set our own session ID
        for cookie in cookies1:
            if "session" in cookie.name.lower() or "sess" in cookie.name.lower():
                # Craft a fixed session ID
                fixed_session_id = "FIXED_SESSION_ID_12345"
                self.http_client.session.cookies.set(
                    cookie.name, fixed_session_id,
                    domain=urlparse(target_url).netloc
                )

                # Make request with the fixed session ID
                response2, error2 = self.http_client.get(target_url)
                if error2 or not response2:
                    continue

                # Check if server accepted our fixed session ID
                session_cookie = None
                for c in response2.cookies:
                    if c.name == cookie.name:
                        session_cookie = c
                        break

                if session_cookie and session_cookie.value == fixed_session_id:
                    findings.append(Finding(
                        title="Session Fixation Vulneribility",
                        severity="high",
                        description="The server accepts user-provided session IDs "
                                    "without regeneration. An attacker can fixate a "
                                    "session ID and steal the victim's session after "
                                    "they log in.",
                        url=target_url,
                        evidence=f"Server accepted fixed session ID: {fixed_session_id}",
                        cwe_id="CWE-384",
                        owasp_category="A07:2021-Identification and Authentication Failures",
                        remediation="Regenerate session ID after login. Set HttpOnly "
                                    "and Secure flags. Use strong random session IDs.",
                    ))
                    break

                # Reset cookie
                self.http_client.session.cookies.set(
                    cookie.name, cookie.value or "",
                    domain=urlparse(target_url).netloc
                )

        return findings

    def _test_session_timeout(self, target_url: str) -> List[Finding]:
        """Test for session timeout (idle session not expiring)."""
        findings = []

        response, error = self.http_client.get(target_url)
        if error or not response:
            return findings

        session_cookies = [c for c in response.cookies
                          if "session" in c.name.lower() or "sess" in c.name.lower()]
        if not session_cookies:
            return findings

        # Check cookie expiry / max-age
        for cookie in session_cookies:
            has_expiry = cookie.expires is not None
            if not has_expiry:
                findings.append(Finding(
                    title="Session Cookie Without Expiry",
                    severity="medium",
                    description=f"Session cookie '{cookie.name}' has no expiry time. "
                                f"Idle sessions persist indefinitely, increasing the "
                                f"risk of session hijacking.",
                    url=target_url,
                    evidence=f"Cookie: {cookie.name}, no expires attribute",
                    cwe_id="CWE-613",
                    owasp_category="A07:2021-Identification and Authentication Failures",
                    remediation="Set appropriate session timeout (e.g., 15-30 minutes "
                                "of inactivity). Use Max-Age and Expires attributes.",
                ))

        return findings

    def _test_default_credentials(self, login_forms: List[Dict]) -> List[Finding]:
        """Test for default/weak credentials on login forms."""
        findings = []

        for form in login_forms[:3]:  # Limit to first 3 forms
            action = form.get("action", "")
            method = form.get("method", "POST")
            inputs = form.get("inputs", [])

            # Identify username and password fields
            username_field = None
            password_field = None
            for inp in inputs:
                name_lower = inp.get("name", "").lower()
                if not username_field and inp.get("type", "") != "password" and \
                   any(k in name_lower for k in ["user", "email", "login", "name", "account"]):
                    username_field = inp["name"]
                if not password_field and inp.get("type", "") == "password":
                    password_field = inp["name"]

            if not username_field or not password_field:
                # Use common names
                username_field = username_field or "username"
                password_field = password_field or "password"

            self.logger.info(f"Testing default creds on {action}")

            for username, password in DEFAULT_CREDS:
                # Get fresh session for each attempt
                self.http_client.session.cookies.clear()

                data = {i["name"]: i.get("value", "") for i in inputs if i.get("name")}
                data[username_field] = username
                data[password_field] = password

                if method == "POST":
                    response, error = self.http_client.post(action, data=data,
                                                            allow_redirects=False)
                else:
                    response, error = self.http_client.get(action, params=data,
                                                            allow_redirects=False)

                if error or not response:
                    continue

                # Check for successful login indicators
                success_indicators = [
                    response.status_code in (301, 302) and
                    "location" in {k.lower() for k in response.headers} and
                    "login" not in response.headers.get("Location", "").lower(),
                    response.status_code == 200 and
                    "logout" in response.text.lower() and
                    "invalid" not in response.text.lower() and
                    "error" not in response.text.lower(),
                ]

                if any(success_indicators):
                    findings.append(Finding(
                        title=f"Default Credentials Accepted ({username}:{password})",
                        severity="critical",
                        description=f"The application accepts default credentials: "
                                    f"username='{username}', password='{password}'. "
                                    f"This gives attackers full access to the system.",
                        url=action,
                        evidence=f"Username: {username}, Password: {password}, "
                                 f"Status: {response.status_code}",
                        cwe_id="CWE-521",
                        owasp_category="A07:2021-Identification and Authentication Failures",
                        remediation="Remove all default credentials. Enforce strong "
                                    "password policies. Force password change on first login.",
                    ))
                    self.logger.finding("critical",
                                        f"Default creds work: {username}:{password}")
                    break

            # Clear cookies after testing
            self.http_client.session.cookies.clear()

        return findings

    def _test_weak_password_policy(self, login_forms: List[Dict]) -> List[Finding]:
        """Test for weak password policy by attempting weak passwords."""
        findings = []

        # Try to register or change password to a weak one
        weak_passwords = [
            "123456", "password", "admin", "12345", "12345678",
            "qwerty", "abc123", "letmein", "monkey", "1234567",
            "password1", "111111", "iloveyou", "1234", "password123",
        ]

        # Check if registration is available
        register_paths = ["/register", "/signup", "/user/register",
                         "/account/register", "/join"]

        for form in login_forms[:1]:
            base_url = form.get("action", "")
            for reg_path in register_paths:
                reg_url = urljoin(base_url, reg_path)
                response, error = self.http_client.get(reg_url, timeout=5)
                if error or not response:
                    continue
                if response.status_code == 200 and response.text:
                    reg_forms = parse_html_forms(response.text, reg_url)
                    if reg_forms:
                        # Found registration form
                        findings.append(Finding(
                            title="Weak Password Policy Check Needed",
                            severity="low",
                            description=f"Registration form found at {reg_url}. "
                                        f"Manual verification needed to check if weak "
                                        f"passwords are accepted.",
                            url=reg_url,
                            cwe_id="CWE-521",
                            remediation="Enforce minimum password length (8+ chars), "
                                        "complexity requirements, and check against "
                                        "common password lists.",
                        ))
                        break

        return findings

    def _test_auth_bypass(self, target_url: str, login_forms: List[Dict]) -> List[Finding]:
        """Test for authentication bypass techniques."""
        findings = []

        # Test for auth bypass via SQL injection on login
        for form in login_forms[:2]:
            action = form.get("action", "")
            method = form.get("method", "POST")
            inputs = form.get("inputs", [])

            username_field = None
            password_field = None
            for inp in inputs:
                if inp.get("type", "") == "password":
                    password_field = inp["name"]
                elif any(k in inp.get("name", "").lower()
                         for k in ["user", "email", "login"]):
                    username_field = inp["name"]

            if not username_field or not password_field:
                continue

            # SQL injection auth bypass payloads
            auth_bypass_payloads = [
                ("' OR '1'='1' --", "anything"),
                ("admin'--", "anything"),
                ("' OR 1=1 --", ""),
                ("' OR ''='", "' OR ''='"),
                ("admin' OR '1'='1", "admin' OR '1'='1"),
                ("' OR '1'='1' /*", ""),
            ]

            for username_payload, password_payload in auth_bypass_payloads:
                self.http_client.session.cookies.clear()

                data = {i["name"]: i.get("value", "") for i in inputs if i.get("name")}
                data[username_field] = username_payload
                data[password_field] = password_payload

                if method == "POST":
                    response, error = self.http_client.post(action, data=data,
                                                            allow_redirects=False)
                else:
                    response, error = self.http_client.get(action, params=data,
                                                            allow_redirects=False)

                if error or not response:
                    continue

                # Check if auth bypass succeeded
                if (response.status_code in (301, 302) and
                    "login" not in response.headers.get("Location", "").lower()):
                    findings.append(Finding(
                        title="Authentication Bypass via SQL Injection",
                        severity="critical",
                        description=f"Authentication bypassed using SQL injection on "
                                    f"login form at {action}. The login query can be "
                                    f"manipulated to bypass authentication.",
                        url=action,
                        parameter=username_field,
                        payload=username_payload,
                        evidence=f"Username: {username_payload}, Password: {password_payload}, "
                                 f"Redirect: {response.headers.get('Location', '')}",
                        cwe_id="CWE-89",
                        owasp_category="A07:2021-Identification and Authentication Failures",
                        remediation="Use parameterized queries for authentication. "
                                    "Implement proper input validation.",
                    ))
                    self.logger.finding("critical",
                                        "Auth bypass via SQLi on login form!")
                    break

            self.http_client.session.cookies.clear()

        return findings
