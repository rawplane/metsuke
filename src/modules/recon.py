"""
Reconnaissance Module
Performs subdomain enumeration, port scanning, technology detection,
robots.txt/sitemap.xml parsing, directory bruteforce, and link crawling.
"""

import socket
import re
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Tuple, Set, Optional
from urllib.parse import urljoin, urlparse, parse_qs

from src.core.config import Config
from src.core.logger import Logger
from src.core.http_client import HTTPClient
from src.core.models import Finding
from src.utils.url_parser import (
    extract_links, parse_html_forms, get_response_technology, normalize_url
)
from src.utils.payloads import SUBDOMAIN_PREFIXES, DIRECTORY_WORDLIST


class ReconModule:
    """Reconnaissance module for target enumeration and information gathering."""

    def __init__(self, http_client: HTTPClient, logger: Logger, config: Config):
        self.http_client = http_client
        self.logger = logger
        self.config = config

    def run(self, target_url: str) -> Tuple[Dict, List[str]]:
        """
        Run all reconnaissance tasks.
        Returns (recon_data_dict, tech_stack_list).
        """
        self.logger.info("Starting reconnaissance phase...")

        recon_data = {
            "target": target_url,
            "subdomains": [],
            "open_ports": [],
            "tech_stack": [],
            "robots_txt": {},
            "sitemap_urls": [],
            "discovered_endpoints": [],
            "discovered_forms": [],
            "discovered_params": {},
            "directory_findings": [],
            "findings": [],
        }

        # Basic connectivity check
        response, error = self.http_client.get(target_url)
        if error:
            self.logger.warning(f"Initial connection to {target_url} failed: {error}")
        elif response:
            self.logger.success(f"Target {target_url} is reachable "
                                f"(HTTP {response.status_code})")

            # Detect technologies
            if self.config.get("recon", "tech_detection", default=True):
                tech = get_response_technology(response)
                recon_data["tech_stack"] = tech
                self.logger.info(f"Detected technologies: {', '.join(tech) if tech else 'None'}")

            # Crawl links
            self.logger.info("Crawling target for links and forms...")
            endpoints, forms, params = self._crawl_and_extract(target_url, response.text)
            recon_data["discovered_endpoints"] = list(endpoints)
            recon_data["discovered_forms"] = forms
            recon_data["discovered_params"] = params
            self.logger.info(f"Found {len(endpoints)} endpoints, {len(forms)} forms, "
                             f"{len(params)} unique parameters")

        # Subdomain enumeration
        if self.config.get("recon", "subdomain_enum", default=True):
            self.logger.info("Enumerating subdomains...")
            subdomains = self._enumerate_subdomains(target_url)
            recon_data["subdomains"] = subdomains
            self.logger.info(f"Found {len(subdomains)} subdomains: "
                             f"{', '.join(subdomains) if subdomains else 'none'}")

        # Port scanning
        if self.config.get("recon", "port_scan", default=True):
            self.logger.info("Scanning ports...")
            open_ports = self._scan_ports(target_url)
            recon_data["open_ports"] = open_ports
            if open_ports:
                self.logger.info(f"Open ports: {', '.join(map(str, open_ports))}")

                # Finding for open ports
                recon_data["findings"].append(Finding(
                    title="Open Ports Detected",
                    severity="info",
                    description=f"Found {len(open_ports)} open ports: "
                                f"{', '.join(map(str, open_ports))}",
                    url=target_url,
                    evidence="\n".join(f"Port {p}" for p in open_ports),
                    cwe_id="CWE-200",
                    remediation="Ensure only necessary ports are exposed. "
                               "Close unused services and restrict access.",
                ))

        # Robots.txt and sitemap.xml
        if self.config.get("recon", "robots_sitemap", default=True):
            self.logger.info("Checking robots.txt and sitemap.xml...")
            robots, sitemap = self._check_robots_sitemap(target_url)
            recon_data["robots_txt"] = robots
            recon_data["sitemap_urls"] = sitemap

            if sitemap:
                recon_data["discovered_endpoints"] = list(
                    set(recon_data["discovered_endpoints"] + sitemap)
                )

            # Finding for sensitive robots.txt entries
            disallowed = robots.get("disallow", [])
            sensitive = [d for d in disallowed if any(k in d.lower()
                         for k in ["admin", "secret", "private", "config", "backup"])]
            if sensitive:
                recon_data["findings"].append(Finding(
                    title="Sensitive Paths in robots.txt",
                    severity="low",
                    description="robots.txt exposes sensitive paths that should not be indexed.",
                    url=urljoin(target_url, "/robots.txt"),
                    evidence="\n".join(f"Disallow: {d}" for d in sensitive),
                    cwe_id="CWE-538",
                    remediation="Remove sensitive paths from robots.txt or use access control instead.",
                ))

        # Directory bruteforce
        if self.config.get("recon", "directory_bruteforce", default=True):
            self.logger.info("Running directory bruteforce...")
            dir_findings = self._directory_bruteforce(target_url)
            recon_data["directory_findings"] = dir_findings
            if dir_findings:
                self.logger.info(f"Found {len(dir_findings)} interesting directories")

                recon_data["findings"].append(Finding(
                    title="Interesting Directories Discovered",
                    severity="low",
                    description=f"Found {len(dir_findings)} accessible directories that may contain sensitive info.",
                    url=target_url,
                    evidence="\n".join(d["url"] for d in dir_findings),
                    cwe_id="CWE-538",
                    remediation="Restrict access to sensitive directories.",
                ))

        self.logger.success("Reconnaissance phase completed.")
        return recon_data, recon_data["tech_stack"]

    def _crawl_and_extract(self, base_url: str, html: str) -> Tuple[Set[str], List[Dict], Dict]:
        """
        Crawl the page for links and forms.
        Returns (endpoints_set, forms_list, params_dict).
        """
        endpoints = set()
        forms = []
        params = {}

        # Extract links
        links = extract_links(html, base_url)
        for link in links:
            if self.http_client.is_same_domain(link, base_url):
                endpoints.add(normalize_url(link))

                # Extract params from URL
                parsed = urlparse(link)
                if parsed.query:
                    query_params = parse_qs(parsed.query)
                    for p in query_params:
                        params[p] = query_params[p][0] if query_params[p] else ""

        # Extract forms
        forms = parse_html_forms(html, base_url)

        # Deep crawl: visit links up to 2 levels
        visited = set()
        to_visit = list(endpoints)[:15]  # Limit to first 15 endpoints

        while to_visit:
            url = to_visit.pop(0)
            if url in visited or len(visited) > 20:
                continue
            visited.add(url)

            response, error = self.http_client.get(url)
            if error or not response:
                continue

            new_links = extract_links(response.text, url)
            for link in new_links:
                if self.http_client.is_same_domain(link, base_url):
                    normalized = normalize_url(link)
                    if normalized not in endpoints:
                        endpoints.add(normalized)
                        if len(to_visit) < 15:
                            to_visit.append(normalized)

                    parsed = urlparse(link)
                    if parsed.query:
                        query_params = parse_qs(parsed.query)
                        for p in query_params:
                            params[p] = query_params[p][0] if query_params[p] else ""

            new_forms = parse_html_forms(response.text, url)
            forms.extend(new_forms)

        return endpoints, forms, params

    def _enumerate_subdomains(self, target_url: str) -> List[str]:
        """Enumerate subdomains using DNS resolution."""
        domain = self.http_client.get_domain(target_url)
        if not domain:
            return []

        # Remove www prefix if present
        root_domain = domain.replace("www.", "")

        found_subdomains = []
        workers = self.config.get("pipeline", "parallel_workers", default=10)

        def check_subdomain(prefix: str) -> Tuple[str, bool]:
            full = f"{prefix}.{root_domain}"
            try:
                socket.gethostbyname(full)
                return full, True
            except socket.gaierror:
                return full, False
            except Exception:
                return full, False

        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(check_subdomain, p): p
                       for p in SUBDOMAIN_PREFIXES}
            for future in as_completed(futures):
                subdomain, is_alive = future.result()
                if is_alive:
                    found_subdomains.append(subdomain)
                    self.logger.finding("info", f"Subdomain found: {subdomain}")

        return sorted(found_subdomains)

    def _scan_ports(self, target_url: str) -> List[int]:
        """Scan common ports on the target."""
        domain = self.http_client.get_domain(target_url)
        if not domain:
            return []

        # Common web-related ports
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
                        993, 995, 1433, 1521, 3306, 3389, 5432,
                        5900, 6379, 8080, 8443, 8888, 9090, 27017]

        port_range = self.config.get("recon", "port_range", default="1-1000")
        # Parse port range if provided, but prefer common ports for speed
        open_ports = []
        workers = self.config.get("pipeline", "parallel_workers", default=10)

        def check_port(port: int) -> Tuple[int, bool]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1.5)
                result = sock.connect_ex((domain, port))
                sock.close()
                return port, result == 0
            except Exception:
                return port, False

        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(check_port, p): p for p in common_ports}
            for future in as_completed(futures):
                port, is_open = future.result()
                if is_open:
                    open_ports.append(port)

        return sorted(open_ports)

    def _check_robots_sitemap(self, target_url: str) -> Tuple[Dict, List[str]]:
        """Check robots.txt and sitemap.xml."""
        robots_data = {"disallow": [], "allow": [], "sitemaps": []}
        sitemap_urls = []

        # Check robots.txt
        robots_url = urljoin(target_url, "/robots.txt")
        response, error = self.http_client.get(robots_url)
        if not error and response and response.status_code == 200:
            self.logger.info("robots.txt found")
            for line in response.text.splitlines():
                line = line.strip()
                if line.lower().startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    if path:
                        robots_data["disallow"].append(path)
                elif line.lower().startswith("allow:"):
                    path = line.split(":", 1)[1].strip()
                    if path:
                        robots_data["allow"].append(path)
                elif line.lower().startswith("sitemap:"):
                    sitemap = line.split(":", 1)[1].strip()
                    if sitemap:
                        robots_data["sitemaps"].append(sitemap)
        else:
            self.logger.info("robots.txt not found or inaccessible")

        # Check sitemap.xml
        sitemap_url = urljoin(target_url, "/sitemap.xml")
        response, error = self.http_client.get(sitemap_url)
        if not error and response and response.status_code == 200:
            self.logger.info("sitemap.xml found")
            # Extract URLs from sitemap
            urls = re.findall(r"<loc>(.*?)</loc>", response.text)
            sitemap_urls = [u.strip() for u in urls]
        else:
            self.logger.info("sitemap.xml not found or inaccessible")

        return robots_data, sitemap_urls

    def _directory_bruteforce(self, target_url: str) -> List[Dict]:
        """Brute force common directories."""
        findings = []
        workers = self.config.get("pipeline", "parallel_workers", default=10)

        # Try to load custom wordlist
        wordlist_path = self.config.get("recon", "wordlist", default="")
        if wordlist_path and os.path.exists(wordlist_path):
            with open(wordlist_path, "r") as f:
                words = [line.strip() for line in f if line.strip()]
        else:
            words = DIRECTORY_WORDLIST

        def check_directory(word: str) -> Optional[Dict]:
            url = urljoin(target_url + "/", word)
            response, error = self.http_client.get(url, timeout=5)
            if error or not response:
                return None

            if response.status_code in (200, 301, 302, 401, 403):
                return {
                    "url": url,
                    "status_code": response.status_code,
                    "length": len(response.text),
                    "word": word,
                }
            return None

        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(check_directory, w): w for w in words}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    findings.append(result)
                    status = result["status_code"]
                    self.logger.finding(
                        "info",
                        f"Directory found: {result['url']} (HTTP {status})"
                    )

        return findings
