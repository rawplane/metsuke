"""
HTTP client wrapper with retry, rate limiting, and proxy support.
All HTTP requests in the pipeline go through this client.
"""

import time
import random
from typing import Optional, Dict, Any, Tuple
from urllib.parse import urlparse, urljoin

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from src.core.logger import Logger


class HTTPClient:
    """HTTP client with built-in retry logic, rate limiting, and proxy support."""

    def __init__(self, config: Dict[str, Any], logger: Logger):
        self.config = config
        self.logger = logger
        self.session = requests.Session()

        # Configure session
        max_retries = config.get("max_retries", 3)
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=20,
                              pool_maxsize=20)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        # Set default headers
        self.session.headers.update({
            "User-Agent": config.get("user_agent",
                                     "Mozilla/5.0 (Pipeline-PenTest/1.0)"),
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "keep-alive",
        })

        # Proxy
        proxy_http = config.get("proxy", {}).get("http", "")
        proxy_https = config.get("proxy", {}).get("https", "")
        if proxy_http or proxy_https:
            self.session.proxies = {
                "http": proxy_http,
                "https": proxy_https or proxy_http,
            }

        # SSL — verify is enabled by default for safety.
        # Only disable warnings centrally when verification is explicitly turned off
        # (e.g. for isolated testing against a target with a self-signed certificate).
        self.verify_ssl = config.get("verify_ssl", True)
        if not self.verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            self.logger.warning(
                "SSL certificate verification is DISABLED (verify_ssl=False). "
                "This should only be used in isolated testing environments."
            )

        # Rate limiting
        self.delay = config.get("delay", 0.1)
        self.timeout = config.get("timeout", 15)
        self.follow_redirects = config.get("follow_redirects", True)

    def request(self, method: str, url: str,
                headers: Optional[Dict] = None,
                params: Optional[Dict] = None,
                data: Optional[Dict] = None,
                json_data: Optional[Dict] = None,
                cookies: Optional[Dict] = None,
                allow_redirects: Optional[bool] = None,
                timeout: Optional[float] = None) -> Tuple[Optional[requests.Response],
                                                          Optional[str]]:
        """
        Make an HTTP request with rate limiting and error handling.

        Returns:
            Tuple of (response, error_message). If successful, error is None.
        """
        # Rate limiting
        if self.delay > 0:
            time.sleep(self.delay + random.uniform(0, 0.05))

        req_headers = headers or {}
        if allow_redirects is None:
            allow_redirects = self.follow_redirects
        if timeout is None:
            timeout = self.timeout

        try:
            response = self.session.request(
                method=method.upper(),
                url=url,
                headers=req_headers,
                params=params,
                data=data,
                json=json_data,
                cookies=cookies,
                allow_redirects=allow_redirects if allow_redirects is not None else self.follow_redirects,
                timeout=timeout,
                verify=self.verify_ssl,
            )
            return response, None
        except requests.exceptions.Timeout:
            return None, f"Request timed out for {url}"
        except requests.exceptions.ConnectionError as e:
            return None, f"Connection error for {url}: {e}"
        except requests.exceptions.RequestException as e:
            return None, f"Request error for {url}: {e}"

    def get(self, url: str, **kwargs) -> Tuple[Optional[requests.Response], Optional[str]]:
        """Convenience method for GET requests."""
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> Tuple[Optional[requests.Response], Optional[str]]:
        """Convenience method for POST requests."""
        return self.request("POST", url, **kwargs)

    def head(self, url: str, **kwargs) -> Tuple[Optional[requests.Response], Optional[str]]:
        """Convenience method for HEAD requests."""
        return self.request("HEAD", url, **kwargs)

    def options(self, url: str, **kwargs) -> Tuple[Optional[requests.Response], Optional[str]]:
        """Convenience method for OPTIONS requests."""
        return self.request("OPTIONS", url, **kwargs)

    def close(self) -> None:
        """Close the HTTP session."""
        self.session.close()

    @staticmethod
    def is_same_domain(url1: str, url2: str) -> bool:
        """Check if two URLs belong to the same domain."""
        return urlparse(url1).netloc == urlparse(url2).netloc

    @staticmethod
    def get_domain(url: str) -> str:
        """Extract the domain from a URL."""
        return urlparse(url).netloc
