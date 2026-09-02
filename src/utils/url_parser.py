"""
Utility functions for URL parsing, parameter extraction, and HTML parsing.
"""

import re
from urllib.parse import urlparse, parse_qs, urljoin, urlencode
from typing import Dict, List, Tuple, Optional

from bs4 import BeautifulSoup


def extract_parameters(url: str) -> Dict[str, str]:
    """Extract query parameters from a URL."""
    parsed = urlparse(url)
    return {k: v[0] if isinstance(v, list) else v for k, v in parse_qs(parsed.query).items()}


def replace_parameter(url: str, param: str, value: str) -> str:
    """Replace a single parameter value in a URL."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    # Set the new value
    params[param] = [value]

    # Rebuild query string
    new_query = urlencode({k: v[0] if isinstance(v, list) else v for k, v in params.items()})
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"


def set_all_params(url: str, params: Dict[str, str]) -> str:
    """Set all parameters in a URL."""
    parsed = urlparse(url)
    new_query = urlencode(params)
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"


def extract_base_url(url: str) -> str:
    """Get the base URL (scheme + host)."""
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def extract_path(url: str) -> str:
    """Get the path component of a URL."""
    return urlparse(url).path


def is_valid_url(url: str) -> bool:
    """Check if a string is a valid URL."""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False


def parse_html_forms(html: str, base_url: str) -> List[Dict]:
    """
    Parse all forms from HTML content.
    Returns list of form dicts with action, method, and inputs.
    """
    soup = BeautifulSoup(html, "lxml")
    forms = []

    for form in soup.find_all("form"):
        action = form.get("action", "")
        method = form.get("method", "get").upper()
        form_url = urljoin(base_url, action) if action else base_url

        inputs = []
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if name:
                inputs.append({
                    "name": name,
                    "type": inp.get("type", "text"),
                    "value": inp.get("value", ""),
                })

        forms.append({
            "action": form_url,
            "method": method,
            "inputs": inputs,
        })

    return forms


def extract_links(html: str, base_url: str) -> List[str]:
    """Extract all links from HTML content."""
    soup = BeautifulSoup(html, "lxml")
    links = []
    for a_tag in soup.find_all("a", href=True):
        href = a_tag["href"]
        if href.startswith(("#", "mailto:", "javascript:", "tel:")):
            continue
        full_url = urljoin(base_url, href)
        links.append(full_url)
    return list(set(links))


def extract_meta_tags(html: str) -> Dict[str, str]:
    """Extract meta tags from HTML."""
    soup = BeautifulSoup(html, "lxml")
    metas = {}
    for meta in soup.find_all("meta"):
        name = meta.get("name") or meta.get("property") or meta.get("http-equiv")
        content = meta.get("content", "")
        if name:
            metas[name] = content
    return metas


def get_response_technology(response) -> List[str]:
    """Detect technologies from response headers and content."""
    tech = []

    if not response:
        return tech

    headers = response.headers

    # Server
    server = headers.get("Server", "")
    if server:
        tech.append(f"Server: {server}")

    # Frameworks
    powered_by = headers.get("X-Powered-By", "")
    if powered_by:
        tech.append(f"X-Powered-By: {powered_by}")

    # ASP.NET
    if headers.get("X-AspNet-Version"):
        tech.append(f"ASP.NET: {headers['X-AspNet-Version']}")

    # Common CMS/framework detection from content
    if response.text:
        text = response.text.lower()
        if "wp-content" in text or "wp-includes" in text:
            tech.append("WordPress")
        if "/sites/all/" in text or "drupal.js" in text:
            tech.append("Drupal")
        if "joomla" in text or "/components/com_" in text:
            tech.append("Joomla")
        if "magento" in text or "/skin/frontend/" in text:
            tech.append("Magento")
        if "__next" in text or "next.js" in text:
            tech.append("Next.js")
        if "react" in text and "react-dom" in text:
            tech.append("React")
        if "vue" in text and "vue.js" in text:
            tech.append("Vue.js")
        if "angular" in text:
            tech.append("Angular")

    return list(set(tech))


def normalize_url(url: str) -> str:
    """Normalize a URL by removing fragments and trailing slashes (except root)."""
    parsed = urlparse(url)
    path = parsed.path.rstrip("/") or "/"
    query = f"?{parsed.query}" if parsed.query else ""
    return f"{parsed.scheme}://{parsed.netloc}{path}{query}"
