"""
Configuration loader for the penetration testing pipeline.
Loads and validates YAML configuration files, with optional overrides
from environment variables / .env file (via python-dotenv).
"""

import os
import yaml
from typing import Any, Dict, Optional

try:
    from dotenv import load_dotenv
    _HAS_DOTENV = True
except ImportError:
    _HAS_DOTENV = False


class Config:
    """Central configuration manager for the pipeline."""

    DEFAULT_CONFIG = {
        "target": {"url": "", "scope": [], "exclude_paths": []},
        "pipeline": {
            "stages": ["recon", "vulnerability_scan", "security_headers",
                       "auth_testing", "report"],
            "stop_on_critical": False,
            "parallel_workers": 10,
        },
        "recon": {
            "subdomain_enum": True,
            "port_scan": True,
            "port_range": "1-1000",
            "tech_detection": True,
            "robots_sitemap": True,
            "directory_bruteforce": False,
            "wordlist": "wordlists/directories.txt",
        },
        "network": {
            "delay": 0.1,
            "timeout": 15,
            "max_retries": 3,
            "user_agent": "Mozilla/5.0 (Pipeline-PenTest/1.0; Security Scanner)",
            "verify_ssl": True,
            "follow_redirects": True,
            "max_redirects": 5,
        },
        "proxy": {"http": "", "https": ""},
        "report": {
            "format": "all",
            "output_dir": "output",
            "include_evidence": True,
        },
        "logging": {
            "level": "INFO",
            "file": "output/pentest.log",
            "console": True,
        },
    }

    def __init__(self, config_path: Optional[str] = None):
        # Load .env file if python-dotenv is available
        if _HAS_DOTENV:
            load_dotenv()
        self._config: Dict[str, Any] = {}
        self.config_path = config_path
        self._load_config()
        self._apply_env_overrides()

    def _load_config(self) -> None:
        """Load configuration from YAML file, merging with defaults."""
        # Start with defaults
        self._config = self._deep_copy(self.DEFAULT_CONFIG)

        if self.config_path and os.path.exists(self.config_path):
            with open(self.config_path, "r", encoding="utf-8") as f:
                user_config = yaml.safe_load(f) or {}
            self._config = self._deep_merge(self._config, user_config)

    def _apply_env_overrides(self) -> None:
        """
        Override configuration values using environment variables.

        Supported variables:
          - TARGET_URL : overrides target.url
          - HTTP_PROXY : overrides proxy.http
          - HTTPS_PROXY: overrides proxy.https
          - AUTH_TOKEN : stored under target.auth_token (not written to YAML)
        """
        env_target = os.getenv("TARGET_URL")
        if env_target:
            self._config.setdefault("target", {})["url"] = env_target

        env_http_proxy = os.getenv("HTTP_PROXY")
        if env_http_proxy:
            self._config.setdefault("proxy", {})["http"] = env_http_proxy

        env_https_proxy = os.getenv("HTTPS_PROXY")
        if env_https_proxy:
            self._config.setdefault("proxy", {})["https"] = env_https_proxy

        env_auth_token = os.getenv("AUTH_TOKEN")
        if env_auth_token:
            self._config.setdefault("target", {})["auth_token"] = env_auth_token

    @staticmethod
    def _deep_copy(d: Dict) -> Dict:
        """Create a deep copy of a dictionary."""
        return {k: Config._deep_copy(v) if isinstance(v, dict) else v
                for k, v in d.items()}

    @staticmethod
    def _deep_merge(base: Dict, override: Dict) -> Dict:
        """Recursively merge override into base dictionary."""
        result = base.copy()
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = Config._deep_merge(result[key], value)
            else:
                result[key] = value
        return result

    def get(self, *keys, default: Any = None) -> Any:
        """
        Get a nested configuration value using dot-notation keys.
        Example: config.get("network", "timeout", default=15)
        """
        value = self._config
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
        return value

    def get_target_url(self) -> str:
        """Get the target URL."""
        return self.get("target", "url", default="")

    def get_network_config(self) -> Dict[str, Any]:
        """Get network-related configuration."""
        return self.get("network", default={})

    def get_pipeline_stages(self) -> list:
        """Get the list of pipeline stages."""
        return self.get("pipeline", "stages", default=[])

    def should_stop_on_critical(self) -> bool:
        """Check if pipeline should stop on critical findings."""
        return self.get("pipeline", "stop_on_critical", default=False)

    def to_dict(self) -> Dict[str, Any]:
        """Return the full configuration as a dictionary."""
        return self._config
