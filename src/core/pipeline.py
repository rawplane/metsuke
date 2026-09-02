"""
Pipeline Runner - orchestrates the entire penetration testing process.
Manages stage execution, parallel processing, and result collection.
"""

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional

from src.core.config import Config
from src.core.logger import Logger
from src.core.http_client import HTTPClient
from src.core.models import ScanResult, Finding
from src.core.report import ReportGenerator

from src.modules.recon import ReconModule
from src.modules.vuln_scanner import VulnerabilityScanner
from src.modules.security_headers import SecurityHeadersChecker
from src.modules.auth_testing import AuthTestingModule


class PipelineRunner:
    """
    Main pipeline orchestrator. Runs each stage sequentially,
    passing results between stages.
    """

    def __init__(self, config_path: str = "config/config.yaml"):
        self.config = Config(config_path)
        net_cfg = self.config.get_network_config()
        self.logger = Logger(
            log_level=self.config.get("logging", "level", default="INFO"),
            log_file=self.config.get("logging", "file", default="output/pentest.log"),
            console=self.config.get("logging", "console", default=True),
        )
        self.http_client = HTTPClient(net_cfg, self.logger)
        self.report_generator = ReportGenerator(
            self.logger, self.config.get("report", "output_dir", default="output")
        )

        # Initialize modules
        self.recon = ReconModule(self.http_client, self.logger, self.config)
        self.vuln_scanner = VulnerabilityScanner(self.http_client, self.logger, self.config)
        self.security_headers = SecurityHeadersChecker(self.http_client, self.logger, self.config)
        self.auth_testing = AuthTestingModule(self.http_client, self.logger, self.config)

        self.results: Optional[ScanResult] = None

    def run(self, target_url: Optional[str] = None) -> ScanResult:
        """
        Execute the full penetration testing pipeline.
        Returns the scan results.
        """
        url = target_url or self.config.get_target_url()
        if not url:
            self.logger.error("No target URL specified.")
            raise ValueError("No target URL specified in config or CLI.")

        # Ensure URL has scheme
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        self.logger.info(f"Starting penetration test pipeline on: {url}")
        self.logger.info("=" * 60)

        result = ScanResult(target_url=url)
        stages = self.config.get_pipeline_stages()
        start_time = time.time()

        for stage in stages:
            self.logger.info(f"[STAGE] Running: {stage.upper()}")
            stage_start = time.time()

            try:
                if stage == "recon":
                    self._run_recon(url, result)
                elif stage == "vulnerability_scan":
                    self._run_vuln_scan(url, result)
                elif stage == "security_headers":
                    self._run_security_headers(url, result)
                elif stage == "auth_testing":
                    self._run_auth_testing(url, result)
                elif stage == "report":
                    fmt = self.config.get("report", "format", default="all")
                    self.report_generator.generate(result, fmt)
                else:
                    self.logger.warning(f"Unknown stage: {stage}")
            except Exception as e:
                self.logger.error(f"Stage '{stage}' failed: {e}")

            elapsed = time.time() - stage_start
            self.logger.info(f"[STAGE] {stage.upper()} completed in {elapsed:.2f}s")

            # Check for stop condition
            if self.config.should_stop_on_critical() and result.has_critical():
                self.logger.critical(
                    "Critical vulnerability found! Stopping pipeline as configured."
                )
                break

        total_time = time.time() - start_time
        result.stats["total_time_seconds"] = round(total_time, 2)
        result.stats["stages_executed"] = [
            s for s in stages if s != "report"
        ]

        self.logger.info("=" * 60)
        summary = result.get_summary()
        self.logger.info(f"Scan completed in {total_time:.2f}s")
        self.logger.info(
            f"Findings: {summary['critical']} Critical, {summary['high']} High, "
            f"{summary['medium']} Medium, {summary['low']} Low, {summary['info']} Info"
        )
        self.logger.info(f"Total findings: {summary['total']}")

        self.http_client.close()
        self.results = result
        return result

    def _run_recon(self, url: str, result: ScanResult) -> None:
        """Run reconnaissance stage."""
        recon_data, tech_stack = self.recon.run(url)
        result.recon_data = recon_data
        result.tech_stack = tech_stack

        # Convert recon findings to result findings
        for finding in recon_data.get("findings", []):
            result.add_finding(finding)

    def _run_vuln_scan(self, url: str, result: ScanResult) -> None:
        """Run vulnerability scanning stage."""
        # Gather endpoints from recon
        endpoints = result.recon_data.get("discovered_endpoints", [])
        forms = result.recon_data.get("discovered_forms", [])
        params = result.recon_data.get("discovered_params", {})

        # If no endpoints found, use the base URL
        if not endpoints:
            endpoints = [url]

        findings = self.vuln_scanner.scan(url, endpoints, forms, params,
                                           result.recon_data)
        for finding in findings:
            result.add_finding(finding)

    def _run_security_headers(self, url: str, result: ScanResult) -> None:
        """Run security headers check stage."""
        findings = self.security_headers.check(url)
        for finding in findings:
            result.add_finding(finding)

    def _run_auth_testing(self, url: str, result: ScanResult) -> None:
        """Run authentication testing stage."""
        findings = self.auth_testing.test(url, result.recon_data)
        for finding in findings:
            result.add_finding(finding)
