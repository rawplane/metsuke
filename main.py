#!/usr/bin/env python3
"""
Pipeline Penetration Tester - Main Entry Point
A comprehensive web application security scanner.

Usage:
    python main.py [OPTIONS]

Examples:
    python main.py -u http://example.com
    python main.py -u http://example.com -c config/custom.yaml
    python main.py -u http://example.com --stages recon,vulnerability_scan,report
    python main.py -u http://example.com --format html
"""

import argparse
import sys
import os

# Try to import pyfiglet for banner
try:
    import pyfiglet
    HAS_FIGLET = True
except ImportError:
    HAS_FIGLET = False

from src.core.pipeline import PipelineRunner


BANNER = r"""
 ____ ____ _    _    _    _  ___ ____ ____ ___ ____
| _ ) ___| |    | |  | |  / __/ ___|  _ |_ _|  _ \
| _ )___ | |    | |  | | \__ \___ | |_| | || |_| |
|___/|____|_|____|_|____|___/____|_____|___|____/
| | | | |__   ___| | |  | __|_   _| | | ___/ _ \
| |_| | '_ \ / _ \ | |__| _|  | | | | | |  | |_) |
 \___/|_.__/ \___/_|____|_____| |_| |_|_|_|_| .__/
                                            |_|
"""

DISCLAIMER = """
DISCLAIMER:
    This tool is for authorized security testing only.
    Only use it against systems you own or have explicit permission to test.
    Unauthorized use is illegal and unethical.
"""


def print_banner():
    """Print the tool banner."""
    if HAS_FIGLET:
        ascii_art = pyfiglet.figlet_format("Pipeline PenTester", font="slant")
        print(ascii_art)
    else:
        print(BANNER)
    print("=" * 60)
    print("  Advanced Web Application Penetration Testing Pipeline v1.0")
    print("=" * 60)
    print(DISCLAIMER)


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Pipeline Penetration Tester - Advanced Web Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py -u http://example.com
  python main.py -u https://target.com --config config/custom.yaml
  python main.py -u http://example.com --format html
  python main.py -u http://example.com --stages recon,security_headers,report
  python main.py --config config/config.yaml
""",
    )

    parser.add_argument(
        "-u", "--url",
        help="Target URL to scan (e.g., http://example.com)",
        type=str,
    )

    parser.add_argument(
        "-c", "--config",
        help="Path to configuration file (default: config/config.yaml)",
        type=str,
        default="config/config.yaml",
    )

    parser.add_argument(
        "--stages",
        help="Comma-separated list of stages to run "
             "(recon,vulnerability_scan,security_headers,auth_testing,report)",
        type=str,
    )

    parser.add_argument(
        "--format",
        help="Report format (all, html, json, txt)",
        type=str,
        choices=["all", "html", "json", "txt"],
    )

    parser.add_argument(
        "--delay",
        help="Delay between requests in seconds (default: 0.1)",
        type=float,
    )

    parser.add_argument(
        "--timeout",
        help="Request timeout in seconds (default: 15)",
        type=float,
    )

    parser.add_argument(
        "--workers",
        help="Number of parallel workers (default: 10)",
        type=int,
    )

    parser.add_argument(
        "--proxy",
        help="HTTP/HTTPS proxy URL (e.g., http://127.0.0.1:8080)",
        type=str,
    )

    parser.add_argument(
        "--verbose", "-v",
        help="Verbose output (DEBUG logging)",
        action="store_true",
    )

    parser.add_argument(
        "--no-banner",
        help="Skip banner display",
        action="store_true",
    )

    return parser.parse_args()


def apply_cli_overrides(runner: PipelineRunner, args) -> None:
    """Apply CLI argument overrides to the configuration."""
    config = runner.config

    # Override target URL
    if args.url:
        config._config.setdefault("target", {})["url"] = args.url

    # Override stages
    if args.stages:
        stages = [s.strip() for s in args.stages.split(",")]
        config._config.setdefault("pipeline", {})["stages"] = stages

    # Override report format
    if args.format:
        config._config.setdefault("report", {})["format"] = args.format

    # Override delay
    if args.delay is not None:
        config._config.setdefault("network", {})["delay"] = args.delay

    # Override timeout
    if args.timeout is not None:
        config._config.setdefault("network", {})["timeout"] = args.timeout

    # Override workers
    if args.workers is not None:
        config._config.setdefault("pipeline", {})["parallel_workers"] = args.workers

    # Override proxy
    if args.proxy:
        config._config.setdefault("proxy", {})["http"] = args.proxy
        config._config.setdefault("proxy", {})["https"] = args.proxy

    # Override log level
    if args.verbose:
        config._config.setdefault("logging", {})["level"] = "DEBUG"
        # Reinitialize logger with debug level
        from src.core.logger import Logger
        runner.logger = Logger(
            log_level="DEBUG",
            log_file=config.get("logging", "file", default="output/pentest.log"),
            console=True,
        )


def main():
    """Main entry point."""
    args = parse_arguments()

    if not args.no_banner:
        print_banner()

    # Check for config file
    if not os.path.exists(args.config):
        print(f"[!] Configuration file not found: {args.config}")
        print("    Using default configuration. Create one from config/config.yaml")
        args.config = "config/config.yaml"

    # Initialize pipeline
    try:
        runner = PipelineRunner(config_path=args.config)
        apply_cli_overrides(runner, args)
    except Exception as e:
        print(f"[ERROR] Failed to initialize pipeline: {e}")
        sys.exit(1)

    # Check if target is set
    target_url = runner.config.get_target_url()
    if not target_url and not args.url:
        print("[ERROR] No target URL specified.")
        print("  Use -u/--url to specify a target, or set it in the config file.")
        print("  Example: python main.py -u http://example.com")
        sys.exit(1)

    # Run the pipeline
    try:
        result = runner.run(target_url=args.url)

        # Print summary
        print("\n" + "=" * 60)
        print("  SCAN SUMMARY")
        print("=" * 60)
        summary = result.get_summary()
        print(f"  Target:     {result.target_url}")
        print(f"  Duration:   {result.stats.get('total_time_seconds', 0)}s")
        print(f"  Critical:   {summary['critical']}")
        print(f"  High:       {summary['high']}")
        print(f"  Medium:     {summary['medium']}")
        print(f"  Low:        {summary['low']}")
        print(f"  Info:       {summary['info']}")
        print(f"  Total:      {summary['total']}")
        print()
        print("  Reports saved to: output/")
        print("=" * 60)

        sys.exit(0 if summary["critical"] == 0 else 2)

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
        sys.exit(130)
    except Exception as e:
        print(f"\n[ERROR] Pipeline failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
