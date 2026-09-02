"""
Advanced logging system for the penetration testing pipeline.
Provides colored console output and file logging.
"""

import logging
import os
from logging.handlers import RotatingFileHandler
from typing import Optional

from colorama import Fore, Style, init as colorama_init

# Initialize colorama
colorama_init(autoreset=True)


class ColoredFormatter(logging.Formatter):
    """Custom formatter with color-coded log levels for console output."""

    COLORS = {
        logging.DEBUG: Fore.CYAN,
        logging.INFO: Fore.GREEN,
        logging.WARNING: Fore.YELLOW,
        logging.ERROR: Fore.RED,
        logging.CRITICAL: Fore.RED + Style.BRIGHT,
    }

    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelno, "")
        record.levelname = f"{color}{record.levelname}{Style.RESET_ALL}"
        return super().format(record)


class Logger:
    """Singleton logger for the entire pipeline."""

    _instance: Optional["Logger"] = None

    def __new__(cls, *args, **kwargs) -> "Logger":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self, log_level: str = "INFO", log_file: str = "output/pentest.log",
                 console: bool = True):
        if self._initialized:
            return
        self._initialized = True

        self.logger = logging.getLogger("PipelinePenTest")
        self.logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))
        self.logger.handlers = []

        # Ensure output directory exists
        log_dir = os.path.dirname(log_file)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)

        # Console handler with colors
        if console:
            console_handler = logging.StreamHandler()
            console_handler.setLevel(getattr(logging, log_level.upper(), logging.INFO))
            console_fmt = ColoredFormatter(
                "%(asctime)s [%(levelname)s] %(message)s",
                datefmt="%H:%M:%S",
            )
            console_handler.setFormatter(console_fmt)
            self.logger.addHandler(console_handler)

        # File handler
        file_handler = RotatingFileHandler(
            log_file, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"
        )
        file_handler.setLevel(logging.DEBUG)
        file_fmt = logging.Formatter(
            "%(asctime)s [%(levelname)s] [%(filename)s:%(lineno)d] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        file_handler.setFormatter(file_fmt)
        self.logger.addHandler(file_handler)

    def debug(self, msg: str) -> None:
        self.logger.debug(msg)

    def info(self, msg: str) -> None:
        self.logger.info(msg)

    def warning(self, msg: str) -> None:
        self.logger.warning(msg)

    def error(self, msg: str) -> None:
        self.logger.error(msg)

    def critical(self, msg: str) -> None:
        self.logger.critical(msg)

    def success(self, msg: str) -> None:
        """Log a success message (INFO level with green prefix)."""
        self.logger.info(f"{Fore.GREEN}[+]{Style.RESET_ALL} {msg}")

    def finding(self, severity: str, msg: str) -> None:
        """Log a security finding with appropriate severity coloring."""
        severity_colors = {
            "critical": Fore.RED + Style.BRIGHT,
            "high": Fore.RED,
            "medium": Fore.YELLOW,
            "low": Fore.CYAN,
            "info": Fore.BLUE,
        }
        color = severity_colors.get(severity.lower(), Fore.WHITE)
        self.logger.warning(
            f"{color}[{severity.upper()}] {msg}{Style.RESET_ALL}"
        )


def get_logger(log_level: str = "INFO", log_file: str = "output/pentest.log",
               console: bool = True) -> Logger:
    """Get or initialize the singleton logger instance."""
    return Logger(log_level, log_file, console)
