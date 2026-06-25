"""
Logging configuration for SentinelRecon
Sets up rotating file logger and console output
"""

import logging
import logging.handlers
import os
from pathlib import Path
from typing import Optional


class LoggerSetup:
    """Configure logging for SentinelRecon"""

    _logger_instance = None

    @staticmethod
    def setup_logger(
        name: str = "sentinelrecon",
        log_file: Optional[str] = None,
        log_level: str = "INFO",
        console_output: bool = True,
    ) -> logging.Logger:
        """
        Set up and configure logger
        
        Args:
            name: Logger name
            log_file: Path to log file (if None, uses ~/.sentinelrecon/logs/sentinel.log)
            log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            console_output: Whether to also log to console
            
        Returns:
            Configured logger instance
        """
        if LoggerSetup._logger_instance:
            return LoggerSetup._logger_instance

        logger = logging.getLogger(name)
        logger.setLevel(getattr(logging, log_level.upper()))

        # Default log file location
        if log_file is None:
            log_dir = Path.home() / ".sentinelrecon" / "logs"
            log_dir.mkdir(parents=True, exist_ok=True)
            log_file = str(log_dir / "sentinel.log")
        else:
            # Ensure log directory exists
            log_dir = Path(log_file).parent
            log_dir.mkdir(parents=True, exist_ok=True)

        # Create formatters
        detailed_formatter = logging.Formatter(
            '[%(asctime)s] %(levelname)-8s [%(name)s:%(funcName)s:%(lineno)d] %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        simple_formatter = logging.Formatter(
            '[%(levelname)s] %(message)s'
        )

        # File handler with rotation
        try:
            file_handler = logging.handlers.RotatingFileHandler(
                log_file,
                maxBytes=10 * 1024 * 1024,  # 10MB
                backupCount=5,
                encoding='utf-8'
            )
            file_handler.setLevel(getattr(logging, log_level.upper()))
            file_handler.setFormatter(detailed_formatter)
            logger.addHandler(file_handler)
        except Exception as e:
            print(f"Warning: Could not create file logger: {e}")

        # Console handler
        if console_output:
            console_handler = logging.StreamHandler()
            console_handler.setLevel(getattr(logging, log_level.upper()))
            console_handler.setFormatter(simple_formatter)
            logger.addHandler(console_handler)

        LoggerSetup._logger_instance = logger
        return logger

    @staticmethod
    def get_logger(name: str = "sentinelrecon") -> logging.Logger:
        """Get logger instance"""
        if LoggerSetup._logger_instance is None:
            LoggerSetup.setup_logger(name=name)
        return logging.getLogger(name)

    @staticmethod
    def reset_logger():
        """Reset logger instance"""
        LoggerSetup._logger_instance = None
