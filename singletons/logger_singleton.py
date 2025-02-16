"""
Logger Singleton for Connectly API.
Provides centralized logging functionality across the application.
"""

import logging
import os
from datetime import datetime
from typing import Optional


class LoggerSingleton:
    _instance = None
    _initialized = False

    def __new__(cls) -> 'LoggerSingleton':
        if not cls._instance:
            cls._instance = super(LoggerSingleton, cls).__new__(cls)
        return cls._instance

    def __init__(self) -> None:
        if not self._initialized:
            self._initialize()
            LoggerSingleton._initialized = True

    def _initialize(self) -> None:
        """Initialize the logger with proper configuration."""
        self.logger = logging.getLogger("connectly_logger")
        self.logger.setLevel(logging.INFO)

        # Create logs directory if it doesn't exist
        if not os.path.exists('logs'):
            os.makedirs('logs')

        # Create console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        )
        console_handler.setFormatter(console_formatter)

        # Create file handler
        file_handler = logging.FileHandler(
            f'logs/connectly_{datetime.now().strftime("%Y%m%d")}.log'
        )
        file_handler.setLevel(logging.INFO)
        file_formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - [%(name)s] - %(message)s'
        )
        file_handler.setFormatter(file_formatter)

        # Add handlers to logger
        self.logger.addHandler(console_handler)
        self.logger.addHandler(file_handler)

    def get_logger(self) -> logging.Logger:
        """
        Get the configured logger instance.
        
        Returns:
            The configured logger instance
        """
        return self.logger

    @classmethod
    def get_instance(cls) -> 'LoggerSingleton':
        """
        Get the singleton instance.
        
        Returns:
            The singleton logger instance
        """
        if not cls._instance:
            cls._instance = LoggerSingleton()
        return cls._instance 