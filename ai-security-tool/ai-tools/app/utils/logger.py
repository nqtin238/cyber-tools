#!/usr/bin/env python3
# File: ai-tools/app/utils/logger.py
# Purpose: Centralized logging configuration for the application
# Usage: Import get_logger and use it to create loggers for different modules

import logging
import os
from datetime import datetime
from app.core.config import settings

def get_logger(name: str) -> logging.Logger:
    """
    Get a configured logger instance.
    
    Args:
        name (str): The name of the logger (typically __name__)
        
    Returns:
        logging.Logger: Configured logger instance
    """
    # Create logs directory if it doesn't exist
    log_dir = os.path.join("logs")
    os.makedirs(log_dir, exist_ok=True)
    
    # Create a logger
    logger = logging.getLogger(name)
    
    # Set log level from settings
    log_level = getattr(logging, settings.LOG_LEVEL.upper())
    logger.setLevel(log_level)
    
    # Create handlers
    # File handler with date in filename
    timestamp = datetime.now().strftime("%Y-%m-%d")
    log_file = os.path.join(log_dir, f"security_analysis_{timestamp}.log")
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(log_level)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    
    # Create formatters and add them to handlers
    log_format = logging.Formatter(settings.LOGGING.format)
    file_handler.setFormatter(log_format)
    console_handler.setFormatter(log_format)
    
    # Add handlers to logger
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger 