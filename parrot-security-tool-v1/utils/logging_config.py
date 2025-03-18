"""Centralized logging configuration for Parrot Security Tool"""
import os
import json
import logging
import logging.handlers
import datetime
from pathlib import Path
import platform
import socket
from typing import Dict, Any, Optional

# Try to import sentry_sdk for error tracking
try:
    import sentry_sdk
    from sentry_sdk.integrations.logging import LoggingIntegration
    SENTRY_AVAILABLE = True
except ImportError:
    SENTRY_AVAILABLE = False

# Log directory setup
LOG_DIR = Path("logs")
LOG_DIR.mkdir(exist_ok=True)

# Define log levels
LOG_LEVELS = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
    "CRITICAL": logging.CRITICAL
}

# JSON log formatter
class JsonFormatter(logging.Formatter):
    """Formatter for JSON structured logs"""
    
    def format(self, record):
        log_data = {
            'timestamp': datetime.datetime.now().isoformat(),
            'level': record.levelname,
            'name': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno,
            'process_id': record.process,
            'thread_id': record.thread,
            'hostname': socket.gethostname(),
            'platform': platform.platform(),
        }
        
        # Add exception info if available
        if record.exc_info:
            log_data['exception'] = {
                'type': record.exc_info[0].__name__,
                'message': str(record.exc_info[1]),
                'traceback': self.formatException(record.exc_info)
            }
            
        # Add extra data if available
        if hasattr(record, 'extra'):
            log_data['extra'] = record.extra
            
        return json.dumps(log_data)

def initialize_logging(
    level: str = "INFO",
    app_name: str = "parrot-security-tool",
    sentry_dsn: Optional[str] = None,
    log_to_console: bool = True,
    log_to_file: bool = True,
    max_file_size_mb: int = 10,
    backup_count: int = 5,
    json_format: bool = True
) -> logging.Logger:
    """
    Initialize centralized logging configuration
    
    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        app_name: Name of the application for logger naming
        sentry_dsn: Sentry DSN URL for error tracking (if None, Sentry is disabled)
        log_to_console: Whether to log to console
        log_to_file: Whether to log to file
        max_file_size_mb: Maximum log file size in MB before rotation
        backup_count: Number of rotated log files to keep
        json_format: Whether to use JSON format for logs
        
    Returns:
        Root logger configured with handlers
    """
    # Convert level string to logging level
    log_level = LOG_LEVELS.get(level.upper(), logging.INFO)
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    
    # Clear any existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Create formatters
    if json_format:
        formatter = JsonFormatter()
    else:
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(name)s - %(message)s'
        )
    
    # Add console handler if enabled
    if log_to_console:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(log_level)
        console_handler.setFormatter(formatter)
        root_logger.addHandler(console_handler)
    
    # Add file handler if enabled
    if log_to_file:
        timestamp = datetime.datetime.now().strftime('%Y%m%d')
        file_name = f"{app_name}_{timestamp}.log"
        log_file = os.path.join(LOG_DIR, file_name)
        
        # Use rotating file handler to prevent large log files
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=max_file_size_mb * 1024 * 1024,
            backupCount=backup_count
        )
        file_handler.setLevel(log_level)
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)
    
    # Initialize Sentry integration if available and DSN is provided
    if SENTRY_AVAILABLE and sentry_dsn:
        # Configure Sentry SDK with logging integration
        sentry_logging = LoggingIntegration(
            level=logging.WARNING,  # Capture warnings and above as breadcrumbs
            event_level=logging.ERROR  # Send errors and above as events
        )
        
        sentry_sdk.init(
            dsn=sentry_dsn,
            integrations=[sentry_logging],
            
            # Associate traces with environments
            environment=os.environ.get("ENVIRONMENT", "development"),
            
            # Set traces sample rate
            traces_sample_rate=0.2,
            
            # Add application version if available
            release=os.environ.get("APP_VERSION", "0.1.0"),
        )
        
        app_logger = logging.getLogger(app_name)
        app_logger.info(f"Sentry integration initialized with environment: {os.environ.get('ENVIRONMENT', 'development')}")
    elif sentry_dsn:
        app_logger = logging.getLogger(app_name)
        app_logger.warning("Sentry SDK not available. Install with: pip install sentry-sdk")
    
    return root_logger

def get_logger(name: str, extra: Dict[str, Any] = None) -> logging.Logger:
    """
    Get a logger with the specified name and optional extra data
    
    Args:
        name: Logger name
        extra: Extra data to include in all log records
        
    Returns:
        Logger instance
    """
    logger = logging.getLogger(name)
    
    # Add adapter for extra data if provided
    if extra:
        return LoggerAdapter(logger, extra)
    
    return logger

class LoggerAdapter(logging.LoggerAdapter):
    """Custom logger adapter to add extra data to log records"""
    
    def process(self, msg, kwargs):
        # Ensure 'extra' is in kwargs
        kwargs.setdefault('extra', {})
        # Add adapter's extra data to the kwargs
        kwargs['extra']['extra'] = self.extra
        return msg, kwargs

def log_with_context(logger, level, message, **context):
    """
    Log a message with additional context
    
    Args:
        logger: Logger instance
        level: Log level (debug, info, warning, error, critical)
        message: Log message
        **context: Additional context to include in the log
    """
    log_fn = getattr(logger, level.lower())
    
    # Create extra attribute for context
    extra = {'extra': context}
    log_fn(message, extra=extra)
