"""
Structured logging configuration for CYBERSICKER
Provides comprehensive logging with proper error handling and tracing
"""

import logging
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict
import traceback

# Create logs directory if it doesn't exist
LOG_DIR = Path("logs")
LOG_DIR.mkdir(exist_ok=True)

class StructuredFormatter(logging.Formatter):
    """Custom formatter for structured JSON logs"""
    
    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }
        
        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = {
                "type": record.exc_info[0].__name__,
                "message": str(record.exc_info[1]),
                "traceback": traceback.format_exc(),
            }
        
        # Add extra fields if provided
        if hasattr(record, "extra_data"):
            log_data.update(record.extra_data)
        
        return json.dumps(log_data)

def setup_logging(
    name: str = "cybersicker",
    level: int = logging.INFO,
    log_file: str = None
) -> logging.Logger:
    """
    Configure and return a logger with both file and console handlers
    
    Args:
        name: Logger name
        level: Logging level (default: INFO)
        log_file: Optional log file path (default: logs/{name}.log)
    
    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # Prevent duplicate handlers
    if logger.handlers:
        return logger
    
    # Set up file handler
    if log_file is None:
        log_file = LOG_DIR / f"{name}.log"
    else:
        log_file = Path(log_file)
        log_file.parent.mkdir(parents=True, exist_ok=True)
    
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(level)
    file_handler.setFormatter(StructuredFormatter())
    logger.addHandler(file_handler)
    
    # Set up console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    console_formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    
    return logger

# Application loggers
api_logger = setup_logging("cybersicker.api", level=logging.INFO)
app_logger = setup_logging("cybersicker.app", level=logging.INFO)
agent_logger = setup_logging("cybersicker.agent", level=logging.INFO)
security_logger = setup_logging("cybersicker.security", level=logging.WARNING)

def log_api_call(method: str, endpoint: str, status_code: int, duration_ms: float, **kwargs):
    """Log API calls with relevant metadata"""
    api_logger.info(
        f"API Call: {method} {endpoint} - {status_code}",
        extra={"extra_data": {"duration_ms": duration_ms, **kwargs}}
    )

def log_error(logger: logging.Logger, error: Exception, context: Dict[str, Any] = None):
    """Log errors with full context"""
    logger.error(
        f"Error: {error.__class__.__name__}",
        exc_info=True,
        extra={"extra_data": context or {}}
    )

def log_security_event(event_type: str, severity: str, details: Dict[str, Any]):
    """Log security-related events"""
    security_logger.warning(
        f"Security Event: {event_type} [{severity}]",
        extra={"extra_data": details}
    )
