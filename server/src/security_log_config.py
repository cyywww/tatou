# server/src/security_log_config.py
import logging
import os
from pathlib import Path

def setup_security_logging():
    """Setup security logging configuration - OBSERVATION POINT 5: Logging Infrastructure"""
    # OBSERVATION POINT 5.1: Log Directory Setup
    # Use current working directory for logs to avoid permission issues
    log_dir = Path("logs")
    log_dir.mkdir(parents=True, exist_ok=True)
    
    # OBSERVATION POINT 5.2: Security Logger Configuration
    # Configure security logger for attack detection logging
    security_logger = logging.getLogger('security')
    security_handler = logging.FileHandler(log_dir / 'security.log')
    security_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    security_logger.addHandler(security_handler)
    security_logger.setLevel(logging.INFO)
    
    # OBSERVATION: Force flush to ensure immediate log writing
    security_handler.flush()
    
    return security_logger