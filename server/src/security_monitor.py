# server/src/security_monitor.py
import logging
import uuid
from flask import request, g
from datetime import datetime

def init_security_monitoring(app):
    """Initialize security monitoring middleware"""
    security_logger = logging.getLogger('security')
    
    # OBSERVATION POINT 1: Request Start Monitoring
    # This decorator creates an observation point that captures every incoming request
    @app.before_request
    def log_request_start():
        """Log request start - OBSERVATION POINT for attack detection"""
        g.request_id = str(uuid.uuid4())
        g.start_time = datetime.utcnow()
        
        # OBSERVATION: Log request information for attack pattern analysis
        app.logger.info(f"[REQ_START] {g.request_id} {request.method} {request.path} from {request.remote_addr}")
        security_logger.info(f"[REQ_START] {g.request_id} {request.method} {request.path} from {request.remote_addr}")
        
        # OBSERVATION: Force flush logs to ensure immediate recording
        for handler in security_logger.handlers:
            handler.flush()
        
        # OBSERVATION POINT 2: Suspicious Request Pattern Detection
        # This function analyzes the request for various attack patterns
        check_suspicious_request(app, security_logger)

    # OBSERVATION POINT 3: Request End Monitoring
    # This decorator creates an observation point that captures request completion and response
    @app.after_request
    def log_request_end(response):
        """Log request end - OBSERVATION POINT for response analysis"""
        duration = (datetime.utcnow() - g.start_time).total_seconds()
        
        # OBSERVATION: Log failed requests for attack pattern analysis
        if response.status_code >= 400:
            security_logger.warning(f"[REQ_FAIL] {g.request_id} {request.method} {request.path} from {request.remote_addr} status={response.status_code} duration={duration:.3f}s")
        else:
            # OBSERVATION: Log successful requests for normal traffic analysis
            app.logger.info(f"[REQ_OK] {g.request_id} {request.method} {request.path} from {request.remote_addr} status={response.status_code} duration={duration:.3f}s")
            security_logger.info(f"[REQ_OK] {g.request_id} {request.method} {request.path} from {request.remote_addr} status={response.status_code} duration={duration:.3f}s")
        
        # OBSERVATION: Force flush logs to ensure immediate recording
        for handler in security_logger.handlers:
            handler.flush()
        
        return response

def check_suspicious_request(app, security_logger):
    """Check suspicious request patterns - OBSERVATION POINT 4: Attack Pattern Detection"""
    path = request.path.lower()
    query_string = request.query_string.decode('utf-8', errors='ignore').lower()
    
    # OBSERVATION POINT 4.1: Path Traversal Detection
    # Check path traversal - check multiple possible path sources
    raw_paths = [
        request.environ.get('PATH_INFO', ''),
        request.environ.get('RAW_URI', ''),
        request.environ.get('REQUEST_URI', ''),
        str(request.path)
    ]
    
    # OBSERVATION: Debug information for path analysis
    security_logger.info(f"[DEBUG] {g.request_id} paths: {raw_paths}")
    
    for raw_path in raw_paths:
        raw_path_lower = raw_path.lower()
        if any(pattern in raw_path_lower for pattern in ['../', '..\\', '%2e%2e', '..%2f']):
            security_logger.warning(f"[PATH_TRAVERSAL] {g.request_id} path={request.path} raw_path={raw_path} from {request.remote_addr}")
            break
    
    # OBSERVATION POINT 4.2: SQL Injection Detection
    # Check SQL injection patterns
    sql_patterns = ['union', 'select', 'insert', 'delete', 'drop', 'script', 'eval']
    if any(pattern in query_string for pattern in sql_patterns):
        security_logger.warning(f"[SQL_INJECTION] {g.request_id} query={query_string} from {request.remote_addr}")
    
    # OBSERVATION POINT 4.3: Suspicious File Access Detection
    # Check suspicious file access
    suspicious_files = ['flag', 'secret', 'password', 'key', 'token', 'credential', 'config', 'env']
    if any(pattern in path for pattern in suspicious_files):
        security_logger.warning(f"[SUSPICIOUS_FILE] {g.request_id} path={request.path} from {request.remote_addr}")
    
    # OBSERVATION POINT 4.4: Suspicious User-Agent Detection
    # Check suspicious User-Agent
    user_agent = request.headers.get('User-Agent', '').lower()
    if any(pattern in user_agent for pattern in ['sqlmap', 'nikto', 'nmap', 'scanner', 'bot']):
        security_logger.warning(f"[SUSPICIOUS_UA] {g.request_id} user_agent={user_agent} from {request.remote_addr}")
