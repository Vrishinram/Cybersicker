"""
Input validation and sanitization utilities for CYBERSICKER API
Provides comprehensive validation for all incoming requests
"""

import re
from typing import Any, Optional, List, Dict
from pydantic import BaseModel, Field, validator, root_validator
from enum import Enum

class SeverityLevel(str, Enum):
    """Threat severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class ThreatType(str, Enum):
    """Supported threat types"""
    MALWARE = "malware"
    PHISHING = "phishing"
    DDoS = "ddos"
    RANSOMWARE = "ransomware"
    INTRUSION = "intrusion"
    VULNERABILITY = "vulnerability"
    ANOMALY = "anomaly"
    UNKNOWN = "unknown"

# Regex patterns for validation
IP_PATTERN = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)
DOMAIN_PATTERN = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*"
    r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
)
EMAIL_PATTERN = re.compile(
    r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
)
MD5_PATTERN = re.compile(r"^[a-fA-F0-9]{32}$")
SHA256_PATTERN = re.compile(r"^[a-fA-F0-9]{64}$")

def validate_ip_address(ip: str) -> bool:
    """Validate IPv4 address format"""
    return bool(IP_PATTERN.match(ip))

def validate_domain(domain: str) -> bool:
    """Validate domain name format"""
    if len(domain) > 253:
        return False
    return bool(DOMAIN_PATTERN.match(domain))

def validate_email(email: str) -> bool:
    """Validate email address format"""
    return bool(EMAIL_PATTERN.match(email))

def validate_hash(hash_value: str) -> str:
    """Validate and identify hash type (MD5, SHA256, etc.)"""
    hash_value = hash_value.lower()
    if MD5_PATTERN.match(hash_value):
        return "md5"
    elif SHA256_PATTERN.match(hash_value):
        return "sha256"
    return None

def sanitize_string(value: str, max_length: int = 1000) -> str:
    """Sanitize string input"""
    if not isinstance(value, str):
        raise ValueError("Input must be a string")
    
    # Remove leading/trailing whitespace
    value = value.strip()
    
    # Limit length
    if len(value) > max_length:
        raise ValueError(f"String exceeds maximum length of {max_length}")
    
    # Remove null bytes
    value = value.replace("\x00", "")
    
    return value

def sanitize_dict(data: Dict[str, Any], max_depth: int = 10) -> Dict[str, Any]:
    """Recursively sanitize dictionary"""
    if max_depth <= 0:
        raise ValueError("Dictionary nesting too deep")
    
    sanitized = {}
    for key, value in data.items():
        # Sanitize key
        if not isinstance(key, str):
            key = str(key)
        key = sanitize_string(key, max_length=100)
        
        # Sanitize value
        if isinstance(value, dict):
            sanitized[key] = sanitize_dict(value, max_depth - 1)
        elif isinstance(value, list):
            sanitized[key] = [
                sanitize_dict(v, max_depth - 1) if isinstance(v, dict)
                else sanitize_string(str(v)) if isinstance(v, str)
                else v
                for v in value
            ]
        elif isinstance(value, str):
            sanitized[key] = sanitize_string(value)
        else:
            sanitized[key] = value
    
    return sanitized

# Pydantic models for API validation

class ThreatAnalysisRequest(BaseModel):
    """Request model for threat analysis"""
    threat_type: ThreatType
    indicator: str = Field(..., min_length=1, max_length=500)
    severity: Optional[SeverityLevel] = SeverityLevel.INFO
    context: Optional[str] = Field(None, max_length=2000)
    
    @validator("indicator")
    def validate_indicator(cls, v):
        return sanitize_string(v)
    
    @validator("context")
    def validate_context(cls, v):
        if v is None:
            return v
        return sanitize_string(v)

class NetworkScanRequest(BaseModel):
    """Request model for network scanning"""
    target: str = Field(..., min_length=1, max_length=255)
    scan_type: str = Field(default="basic", regex="^(basic|deep|stealth)$")
    timeout: int = Field(default=30, ge=5, le=300)
    
    @validator("target")
    def validate_target(cls, v):
        sanitized = sanitize_string(v)
        if validate_ip_address(sanitized) or validate_domain(sanitized):
            return sanitized
        raise ValueError("Invalid IP address or domain")

class AgentQueryRequest(BaseModel):
    """Request model for AI agent queries"""
    query: str = Field(..., min_length=1, max_length=5000)
    context_limit: int = Field(default=5, ge=1, le=20)
    temperature: float = Field(default=0.7, ge=0.0, le=1.0)
    
    @validator("query")
    def validate_query(cls, v):
        return sanitize_string(v)

class HashSearchRequest(BaseModel):
    """Request model for hash-based searches"""
    hash_value: str = Field(..., min_length=32, max_length=64)
    
    @validator("hash_value")
    def validate_hash_value(cls, v):
        v = sanitize_string(v).lower()
        hash_type = validate_hash(v)
        if not hash_type:
            raise ValueError("Invalid hash format (must be MD5 or SHA256)")
        return v

class BatchAnalysisRequest(BaseModel):
    """Request model for batch threat analysis"""
    indicators: List[str] = Field(..., min_items=1, max_items=100)
    threat_type: Optional[ThreatType] = ThreatType.UNKNOWN
    
    @validator("indicators")
    def validate_indicators(cls, v):
        return [sanitize_string(indicator, max_length=255) for indicator in v]

class ConfigurationUpdate(BaseModel):
    """Request model for configuration updates"""
    key: str = Field(..., regex="^[A-Z_]+$")
    value: Any
    environment: str = Field(default="dev", regex="^(dev|staging|prod)$")
    
    @validator("key")
    def validate_key(cls, v):
        if len(v) > 100:
            raise ValueError("Configuration key too long")
        return v
