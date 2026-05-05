"""
Enhanced OpenAPI/FastAPI documentation for CYBERSICKER
Provides comprehensive API documentation with examples
"""

from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi
from typing import Dict, Any

def custom_openapi(app: FastAPI) -> Dict[str, Any]:
    """Generate custom OpenAPI schema with enhanced documentation"""
    
    if app.openapi_schema:
        return app.openapi_schema
    
    openapi_schema = get_openapi(
        title="CYBERSICKER SOC API",
        version="2.0.0",
        description="""
        # CYBERSICKER - Advanced Cybersecurity Operations Center API
        
        Complete threat intelligence and security operations platform with:
        - **Real-time threat detection** across network and endpoints
        - **Advanced threat analysis** powered by AI/ML
        - **Network vulnerability scanning** and assessment
        - **Security event correlation** and investigation
        - **Automated response capabilities** to threats
        
        ## Authentication
        All endpoints require Bearer token authentication:
        ```
        Authorization: Bearer <api_key_or_jwt_token>
        ```
        
        ## Rate Limiting
        - **Standard tier**: 100 requests per minute
        - **Premium tier**: 1000 requests per minute
        
        Rate limit info is provided in response headers:
        - `X-RateLimit-Limit`: Maximum requests allowed
        - `X-RateLimit-Remaining`: Requests remaining
        - `X-RateLimit-Reset`: Unix timestamp when limit resets
        
        ## Error Handling
        All errors follow standard format:
        ```json
        {
            "error": "ErrorType",
            "message": "Descriptive error message",
            "status_code": 400,
            "details": {}
        }
        ```
        
        ## Pagination
        Paginated endpoints support:
        - `page`: Page number (1-indexed)
        - `page_size`: Items per page (default: 20, max: 100)
        - `sort`: Field to sort by
        - `order`: asc or desc
        """,
        routes=app.routes,
        tags=[
            {
                "name": "Threat Analysis",
                "description": "Endpoints for analyzing and detecting threats"
            },
            {
                "name": "Network Scanning",
                "description": "Network vulnerability scanning and discovery"
            },
            {
                "name": "AI Agent",
                "description": "AI-powered threat investigation and chat"
            },
            {
                "name": "Hash Search",
                "description": "Search threats by file hash (MD5, SHA256)"
            },
            {
                "name": "Health",
                "description": "System health and status endpoints"
            }
        ]
    )
    
    # Add operation examples
    if "/analyze-threat" in openapi_schema.get("paths", {}):
        openapi_schema["paths"]["/analyze-threat"]["post"]["examples"] = {
            "malware_detection": {
                "summary": "Malware Detection Example",
                "value": {
                    "threat_type": "malware",
                    "indicator": "192.168.1.100",
                    "severity": "critical",
                    "context": "Detected suspicious network activity"
                }
            },
            "phishing_email": {
                "summary": "Phishing Email Detection",
                "value": {
                    "threat_type": "phishing",
                    "indicator": "attacker@fake-bank.com",
                    "severity": "high",
                    "context": "Sent to 50+ employees"
                }
            }
        }
    
    # Add security scheme
    openapi_schema["components"]["securitySchemes"] = {
        "BearerToken": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
            "description": "JWT token for API authentication"
        },
        "APIKey": {
            "type": "http",
            "scheme": "bearer",
            "description": "API key for service-to-service authentication"
        }
    }
    
    # Add response schemas
    openapi_schema["components"]["schemas"]["ThreatIndicator"] = {
        "type": "object",
        "properties": {
            "indicator": {
                "type": "string",
                "description": "IP, domain, hash, or email indicator"
            },
            "threat_type": {
                "type": "string",
                "enum": ["malware", "phishing", "ddos", "ransomware", "intrusion", "vulnerability", "anomaly"],
                "description": "Type of threat"
            },
            "severity": {
                "type": "string",
                "enum": ["critical", "high", "medium", "low", "info"],
                "description": "Threat severity level"
            },
            "confidence": {
                "type": "number",
                "minimum": 0,
                "maximum": 1,
                "description": "Confidence score (0-1)"
            },
            "source": {
                "type": "string",
                "description": "Source of the threat intelligence"
            },
            "timestamp": {
                "type": "string",
                "format": "date-time",
                "description": "When the threat was detected"
            }
        },
        "required": ["indicator", "threat_type", "severity"]
    }
    
    openapi_schema["components"]["schemas"]["ErrorResponse"] = {
        "type": "object",
        "properties": {
            "error": {"type": "string"},
            "message": {"type": "string"},
            "status_code": {"type": "integer"},
            "details": {"type": "object"}
        }
    }
    
    # Add global security requirement
    openapi_schema["security"] = [{"BearerToken": []}]
    
    app.openapi_schema = openapi_schema
    return app.openapi_schema

def add_api_documentation(app: FastAPI):
    """Apply enhanced documentation to FastAPI app"""
    app.openapi = lambda: custom_openapi(app)
    
    # Custom ReDoc UI configuration
    from fastapi.staticfiles import StaticFiles
    
    app.swagger_ui_init_oauth = {
        "usePkceWithAuthorizationCodeFlow": True
    }

# Documentation for common response patterns
RESPONSE_EXAMPLES = {
    "success_threat_analysis": {
        "summary": "Successful threat analysis",
        "value": {
            "status": "success",
            "data": {
                "indicator": "192.168.1.100",
                "threat_type": "malware",
                "severity": "high",
                "confidence": 0.95,
                "analysis": "Known C2 command and control server",
                "recommendations": [
                    "Block IP at firewall",
                    "Monitor outbound connections",
                    "Run full system scan"
                ]
            }
        }
    },
    "error_invalid_input": {
        "summary": "Invalid input error",
        "value": {
            "error": "ValidationError",
            "message": "Invalid threat indicator",
            "status_code": 422,
            "details": {
                "field": "indicator",
                "reason": "Invalid IP address format"
            }
        }
    },
    "error_rate_limited": {
        "summary": "Rate limit exceeded",
        "value": {
            "error": "RateLimitError",
            "message": "Rate limit exceeded",
            "status_code": 429,
            "details": {
                "retry_after": 60
            }
        }
    },
    "paginated_response": {
        "summary": "Paginated threat list",
        "value": {
            "items": [
                {
                    "id": 1,
                    "indicator": "192.168.1.100",
                    "threat_type": "malware",
                    "severity": "high"
                },
                {
                    "id": 2,
                    "indicator": "example.com",
                    "threat_type": "phishing",
                    "severity": "medium"
                }
            ],
            "total": 42,
            "page": 1,
            "page_size": 20,
            "total_pages": 3
        }
    }
}

# API endpoint tags
API_TAGS_METADATA = [
    {
        "name": "Threat Analysis",
        "description": "Analyze indicators and detect threats in real-time",
    },
    {
        "name": "Network Scanning",
        "description": "Perform network reconnaissance and vulnerability scanning",
    },
    {
        "name": "AI Investigation",
        "description": "AI-powered threat investigation and analysis",
    },
    {
        "name": "Intelligence",
        "description": "Access threat intelligence and indicators",
    },
    {
        "name": "Health",
        "description": "System health and operational status",
    }
]

# Endpoint specifications
ENDPOINT_SPECS = {
    "analyze_threat": {
        "description": "Analyze a security threat indicator",
        "parameters": {
            "threat_type": "Type of threat (malware, phishing, etc)",
            "indicator": "The threat indicator (IP, domain, hash, email)",
            "severity": "Expected severity level"
        },
        "responses": {
            "200": "Threat analysis completed",
            "422": "Invalid input parameters",
            "429": "Rate limit exceeded",
            "500": "Internal server error"
        }
    },
    "scan_network": {
        "description": "Perform network security scan",
        "parameters": {
            "target": "Network address or CIDR range",
            "scan_type": "Type of scan (basic, deep, stealth)",
            "timeout": "Scan timeout in seconds"
        },
        "responses": {
            "200": "Network scan results",
            "422": "Invalid network specification",
            "429": "Rate limit exceeded"
        }
    }
}
