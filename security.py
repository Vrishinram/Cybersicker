"""
Security hardening module for CYBERSICKER
Implements rate limiting, CORS, security headers, and authentication
"""

import time
from typing import Dict, Optional, Tuple
from collections import defaultdict
from fastapi import Header, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
import jwt
from datetime import datetime, timedelta

class RateLimiter:
    """Token bucket rate limiter with per-endpoint and per-IP tracking"""
    
    def __init__(self, requests_per_minute: int = 60):
        self.requests_per_minute = requests_per_minute
        self.requests_per_second = requests_per_minute / 60
        self.buckets: Dict[str, Tuple[float, int]] = {}
        self.cleanup_interval = 3600  # Clean old entries every hour
        self.last_cleanup = time.time()
    
    def _cleanup_old_entries(self):
        """Remove old bucket entries"""
        current_time = time.time()
        if current_time - self.last_cleanup > self.cleanup_interval:
            cutoff_time = current_time - (24 * 3600)  # 24 hours
            self.buckets = {
                k: v for k, v in self.buckets.items()
                if v[0] > cutoff_time
            }
            self.last_cleanup = current_time
    
    def is_allowed(self, key: str) -> Tuple[bool, Dict]:
        """
        Check if request is allowed and return rate limit info
        
        Returns:
            (is_allowed, rate_limit_info)
        """
        self._cleanup_old_entries()
        
        current_time = time.time()
        
        if key not in self.buckets:
            # New bucket
            self.buckets[key] = (current_time, self.requests_per_minute)
            return True, {
                "limit": self.requests_per_minute,
                "remaining": self.requests_per_minute - 1,
                "reset": int(current_time + 60),
            }
        
        last_time, tokens = self.buckets[key]
        
        # Refill tokens based on time elapsed
        elapsed = current_time - last_time
        tokens_to_add = elapsed * self.requests_per_second
        tokens = min(self.requests_per_minute, tokens + tokens_to_add)
        
        if tokens >= 1:
            tokens -= 1
            self.buckets[key] = (current_time, tokens)
            return True, {
                "limit": self.requests_per_minute,
                "remaining": int(tokens),
                "reset": int(current_time + 60),
            }
        else:
            retry_after = (1 - tokens) / self.requests_per_second
            return False, {
                "limit": self.requests_per_minute,
                "remaining": 0,
                "retry_after": int(retry_after + 1),
            }

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses"""
    
    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        
        # Security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "font-src 'self'; "
            "connect-src 'self' https:;"
        )
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = (
            "geolocation=(), "
            "microphone=(), "
            "camera=(), "
            "payment=(), "
            "usb=(), "
            "magnetometer=(), "
            "gyroscope=(), "
            "accelerometer=()"
        )
        
        # Remove server info
        response.headers.pop("Server", None)
        response.headers["Server"] = "CYBERSICKER/2.0"
        
        return response

class RateLimitMiddleware(BaseHTTPMiddleware):
    """Rate limiting middleware"""
    
    def __init__(self, app, requests_per_minute: int = 60):
        super().__init__(app)
        self.rate_limiter = RateLimiter(requests_per_minute)
        self.exempt_paths = {
            "/health",
            "/docs",
            "/openapi.json",
        }
    
    async def dispatch(self, request: Request, call_next) -> Response:
        # Skip rate limiting for exempt paths
        if request.url.path in self.exempt_paths:
            return await call_next(request)
        
        # Get client IP
        client_ip = request.client.host if request.client else "unknown"
        
        # Create rate limit key (IP + endpoint)
        rate_limit_key = f"{client_ip}:{request.url.path}"
        
        # Check rate limit
        is_allowed, rate_info = self.rate_limiter.is_allowed(rate_limit_key)
        
        if not is_allowed:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded",
                headers={"Retry-After": str(rate_info.get("retry_after", 60))},
            )
        
        # Add rate limit headers
        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(rate_info["limit"])
        response.headers["X-RateLimit-Remaining"] = str(rate_info["remaining"])
        response.headers["X-RateLimit-Reset"] = str(rate_info["reset"])
        
        return response

class APIKeyAuthenticator:
    """API key validation"""
    
    def __init__(self, valid_keys: Dict[str, str]):
        self.valid_keys = valid_keys
    
    def validate_key(self, api_key: str) -> Optional[str]:
        """Validate API key and return associated user/client"""
        if api_key in self.valid_keys:
            return self.valid_keys[api_key]
        return None

class JWTAuthenticator:
    """JWT token validation"""
    
    def __init__(self, secret_key: str, algorithm: str = "HS256"):
        self.secret_key = secret_key
        self.algorithm = algorithm
    
    def create_token(
        self,
        user_id: str,
        expires_in_hours: int = 24
    ) -> str:
        """Create JWT token"""
        payload = {
            "user_id": user_id,
            "exp": datetime.utcnow() + timedelta(hours=expires_in_hours),
            "iat": datetime.utcnow(),
        }
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
    
    def validate_token(self, token: str) -> Optional[Dict]:
        """Validate and decode JWT token"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            return payload
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
    
    def get_user_from_token(self, token: str) -> Optional[str]:
        """Extract user ID from token"""
        payload = self.validate_token(token)
        if payload:
            return payload.get("user_id")
        return None

def require_api_key(
    authorization: str = Header(None),
    authenticator: Optional[APIKeyAuthenticator] = None
) -> str:
    """Dependency for API key authentication"""
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API key",
        )
    
    try:
        scheme, credentials = authorization.split()
        if scheme.lower() != "bearer":
            raise ValueError("Invalid authentication scheme")
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization header",
        )
    
    if authenticator:
        user = authenticator.validate_key(credentials)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API key",
            )
        return user
    
    return credentials

def require_jwt_token(
    authorization: str = Header(None),
    jwt_auth: Optional[JWTAuthenticator] = None
) -> Dict:
    """Dependency for JWT authentication"""
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication token",
        )
    
    try:
        scheme, token = authorization.split()
        if scheme.lower() != "bearer":
            raise ValueError("Invalid authentication scheme")
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization header",
        )
    
    if jwt_auth:
        payload = jwt_auth.validate_token(token)
        if not payload:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired token",
            )
        return payload
    
    return {}
