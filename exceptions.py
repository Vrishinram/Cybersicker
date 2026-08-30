"""
Custom exception classes and error handling for CYBERSICKER
Provides structured error responses and proper HTTP status codes
"""

from typing import Optional, Dict, Any
from fastapi import status

class CybersickerException(Exception):
    """Base exception for all CYBERSICKER errors"""
    def __init__(
        self,
        message: str,
        status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR,
        details: Optional[Dict[str, Any]] = None
    ):
        self.message = message
        self.status_code = status_code
        self.details = details or {}
        super().__init__(self.message)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "error": self.__class__.__name__,
            "message": self.message,
            "status_code": self.status_code,
            "details": self.details,
        }

class ValidationError(CybersickerException):
    """Raised when input validation fails"""
    def __init__(self, message: str, details: Optional[Dict] = None):
        super().__init__(
            message,
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            details=details
        )

class AuthenticationError(CybersickerException):
    """Raised when authentication fails"""
    def __init__(self, message: str = "Authentication failed"):
        super().__init__(
            message,
            status_code=status.HTTP_401_UNAUTHORIZED
        )

class AuthorizationError(CybersickerException):
    """Raised when user lacks required permissions"""
    def __init__(self, message: str = "Insufficient permissions"):
        super().__init__(
            message,
            status_code=status.HTTP_403_FORBIDDEN
        )

class ResourceNotFoundError(CybersickerException):
    """Raised when requested resource is not found"""
    def __init__(self, resource: str, resource_id: Any = None):
        message = f"{resource} not found"
        if resource_id:
            message += f" (ID: {resource_id})"
        super().__init__(
            message,
            status_code=status.HTTP_404_NOT_FOUND,
            details={"resource": resource, "resource_id": resource_id}
        )

class ExternalServiceError(CybersickerException):
    """Raised when external service call fails"""
    def __init__(
        self,
        service_name: str,
        error_message: str,
        details: Optional[Dict] = None
    ):
        super().__init__(
            f"External service error: {service_name}",
            status_code=status.HTTP_502_BAD_GATEWAY,
            details={
                "service": service_name,
                "error": error_message,
                **(details or {})
            }
        )

class RateLimitError(CybersickerException):
    """Raised when rate limit is exceeded"""
    def __init__(self, retry_after: int = 60):
        super().__init__(
            "Rate limit exceeded",
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            details={"retry_after": retry_after}
        )

class DataProcessingError(CybersickerException):
    """Raised when data processing fails"""
    def __init__(self, message: str, step: str, details: Optional[Dict] = None):
        super().__init__(
            f"Data processing error: {message}",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            details={"step": step, **(details or {})}
        )

def create_error_response(error: Exception) -> Dict[str, Any]:
    """Convert exception to standardized error response"""
    if isinstance(error, CybersickerException):
        return error.to_dict()
    
    return {
        "error": error.__class__.__name__,
        "message": str(error),
        "status_code": status.HTTP_500_INTERNAL_SERVER_ERROR,
        "details": {},
    }
