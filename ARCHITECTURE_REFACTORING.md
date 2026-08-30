"""
Module organization and refactoring guide for CYBERSICKER
Proposes new project structure for better maintainability
"""

# Proposed directory structure:
"""
cybersicker/
├── core/
│   ├── __init__.py
│   ├── config.py              # Configuration management
│   ├── exceptions.py          # Exception classes (moved here)
│   ├── logging_config.py      # Logging setup (moved here)
│   └── constants.py           # Global constants
│
├── models/
│   ├── __init__.py
│   ├── threat.py              # Threat-related models
│   ├── scan.py                # Scan-related models
│   ├── user.py                # User models
│   └── base.py                # Base model classes
│
├── repositories/
│   ├── __init__.py
│   ├── base.py                # Base repository (from database.py)
│   ├── threat_repository.py   # Threat data access
│   └── scan_repository.py     # Scan data access
│
├── services/
│   ├── __init__.py
│   ├── threat_analyzer.py     # Threat analysis service
│   ├── network_scanner.py     # Network scanning service
│   ├── ai_agent.py            # AI agent service
│   └── cache_manager.py       # Caching service
│
├── api/
│   ├── __init__.py
│   ├── routes/
│   │   ├── __init__.py
│   │   ├── threats.py         # Threat analysis endpoints
│   │   ├── scans.py           # Network scan endpoints
│   │   ├── agent.py           # AI agent endpoints
│   │   └── health.py          # Health check endpoints
│   ├── middleware/
│   │   ├── __init__.py
│   │   ├── security.py        # Security middleware
│   │   ├── logging.py         # Logging middleware
│   │   └── error_handler.py   # Error handling
│   └── schemas.py             # Pydantic schemas
│
├── ui/
│   ├── streamlit_app.py       # Main Streamlit app
│   ├── pages/
│   │   ├── dashboard.py
│   │   ├── threat_analysis.py
│   │   ├── network_scan.py
│   │   └── settings.py
│   └── components/
│       ├── charts.py
│       └── alerts.py
│
├── utils/
│   ├── __init__.py
│   ├── validation.py          # Input validation (moved here)
│   ├── sanitization.py        # Data sanitization
│   └── formatters.py          # Output formatting
│
├── security/
│   ├── __init__.py
│   ├── authentication.py      # Auth from security.py
│   ├── authorization.py       # Authorization
│   └── rate_limiter.py        # Rate limiting
│
├── cache/
│   ├── __init__.py
│   ├── cache.py               # Caching logic (moved here)
│   └── cache_manager.py       # Cache management
│
├── database/
│   ├── __init__.py
│   ├── connection.py          # DB connection (from database.py)
│   ├── migrations.py          # Schema migrations
│   └── seed_data.py           # Initial data
│
├── tests/
│   ├── __init__.py
│   ├── unit/
│   │   ├── test_threats.py
│   │   ├── test_scans.py
│   │   └── test_validation.py
│   ├── integration/
│   │   └── test_workflows.py
│   └── fixtures/
│       └── conftest.py        # Pytest configuration
│
├── docs/
│   ├── api_docs.md
│   ├── architecture.md
│   ├── deployment.md
│   └── contributing.md
│
├── main.py                    # Application entry point
├── requirements.txt
├── .env.example
├── .gitignore
└── README.md
"""

# Module organization principles

ORGANIZATION_PRINCIPLES = {
    "Single Responsibility": [
        "Each module has one reason to change",
        "Threats handled by threat service",
        "Scans handled by scan service",
        "Auth handled by security module"
    ],
    "Dependency Inversion": [
        "Services depend on abstractions (Repository pattern)",
        "API routes depend on services",
        "Tests depend on mock implementations"
    ],
    "Separation of Concerns": [
        "API layer handles HTTP",
        "Service layer handles business logic",
        "Repository layer handles data access",
        "Core layer handles configuration and setup"
    ],
    "DRY (Don't Repeat Yourself)": [
        "Shared utilities in utils/ module",
        "Base classes in models/ and repositories/",
        "Reusable middleware in api/middleware/"
    ]
}

# Import organization

IMPORT_PATTERNS = {
    "core_imports": "from cybersicker.core import ...",
    "model_imports": "from cybersicker.models import ...",
    "service_imports": "from cybersicker.services import ...",
    "api_imports": "from cybersicker.api import ...",
    "test_imports": "from cybersicker.tests import ..."
}

# Refactoring roadmap

REFACTORING_ROADMAP = {
    "Phase 1 - Structure": {
        "duration": "2 weeks",
        "tasks": [
            "Create new directory structure",
            "Move and reorganize existing code",
            "Update imports throughout",
            "Verify all tests pass"
        ]
    },
    "Phase 2 - Module Isolation": {
        "duration": "1 week",
        "tasks": [
            "Implement dependency injection",
            "Create service layer abstractions",
            "Extract business logic from routes",
            "Add service tests"
        ]
    },
    "Phase 3 - Documentation": {
        "duration": "1 week",
        "tasks": [
            "Document module responsibilities",
            "Add architecture diagrams",
            "Update contributing guidelines",
            "Create module-level docstrings"
        ]
    },
    "Phase 4 - Integration": {
        "duration": "1 week",
        "tasks": [
            "Update main.py entry point",
            "Verify end-to-end workflow",
            "Performance testing",
            "Deploy to staging"
        ]
    }
}

# Example of modular service

class ThreatAnalysisService:
    """
    Service layer for threat analysis
    Example of extracted business logic
    """
    
    def __init__(self, threat_repo, cache_manager, ai_agent):
        self.threat_repo = threat_repo
        self.cache = cache_manager
        self.ai_agent = ai_agent
    
    async def analyze_threat(self, indicator: str, threat_type: str) -> dict:
        # Check cache first
        cached_result = self.cache.get(f"threat:{indicator}")
        if cached_result:
            return cached_result
        
        # Check repository
        existing_threat = self.threat_repo.find_by_indicator(indicator)
        if existing_threat:
            return existing_threat.to_dict()
        
        # Use AI agent for analysis
        analysis = await self.ai_agent.analyze(indicator, threat_type)
        
        # Store in repository
        self.threat_repo.create(analysis)
        
        # Cache result
        self.cache.set(f"threat:{indicator}", analysis, ttl=3600)
        
        return analysis

# Example of API route using service

from fastapi import APIRouter, Depends

router = APIRouter()

def get_threat_service():
    """Dependency injection for threat service"""
    from cybersicker.repositories.threat_repository import ThreatIndicatorRepository
    from cybersicker.cache.cache_manager import CacheManager
    from cybersicker.services.ai_agent import AIAgent
    
    return ThreatAnalysisService(
        threat_repo=ThreatIndicatorRepository(),
        cache_manager=CacheManager(),
        ai_agent=AIAgent()
    )

@router.post("/analyze-threat")
async def analyze_threat(
    indicator: str,
    threat_type: str,
    service: ThreatAnalysisService = Depends(get_threat_service)
):
    """
    Analyze threat indicator
    
    Service handles all business logic
    Route handles HTTP layer only
    """
    result = await service.analyze_threat(indicator, threat_type)
    return {"status": "success", "data": result}

# Configuration management example

class Config:
    """Centralized configuration from core/config.py"""
    
    # Database
    DATABASE_URL: str
    DATABASE_ECHO: bool = False
    
    # API
    API_TITLE: str = "CYBERSICKER API"
    API_VERSION: str = "2.0"
    API_PREFIX: str = "/api"
    
    # Security
    SECRET_KEY: str
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRATION_HOURS: int = 24
    
    # Caching
    CACHE_MAX_SIZE: int = 1000
    CACHE_DEFAULT_TTL: int = 3600
    
    # Logging
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "structured"
    
    @classmethod
    def from_env(cls):
        """Load configuration from environment"""
        import os
        return cls(
            DATABASE_URL=os.getenv("DATABASE_URL"),
            SECRET_KEY=os.getenv("SECRET_KEY"),
            # ... other fields
        )
