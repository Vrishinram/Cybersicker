"""
CYBERSICKER — SOC Routers Package
Exports the Agent, Ingestion, Telemetry, and Containment routers.
"""

from app.routers.agent import router as agent_router
from app.routers.ingest import router as ingest_router
from app.routers.telemetry import router as telemetry_router
from app.routers.containment import router as containment_router

__all__ = [
    "agent_router",
    "ingest_router",
    "telemetry_router",
    "containment_router"
]
