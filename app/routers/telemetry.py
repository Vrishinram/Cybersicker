"""
CYBERSICKER — Real-Time Telemetry Streaming Router
Exposes both WebSocket (/ws/telemetry) and Server-Sent Events (/api/v1/telemetry/stream)
for live streaming of backend SOC triage events, live API polls, RAG hits, and PCAP scans.
"""

from __future__ import annotations

import json
import asyncio
import logging
from typing import List, Dict, Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import StreamingResponse

from app.services.telemetry import telemetry_service

logger = logging.getLogger("Cybersicker.TelemetryRouter")

router = APIRouter(tags=["Real-Time Telemetry Streaming"])


class WebSocketManager:
    """Manages active WebSocket connections from frontend SOC telemetry consoles."""

    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info("WebSocket telemetry client connected. Total active: %d", len(self.active_connections))

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info("WebSocket telemetry client disconnected. Total active: %d", len(self.active_connections))

    async def broadcast(self, message: Dict[str, Any]):
        for connection in list(self.active_connections):
            try:
                await connection.send_text(json.dumps(message))
            except Exception:
                self.disconnect(connection)


ws_manager = WebSocketManager()


# ═══════════════════════════════════════════════════════════════
# WEBSOCKET TELEMETRY ENDPOINT (/ws/telemetry)
# ═══════════════════════════════════════════════════════════════

@router.websocket("/ws/telemetry")
async def websocket_telemetry_endpoint(websocket: WebSocket):
    """
    Real-time bidirectional WebSocket stream delivering structured SOC telemetry events:
    PCAP_FLOW_PROCESSED, LIVE_API_POLL, CHROMA_RAG_MATCH, SYNTHESIS_COMPLETE, etc.
    """
    await ws_manager.connect(websocket)

    # Background task to stream queue events to this websocket
    async def event_forwarder():
        async for event in telemetry_service.subscribe():
            try:
                await websocket.send_text(json.dumps(event))
            except Exception:
                break

    forwarder_task = asyncio.create_task(event_forwarder())

    try:
        while True:
            # Keep connection alive & handle incoming pings or client directives
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
                if msg.get("action") == "ping":
                    await websocket.send_text(json.dumps({"event": "PONG", "ts": int(asyncio.get_event_loop().time() * 1000)}))
            except Exception:
                pass
    except WebSocketDisconnect:
        pass
    finally:
        forwarder_task.cancel()
        ws_manager.disconnect(websocket)


# ═══════════════════════════════════════════════════════════════
# SERVER-SENT EVENTS (SSE) ENDPOINT (/api/v1/telemetry/stream)
# ═══════════════════════════════════════════════════════════════

@router.get("/api/v1/telemetry/stream")
@router.get("/api/telemetry/stream")
async def stream_telemetry_sse(request: Request):
    """
    Server-Sent Events (SSE) stream for browsers and headless monitoring agents.
    Emits data: {"event": ...} formatted lines in real time.
    """
    async def sse_generator():
        try:
            async for event in telemetry_service.subscribe():
                if await request.is_disconnected():
                    break
                yield f"data: {json.dumps(event)}\n\n"
        except asyncio.CancelledError:
            pass

    return StreamingResponse(
        sse_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
            "Access-Control-Allow-Origin": "*"
        }
    )


@router.get("/api/v1/telemetry/events")
@router.get("/api/telemetry/events")
async def get_telemetry_history(limit: int = 25):
    """Returns the most recent buffered telemetry events."""
    return {"events": telemetry_service.get_recent(limit=limit)}

