"""
CYBERSICKER — Centralized Backend Telemetry Service
Emits granular SOC telemetry events over in-memory queues and SSE/WebSocket channels.
"""

import time
import asyncio
from typing import Dict, Any, List
from collections import deque

class TelemetryBroadcaster:
    """Maintains a ring buffer of backend telemetry events and notifies active subscribers."""

    def __init__(self, max_history: int = 100):
        self._history: deque[Dict[str, Any]] = deque(maxlen=max_history)
        self._listeners: List[asyncio.Queue] = []

    def emit(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Records an event and broadcasts to all listening subscribers."""
        if "timestamp" not in event_data:
            event_data["timestamp"] = int(time.time() * 1000)

        self._history.append(event_data)

        # Broadcast to async queues
        for q in list(self._listeners):
            try:
                q.put_nowait(event_data)
            except Exception:
                pass

        return event_data

    def get_recent(self, limit: int = 30) -> List[Dict[str, Any]]:
        """Returns the most recent events."""
        items = list(self._history)
        return items[-limit:]

    async def subscribe(self):
        """Async generator yielding new telemetry events."""
        q = asyncio.Queue()
        self._listeners.append(q)
        try:
            while True:
                event = await q.get()
                yield event
        finally:
            if q in self._listeners:
                self._listeners.remove(q)


# Global singleton instance
telemetry_service = TelemetryBroadcaster()

