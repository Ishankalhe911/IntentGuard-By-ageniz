"""Real-time Glass-Box WebSocket manager with XSS/prompt-injection sanitization and ring-buffer history."""
from __future__ import annotations

import asyncio
import copy
import json
import logging
import threading
import time
import uuid
from collections import deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Deque, Dict, List, Optional, Set

from src.pillar3_capture_shield.settlement_client import sanitize_dashboard_summary

LOGGER = logging.getLogger("intentguard.pillar4.ws")

MAX_EVENT_HISTORY = 200
MAX_STRING_FIELD_LEN = 500


def _sanitize_payload_value(value: Any) -> Any:
    """Recursively sanitize string values before broadcasting to Merchant Dashboard clients."""
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return sanitize_dashboard_summary(value)[:MAX_STRING_FIELD_LEN]
    if isinstance(value, dict):
        return {str(k): _sanitize_payload_value(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_sanitize_payload_value(item) for item in value]
    return sanitize_dashboard_summary(str(value))[:MAX_STRING_FIELD_LEN]


@dataclass(frozen=True)
class GlassBoxEvent:
    event_id: str
    event_type: str
    timestamp_utc: str
    epoch_seconds: float
    order_id: Optional[str]
    incident_id: Optional[str]
    severity: str  # "INFO" | "WARNING" | "CRITICAL" | "SUCCESS"
    headline: str
    payload: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class WebSocketManager:
    """Thread-safe + async-compatible broadcaster for Pillar 4 Glass-Box telemetry."""

    def __init__(self, max_history: int = MAX_EVENT_HISTORY) -> None:
        self._lock = threading.RLock()
        self._connections: Set[Any] = set()
        self._history: Deque[GlassBoxEvent] = deque(maxlen=max(10, int(max_history)))

    @property
    def active_connection_count(self) -> int:
        with self._lock:
            return len(self._connections)

    async def connect(self, websocket: Any) -> None:
        await websocket.accept()
        with self._lock:
            self._connections.add(websocket)
            recent = [evt.to_dict() for evt in self._history]
        try:
            await websocket.send_text(
                json.dumps(
                    {
                        "type": "INITIAL_SNAPSHOT",
                        "active_connections": self.active_connection_count,
                        "recent_events": recent,
                    },
                    default=str,
                )
            )
        except Exception:
            self.disconnect(websocket)

    def disconnect(self, websocket: Any) -> None:
        with self._lock:
            self._connections.discard(websocket)

    def get_recent_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        capped = max(1, min(int(limit), MAX_EVENT_HISTORY))
        with self._lock:
            items = list(self._history)[-capped:]
        items.reverse()
        return [evt.to_dict() for evt in items]

    def record_event(
        self,
        *,
        event_type: str,
        headline: str,
        payload: Optional[Dict[str, Any]] = None,
        order_id: Optional[str] = None,
        incident_id: Optional[str] = None,
        severity: str = "INFO",
        now: Optional[float] = None,
    ) -> GlassBoxEvent:
        """Record a sanitized Glass-Box event from synchronous or async code and schedule broadcast."""
        ts = float(now) if now is not None else time.time()
        iso_ts = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
        clean_payload = _sanitize_payload_value(copy.deepcopy(payload or {}))
        clean_headline = sanitize_dashboard_summary(headline)[:240]
        evt = GlassBoxEvent(
            event_id=f"GB-EVT-{uuid.uuid4().hex[:12].upper()}",
            event_type=str(event_type).strip().upper(),
            timestamp_utc=iso_ts,
            epoch_seconds=ts,
            order_id=str(order_id).strip() if order_id else None,
            incident_id=str(incident_id).strip() if incident_id else None,
            severity=str(severity).strip().upper(),
            headline=clean_headline,
            payload=clean_payload if isinstance(clean_payload, dict) else {"data": clean_payload},
        )
        with self._lock:
            self._connections_snapshot = list(self._connections)
            self._history.append(evt)

        if self._connections_snapshot:
            try:
                loop = asyncio.get_running_loop()
                loop.create_task(self._broadcast_event(evt, self._connections_snapshot))
            except RuntimeError:
                # Called from a synchronous worker thread outside an active asyncio loop.
                pass
        return evt

    async def broadcast(
        self,
        *,
        event_type: str,
        headline: str,
        payload: Optional[Dict[str, Any]] = None,
        order_id: Optional[str] = None,
        incident_id: Optional[str] = None,
        severity: str = "INFO",
        now: Optional[float] = None,
    ) -> GlassBoxEvent:
        evt = self.record_event(
            event_type=event_type,
            headline=headline,
            payload=payload,
            order_id=order_id,
            incident_id=incident_id,
            severity=severity,
            now=now,
        )
        with self._lock:
            targets = list(self._connections)
        if targets:
            await self._broadcast_event(evt, targets)
        return evt

    async def _broadcast_event(self, evt: GlassBoxEvent, targets: List[Any]) -> None:
        serialized = json.dumps({"type": "GLASSBOX_EVENT", "event": evt.to_dict()}, default=str)
        stale: List[Any] = []
        for ws in targets:
            try:
                await ws.send_text(serialized)
            except Exception:
                stale.append(ws)
        for ws in stale:
            self.disconnect(ws)