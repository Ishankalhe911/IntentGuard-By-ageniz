"""
Pillar 1 (File 3/3): Inbound-to-Outbound Webhook Refund Echo Mutex & Idempotency Guard
Location: src/pillar1_velocity_engine/webhook_mutex.py

MVP contract:
- One merchant, one PayPal purchase unit, one authorization, one full capture per order.
- One logical refund operation per capture. A provider-confirmed FAILED refund is terminal
  in this MVP; do not resubmit it as a new attempt. Ambiguous transport outcomes are reconciled.
- An expired PROCESSING lease becomes RECONCILIATION_REQUIRED; it is never treated as
  proof that PayPal did not execute the request.
- Every completion requires the current, one-time claim token.
- SQLite is the durable source for capture links, outbound operations, and inbound webhook
  locks. The in-process RLock protects this single-process MVP; it is not a distributed lock.

Legacy SQLite compatibility:
- Preserves the earlier `mutex_capture_links` and `mutex_outbound_ops` tables.
- Migrates the immediately preceding `webhook_capture_links` and `outbound_refund_ops`
  table names/JSON column names into the canonical legacy-compatible tables.
"""

from __future__ import annotations

import copy
from dataclasses import asdict, dataclass, field
from decimal import Decimal
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import secrets
import sqlite3
import sys
import threading
import time
from typing import Any, Dict, List, Optional, Set, Tuple


def _load_sibling_module(mod_name: str, pkg_import_name: str) -> Any:
    if pkg_import_name in sys.modules:
        sys.modules.setdefault(mod_name, sys.modules[pkg_import_name])
        return sys.modules[pkg_import_name]
    if mod_name in sys.modules:
        return sys.modules[mod_name]
    here = Path(__file__).resolve().parent
    for candidate_dir in (here, here.parent / "pillar1_velocity_engine"):
        candidate = candidate_dir / f"{mod_name}.py"
        if candidate.is_file():
            spec = importlib.util.spec_from_file_location(mod_name, candidate)
            if spec is not None and spec.loader is not None:
                module = importlib.util.module_from_spec(spec)
                sys.modules[mod_name] = module
                spec.loader.exec_module(module)
                return module
    raise ImportError(f"Cannot locate module '{mod_name}'")


try:
    from .state_engine import PAYPAL_SUPPORTED_CURRENCIES, _normalize_amount, validate_financial_amount
except ImportError:
    _state_engine_module = _load_sibling_module(
        "state_engine", "src.pillar1_velocity_engine.state_engine"
    )
    PAYPAL_SUPPORTED_CURRENCIES = _state_engine_module.PAYPAL_SUPPORTED_CURRENCIES
    _normalize_amount = _state_engine_module._normalize_amount
    validate_financial_amount = _state_engine_module.validate_financial_amount


DEFAULT_WEBHOOK_MUTEX_TTL_SECONDS = 120
DEFAULT_MAPPING_TTL_SECONDS = 96 * 3600
DEFAULT_OUTBOUND_OP_LEASE_SECONDS = 120
DEFAULT_MAX_BLOCKED_LOG_SIZE = 500

VALID_OUTBOUND_OUTCOMES = frozenset(
    {"SUCCEEDED", "FAILED", "PENDING", "RECONCILIATION_REQUIRED", "NOT_SUBMITTED", "REJECTED"}
)


@dataclass
class WebhookRefundLock:
    order_id: Optional[str]
    capture_id: str
    webhook_event_id: str
    origin: str = "ORIGIN_PAYPAL_WEBHOOK"
    acquired_at: float = field(default_factory=time.time)
    expires_at: float = 0.0


@dataclass
class BlockedRefundEchoEvent:
    order_id: Optional[str]
    capture_id: str
    webhook_event_id: str
    blocked_at: float
    caller_source: str
    message: str


@dataclass
class OutboundRefundOperation:
    operation_id: str
    capture_id: str
    order_id: Optional[str]
    amount: str
    currency: str
    request_fingerprint: str
    status: str
    paypal_request_id: str
    claim_token: str
    generation: int = 1
    updated_at: float = field(default_factory=time.time)
    reclaimed_count: int = 0
    paypal_refund_id: Optional[str] = None
    provider_status: Optional[str] = None
    reason: Optional[str] = None
    provider_error_code: Optional[str] = None
    provider_http_status: Optional[int] = None
    provider_debug_id: Optional[str] = None


def _require_finite_time(value: Optional[float], field_name: str = "now") -> float:
    if value is None:
        return time.time()
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(float(value)):
        raise ValueError(f"{field_name} must be a finite Unix timestamp.")
    return float(value)


class WebhookRefundMutex:
    """Single-process MVP refund coordinator with durable SQLite operation state."""

    def __init__(
        self,
        ttl_seconds: int = DEFAULT_WEBHOOK_MUTEX_TTL_SECONDS,
        mapping_ttl_seconds: int = DEFAULT_MAPPING_TTL_SECONDS,
        outbound_op_lease_seconds: int = DEFAULT_OUTBOUND_OP_LEASE_SECONDS,
        max_blocked_log_size: int = DEFAULT_MAX_BLOCKED_LOG_SIZE,
        db_path: Optional[str] = None,
    ) -> None:
        if ttl_seconds <= 0 or outbound_op_lease_seconds <= 0:
            raise ValueError("Webhook and outbound-operation lease TTLs must be positive.")
        if max_blocked_log_size < 0:
            raise ValueError("max_blocked_log_size cannot be negative.")

        self.ttl_seconds = int(ttl_seconds)
        self.mapping_ttl_seconds = int(mapping_ttl_seconds)
        self.outbound_op_lease_seconds = int(outbound_op_lease_seconds)
        self.max_blocked_log_size = int(max_blocked_log_size)
        self.db_path = db_path
        self._lock = threading.RLock()

        self._locks_by_capture_id: Dict[str, WebhookRefundLock] = {}
        self._capture_to_order: Dict[str, str] = {}
        self._order_to_captures: Dict[str, Set[str]] = {}
        self._capture_link_timestamps: Dict[str, float] = {}
        self._outbound_ops: Dict[str, OutboundRefundOperation] = {}
        self._active_capture_op: Dict[str, str] = {}
        self._generation_counter = 0
        self._blocked_echo_log: List[BlockedRefundEchoEvent] = []

        if self.db_path:
            self._init_db()
            self._load_persisted_state()

    # ------------------------------------------------------------------
    # SQLite schema and compatibility migration
    # ------------------------------------------------------------------
    def _table_exists(self, conn: sqlite3.Connection, table_name: str) -> bool:
        row = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table_name,)
        ).fetchone()
        return row is not None

    def _table_columns(self, conn: sqlite3.Connection, table_name: str) -> Set[str]:
        return {str(row[1]) for row in conn.execute(f"PRAGMA table_info({table_name})").fetchall()}

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path, timeout=10.0) as conn:
            conn.execute("PRAGMA busy_timeout=10000")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS mutex_capture_links (
                    capture_id TEXT PRIMARY KEY,
                    order_id TEXT NOT NULL,
                    linked_at REAL NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS mutex_outbound_ops (
                    operation_id TEXT PRIMARY KEY,
                    op_json TEXT NOT NULL,
                    updated_at REAL NOT NULL,
                    capture_id TEXT
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS mutex_webhook_locks (
                    capture_id TEXT PRIMARY KEY,
                    lock_json TEXT NOT NULL,
                    expires_at REAL NOT NULL
                )
                """
            )

            # The original table predates the capture_id column. Add it without discarding
            # existing operation records, then backfill it from their JSON documents.
            if "capture_id" not in self._table_columns(conn, "mutex_outbound_ops"):
                conn.execute("ALTER TABLE mutex_outbound_ops ADD COLUMN capture_id TEXT")

            rows = conn.execute(
                "SELECT operation_id, op_json FROM mutex_outbound_ops"
            ).fetchall()
            for operation_id, op_json in rows:
                try:
                    payload = json.loads(op_json)
                except (TypeError, json.JSONDecodeError) as exc:
                    raise RuntimeError(
                        f"Cannot migrate malformed persisted refund operation '{operation_id}'."
                    ) from exc
                capture_id = payload.get("capture_id")
                if capture_id:
                    conn.execute(
                        "UPDATE mutex_outbound_ops SET capture_id=? WHERE operation_id=?",
                        (str(capture_id), operation_id),
                    )

            # Migrate the immediately preceding renamed tables, if they exist.
            if self._table_exists(conn, "webhook_capture_links"):
                alternate_links = conn.execute(
                    "SELECT capture_id, order_id, linked_at FROM webhook_capture_links"
                ).fetchall()
                for capture_id, order_id, linked_at in alternate_links:
                    canonical = conn.execute(
                        "SELECT order_id FROM mutex_capture_links WHERE capture_id=?", (capture_id,)
                    ).fetchone()
                    if canonical is not None and canonical[0] != order_id:
                        raise RuntimeError(
                            f"Conflicting legacy capture mapping for '{capture_id}': "
                            f"'{canonical[0]}' vs '{order_id}'. Resolve before migration."
                        )
                    conn.execute(
                        "INSERT OR IGNORE INTO mutex_capture_links (capture_id, order_id, linked_at) VALUES (?,?,?)",
                        (capture_id, order_id, linked_at),
                    )

            if self._table_exists(conn, "outbound_refund_ops"):
                columns = self._table_columns(conn, "outbound_refund_ops")
                json_column = "record_json" if "record_json" in columns else ("op_json" if "op_json" in columns else None)
                if json_column is None:
                    raise RuntimeError("Cannot migrate outbound_refund_ops: no recognized JSON column.")
                rows = conn.execute(
                    f"SELECT operation_id, {json_column}, updated_at FROM outbound_refund_ops"
                ).fetchall()
                for operation_id, record_json, updated_at in rows:
                    payload = json.loads(record_json)
                    capture_id = payload.get("capture_id")
                    canonical = conn.execute(
                        "SELECT op_json, capture_id FROM mutex_outbound_ops WHERE operation_id=?",
                        (operation_id,),
                    ).fetchone()
                    if canonical is not None:
                        canonical_payload = json.loads(canonical[0])
                        incoming_payload = json.loads(record_json)
                        if (
                            canonical[1] != capture_id
                            or canonical_payload.get("request_fingerprint") != incoming_payload.get("request_fingerprint")
                            or canonical_payload != incoming_payload
                        ):
                            raise RuntimeError(
                                f"Divergent copies of legacy refund operation_id '{operation_id}' exist. "
                                "Resolve the operation records before migration; migration will not choose one silently."
                            )
                    else:
                        conn.execute(
                            """
                            INSERT INTO mutex_outbound_ops
                                (operation_id, op_json, updated_at, capture_id)
                            VALUES (?, ?, ?, ?)
                            """,
                            (operation_id, record_json, updated_at, capture_id),
                        )

            # Enforce the one-logical-refund-per-capture MVP rule across restarts. If legacy
            # data violates it, fail startup rather than silently selecting one operation.
            try:
                conn.execute(
                    """
                    CREATE UNIQUE INDEX IF NOT EXISTS uq_mutex_outbound_capture
                    ON mutex_outbound_ops(capture_id)
                    WHERE capture_id IS NOT NULL
                    """
                )
            except sqlite3.IntegrityError as exc:
                raise RuntimeError(
                    "Persisted refund history contains multiple logical operations for one capture; "
                    "reconcile the database before starting this one-refund-per-capture MVP."
                ) from exc
            conn.commit()

    def _persist_link_locked(self, capture_id: str, order_id: str, linked_at: float) -> None:
        if not self.db_path:
            return
        with sqlite3.connect(self.db_path, timeout=10.0) as conn:
            conn.execute(
                """
                INSERT INTO mutex_capture_links (capture_id, order_id, linked_at)
                VALUES (?, ?, ?)
                ON CONFLICT(capture_id) DO UPDATE SET
                    order_id=excluded.order_id,
                    linked_at=excluded.linked_at
                """,
                (capture_id, order_id, linked_at),
            )
            conn.commit()

    def _persist_lock_locked(self, lock: WebhookRefundLock) -> None:
        if not self.db_path:
            return
        with sqlite3.connect(self.db_path, timeout=10.0) as conn:
            conn.execute(
                """
                INSERT INTO mutex_webhook_locks (capture_id, lock_json, expires_at)
                VALUES (?, ?, ?)
                ON CONFLICT(capture_id) DO UPDATE SET
                    lock_json=excluded.lock_json,
                    expires_at=excluded.expires_at
                """,
                (lock.capture_id, json.dumps(asdict(lock)), lock.expires_at),
            )
            conn.commit()

    def _delete_lock_persisted_locked(self, capture_id: str) -> None:
        if not self.db_path:
            return
        with sqlite3.connect(self.db_path, timeout=10.0) as conn:
            conn.execute("DELETE FROM mutex_webhook_locks WHERE capture_id=?", (capture_id,))
            conn.commit()

    def _persist_op_locked(self, op: OutboundRefundOperation) -> None:
        if not self.db_path:
            return
        try:
            with sqlite3.connect(self.db_path, timeout=10.0) as conn:
                conn.execute(
                    """
                    INSERT INTO mutex_outbound_ops
                        (operation_id, op_json, updated_at, capture_id)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(operation_id) DO UPDATE SET
                        op_json=excluded.op_json,
                        updated_at=excluded.updated_at,
                        capture_id=excluded.capture_id
                    """,
                    (op.operation_id, json.dumps(asdict(op)), op.updated_at, op.capture_id),
                )
                conn.commit()
        except sqlite3.IntegrityError as exc:
            raise ValueError(
                f"Capture '{op.capture_id}' already has a different persisted refund operation."
            ) from exc

    def _load_persisted_state(self) -> None:
        if not self.db_path:
            return
        with self._lock:
            current_time = time.time()
            with sqlite3.connect(self.db_path, timeout=10.0) as conn:
                link_rows = conn.execute(
                    "SELECT capture_id, order_id, linked_at FROM mutex_capture_links"
                ).fetchall()
                op_rows = conn.execute(
                    "SELECT op_json FROM mutex_outbound_ops ORDER BY updated_at ASC"
                ).fetchall()
                lock_rows = conn.execute(
                    "SELECT lock_json, expires_at FROM mutex_webhook_locks"
                ).fetchall()

            for capture_id, order_id, linked_at in link_rows:
                self._capture_to_order[capture_id] = order_id
                self._order_to_captures.setdefault(order_id, set()).add(capture_id)
                self._capture_link_timestamps[capture_id] = float(linked_at)

            for (op_json,) in op_rows:
                payload = json.loads(op_json)
                payload.setdefault("generation", 1)
                payload.setdefault("reclaimed_count", 0)
                payload.setdefault("claim_token", f"legacy-invalid-{secrets.token_urlsafe(12)}")
                payload.setdefault("updated_at", current_time)
                payload.setdefault("reason", None)
                op = OutboundRefundOperation(**payload)
                if not op.capture_id:
                    raise RuntimeError(
                        f"Persisted refund operation '{op.operation_id}' has no capture_id; reconcile it manually."
                    )
                existing_op_id = self._active_capture_op.get(op.capture_id)
                if existing_op_id and existing_op_id != op.operation_id:
                    raise RuntimeError(
                        f"Multiple persisted refund operations reference capture '{op.capture_id}'."
                    )
                mapped_order = self._capture_to_order.get(op.capture_id)
                if mapped_order and op.order_id and mapped_order != op.order_id:
                    raise RuntimeError(
                        f"Persisted refund operation '{op.operation_id}' conflicts with capture/order link "
                        f"('{op.capture_id}' -> '{mapped_order}', operation order '{op.order_id}')."
                    )
                if op.order_id and not mapped_order:
                    self._capture_to_order[op.capture_id] = op.order_id
                    self._order_to_captures.setdefault(op.order_id, set()).add(op.capture_id)
                self._outbound_ops[op.operation_id] = op
                self._active_capture_op[op.capture_id] = op.operation_id
                self._generation_counter = max(self._generation_counter, op.generation)

            for lock_json, expires_at in lock_rows:
                if float(expires_at) > current_time:
                    lock = WebhookRefundLock(**json.loads(lock_json))
                    self._locks_by_capture_id[lock.capture_id] = lock
                else:
                    self._delete_lock_persisted_locked(
                        str(json.loads(lock_json).get("capture_id") or "")
                    )

    # ------------------------------------------------------------------
    # Link ownership and inbound webhook echo locks
    # ------------------------------------------------------------------
    def register_order_capture_link(
        self,
        order_id: str,
        capture_id: str,
        state_engine: Optional[object] = None,
        now: Optional[float] = None,
    ) -> None:
        oid = (order_id or "").strip()
        cid = (capture_id or "").strip()
        if not oid or not cid:
            raise ValueError("Both order_id and capture_id are required.")
        current_time = now if now is not None else time.time()
        if isinstance(current_time, bool) or not isinstance(current_time, (int, float)) or not math.isfinite(float(current_time)):
            raise ValueError("now must be a finite timestamp.")

        with self._lock:
            order_record = None
            if state_engine is not None:
                if not hasattr(state_engine, "get_order") or not hasattr(state_engine, "get_order_by_capture_id"):
                    raise TypeError("state_engine must expose get_order() and get_order_by_capture_id().")
                order_record = state_engine.get_order(oid)
                if order_record is None:
                    raise ValueError(f"Cannot register capture link for unknown order_id '{oid}'.")
                by_capture = state_engine.get_order_by_capture_id(cid)
                if by_capture is None:
                    raise ValueError(
                        f"Capture '{cid}' is not registered in StateEngine; register the verified capture "
                        "there before mirroring its link into the webhook mutex."
                    )
                if by_capture.order_id != oid:
                    raise ValueError(
                        f"Capture '{cid}' is owned by StateEngine order '{by_capture.order_id}', not '{oid}'."
                    )
                known_caps = set(getattr(order_record, "capture_ids", []) or [])
                if getattr(order_record, "capture_id", None):
                    known_caps.add(order_record.capture_id)
                if len(known_caps) != 1 or cid not in known_caps:
                    raise ValueError(
                        f"StateEngine must show exactly the requested single capture for order '{oid}'; "
                        f"known captures: {sorted(known_caps)}."
                    )

            existing_order = self._capture_to_order.get(cid)
            if existing_order is not None and existing_order != oid:
                raise ValueError(
                    f"Conflicting capture-to-order link: capture '{cid}' already belongs to '{existing_order}'."
                )
            existing_caps = self._order_to_captures.get(oid, set())
            if existing_caps and cid not in existing_caps:
                raise ValueError(
                    f"MVP supports one capture per order; order '{oid}' already has captures {sorted(existing_caps)}."
                )
            # Commit the durable mapping first; an SQLite failure must not leave a
            # process-local link that disappears after restart.
            self._persist_link_locked(cid, oid, float(current_time))
            self._capture_to_order[cid] = oid
            self._order_to_captures.setdefault(oid, set()).add(cid)
            self._capture_link_timestamps[cid] = float(current_time)

    def _sync_and_validate_links_locked(
        self,
        clean_order_id: Optional[str],
        clean_capture_id: Optional[str],
        state_engine: Optional[object],
        current_time: float,
    ) -> Tuple[Optional[str], Set[str]]:
        mapped_order_for_capture: Optional[str] = None
        if clean_capture_id:
            mapped_order_for_capture = self._capture_to_order.get(clean_capture_id)
            state_record = None
            if state_engine is not None:
                if not hasattr(state_engine, "get_order_by_capture_id"):
                    raise TypeError("state_engine must expose get_order_by_capture_id().")
                state_record = state_engine.get_order_by_capture_id(clean_capture_id)
                if state_record is None:
                    raise ValueError(
                        f"Unknown or unverified capture_id '{clean_capture_id}' in StateEngine; "
                        "a mutex-only mapping is insufficient when an authoritative StateEngine is supplied."
                    )
                if mapped_order_for_capture and mapped_order_for_capture != state_record.order_id:
                    raise ValueError(
                        f"Capture '{clean_capture_id}' mapping mismatch between mutex "
                        f"('{mapped_order_for_capture}') and StateEngine ('{state_record.order_id}')."
                    )
                mapped_order_for_capture = state_record.order_id

        if clean_order_id and state_engine is not None and hasattr(state_engine, "get_order"):
            order_record = state_engine.get_order(clean_order_id)
            if order_record is None:
                raise ValueError(f"Unknown order_id '{clean_order_id}' in StateEngine.")
            if clean_capture_id:
                known_caps = set(getattr(order_record, "capture_ids", []) or [])
                if getattr(order_record, "capture_id", None):
                    known_caps.add(order_record.capture_id)
                registered_mutex_owner = self._capture_to_order.get(clean_capture_id)
                if clean_capture_id not in known_caps and registered_mutex_owner != clean_order_id:
                    raise ValueError(
                        f"Capture '{clean_capture_id}' has no verified link to order '{clean_order_id}'."
                    )

        if clean_order_id and clean_capture_id and mapped_order_for_capture and mapped_order_for_capture != clean_order_id:
            raise ValueError(
                f"Conflicting order/capture pair: capture '{clean_capture_id}' belongs to '{mapped_order_for_capture}', "
                f"not '{clean_order_id}'."
            )
        if clean_order_id and clean_capture_id and state_engine is None and mapped_order_for_capture is None:
            raise ValueError(
                f"Capture '{clean_capture_id}' must be registered to order '{clean_order_id}' before use."
            )

        resolved_order_id = clean_order_id or mapped_order_for_capture
        order_captures: Set[str] = set()
        if resolved_order_id:
            order_captures.update(self._order_to_captures.get(resolved_order_id, set()))
            if state_engine is not None and hasattr(state_engine, "get_order"):
                order_record = state_engine.get_order(resolved_order_id)
                if order_record is not None:
                    if getattr(order_record, "capture_id", None):
                        order_captures.add(order_record.capture_id)
                    order_captures.update(getattr(order_record, "capture_ids", []) or [])
        if clean_capture_id:
            order_captures.add(clean_capture_id)

        if resolved_order_id and len(order_captures) > 1:
            raise ValueError(
                f"MVP does not support multiple captures for order '{resolved_order_id}': {sorted(order_captures)}."
            )

        if resolved_order_id:
            for capture in order_captures:
                owner = self._capture_to_order.get(capture)
                if owner and owner != resolved_order_id:
                    raise ValueError(
                        f"Capture '{capture}' is already mapped to order '{owner}', "
                        f"cannot associate it with '{resolved_order_id}'."
                    )
                if capture not in self._capture_link_timestamps:
                    self._persist_link_locked(capture, resolved_order_id, current_time)
                    self._capture_link_timestamps[capture] = current_time
                self._capture_to_order[capture] = resolved_order_id
                self._order_to_captures.setdefault(resolved_order_id, set()).add(capture)

        return resolved_order_id, order_captures

    def _prune_expired(self, current_time: float) -> None:
        # Do not prune capture mappings or outbound refund history in the MVP. Removing a
        # FAILED operation after an arbitrary TTL would permit a second logical refund later.
        expired = [
            capture_id for capture_id, lock in self._locks_by_capture_id.items()
            if lock.expires_at <= current_time
        ]
        for capture_id in expired:
            self._locks_by_capture_id.pop(capture_id, None)
            self._delete_lock_persisted_locked(capture_id)

    def set_webhook_refund_lock(
        self,
        webhook_event_id: str,
        order_id: Optional[str] = None,
        capture_id: Optional[str] = None,
        state_engine: Optional[object] = None,
        ttl_seconds: Optional[int] = None,
        now: Optional[float] = None,
    ) -> WebhookRefundLock:
        event_id = (webhook_event_id or "").strip()
        if not event_id:
            raise ValueError("webhook_event_id is required.")
        current_time = _require_finite_time(now)
        ttl = self.ttl_seconds if ttl_seconds is None else int(ttl_seconds)
        if ttl <= 0:
            raise ValueError("Webhook lock TTL must be positive.")
        clean_order = order_id.strip() if order_id and order_id.strip() else None
        clean_capture = capture_id.strip() if capture_id and capture_id.strip() else None
        if not clean_order and not clean_capture:
            raise ValueError("At least one of order_id or capture_id is required.")

        with self._lock:
            self._prune_expired(float(current_time))
            resolved_order, captures = self._sync_and_validate_links_locked(
                clean_order, clean_capture, state_engine, float(current_time)
            )
            target_capture = clean_capture or (next(iter(captures)) if len(captures) == 1 else None)
            if not target_capture:
                raise ValueError(
                    "MISSING_KNOWN_CAPTURE_FOR_WEBHOOK_LOCK: webhook refund lock requires exactly one known capture."
                )
            lock = WebhookRefundLock(
                order_id=resolved_order,
                capture_id=target_capture,
                webhook_event_id=event_id,
                acquired_at=float(current_time),
                expires_at=float(current_time) + ttl,
            )
            self._persist_lock_locked(lock)
            self._locks_by_capture_id[target_capture] = lock
            return copy.deepcopy(lock)

    def can_call_outbound_refund(
        self,
        order_id: Optional[str] = None,
        capture_id: Optional[str] = None,
        state_engine: Optional[object] = None,
        caller_source: str = "MCP_OR_STORE_CALLBACK",
        now: Optional[float] = None,
    ) -> Tuple[bool, str, Optional[WebhookRefundLock]]:
        current_time = _require_finite_time(now)
        clean_order = order_id.strip() if order_id and order_id.strip() else None
        clean_capture = capture_id.strip() if capture_id and capture_id.strip() else None
        if not clean_order and not clean_capture:
            return False, "MISSING_REFUND_TARGET", None

        with self._lock:
            self._prune_expired(float(current_time))
            resolved_order, captures = self._sync_and_validate_links_locked(
                clean_order, clean_capture, state_engine, float(current_time)
            )
            if len(captures) > 1:
                return False, "MVP_MULTIPLE_CAPTURES_NOT_SUPPORTED", None
            target_capture = clean_capture or (next(iter(captures)) if len(captures) == 1 else None)
            if not target_capture:
                return False, "MISSING_KNOWN_CAPTURE_FOR_ORDER_REFUND", None
            active_lock = self._locks_by_capture_id.get(target_capture)
            if active_lock is None:
                return True, "ALLOWED_OUTBOUND_REFUND", None

            remaining = round(max(0.0, active_lock.expires_at - float(current_time)), 1)
            message = (
                f"BLOCKED_WEBHOOK_ECHO: Outbound refund on order={resolved_order or active_lock.order_id} "
                f"capture={target_capture} blocked because refund originated from PayPal webhook "
                f"{active_lock.webhook_event_id} ({remaining}s lock remaining)."
            )
            self._blocked_echo_log.append(
                BlockedRefundEchoEvent(
                    order_id=resolved_order or active_lock.order_id,
                    capture_id=target_capture,
                    webhook_event_id=active_lock.webhook_event_id,
                    blocked_at=float(current_time),
                    caller_source=caller_source,
                    message=message,
                )
            )
            if self.max_blocked_log_size == 0:
                self._blocked_echo_log.clear()
            elif len(self._blocked_echo_log) > self.max_blocked_log_size:
                self._blocked_echo_log = self._blocked_echo_log[-self.max_blocked_log_size:]
            return False, message, copy.deepcopy(active_lock)

    # ------------------------------------------------------------------
    # Outbound refund reservation and one-time fencing tokens
    # ------------------------------------------------------------------
    @staticmethod
    def _compute_request_fingerprint(
        capture_id: str,
        order_id: Optional[str],
        norm_amount: str,
        norm_currency: str,
        reason: Optional[str] = None,
    ) -> str:
        # Preserve the pre-existing fingerprint format for retry compatibility. Reason is
        # descriptive metadata, not part of the financial operation identity.
        raw = f"{capture_id}|{order_id or ''}|{norm_amount}|{norm_currency}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:20]

    def _new_claim_token(self, operation_id: str, generation: int) -> str:
        nonce = secrets.token_urlsafe(24)
        return f"claim_{generation}_{hashlib.sha256((operation_id + '|' + nonce).encode()).hexdigest()[:24]}"

    def _invalidate_claim_locked(self, op: OutboundRefundOperation) -> int:
        new_generation = max(self._generation_counter, op.generation) + 1
        op.generation = new_generation
        op.claim_token = f"closed_{op.generation}_{secrets.token_urlsafe(18)}"
        return new_generation

    def _linked_order_for_capture(
        self,
        capture_id: str,
        order_id: Optional[str],
        state_engine: Optional[object],
    ) -> Optional[object]:
        linked_order = None
        mapped_order = self._capture_to_order.get(capture_id)
        if state_engine is not None:
            if hasattr(state_engine, "get_order_by_capture_id"):
                linked_order = state_engine.get_order_by_capture_id(capture_id)
            if linked_order is None and order_id and hasattr(state_engine, "get_order"):
                linked_order = state_engine.get_order(order_id)
        if linked_order is not None and order_id and linked_order.order_id != order_id:
            raise ValueError(
                f"Capture '{capture_id}' belongs to order '{linked_order.order_id}', not '{order_id}'."
            )
        if mapped_order and linked_order is not None and mapped_order != linked_order.order_id:
            raise ValueError(
                f"Mutex capture mapping '{mapped_order}' conflicts with StateEngine order '{linked_order.order_id}'."
            )
        return linked_order

    def reserve_outbound_refund(
        self,
        capture_id: Optional[str] = None,
        order_id: Optional[str] = None,
        operation_id: Optional[str] = None,
        amount: Optional[str | float | int | Decimal] = None,
        currency: Optional[str] = None,
        reason: Optional[str] = None,
        state_engine: Optional[object] = None,
        caller_source: str = "MCP_OR_STORE_CALLBACK",
        now: Optional[float] = None,
    ) -> Tuple[bool, str, Optional[OutboundRefundOperation]]:
        current_time = now if now is not None else time.time()
        clean_capture = capture_id.strip() if capture_id and capture_id.strip() else None
        clean_order = order_id.strip() if order_id and order_id.strip() else None
        supplied_operation_id = operation_id.strip() if operation_id and operation_id.strip() else None
        if reason is not None and not isinstance(reason, str):
            raise ValueError("reason must be a string or None.")
        clean_reason = reason.strip() if reason and reason.strip() else None
        if not clean_capture and not clean_order:
            raise ValueError("A capture_id or order_id is required to reserve a refund.")
        if isinstance(current_time, bool) or not isinstance(current_time, (int, float)) or not math.isfinite(float(current_time)):
            raise ValueError("now must be a finite timestamp.")
        current_time = float(current_time)

        with self._lock:
            allowed, message, _ = self.can_call_outbound_refund(
                order_id=clean_order,
                capture_id=clean_capture,
                state_engine=state_engine,
                caller_source=caller_source,
                now=current_time,
            )
            if not allowed:
                return False, message, None

            resolved_order, captures = self._sync_and_validate_links_locked(
                clean_order, clean_capture, state_engine, current_time
            )
            target_capture = clean_capture or (next(iter(captures)) if len(captures) == 1 else None)
            if not target_capture:
                if len(captures) > 1:
                    return False, "AMBIGUOUS_MULTI_CAPTURE_ORDER_REFUND", None
                return False, "MISSING_KNOWN_CAPTURE_FOR_ORDER_REFUND", None

            linked_order = self._linked_order_for_capture(target_capture, resolved_order, state_engine)
            raw_currency = (
                currency.strip().upper() if currency and currency.strip()
                else (linked_order.currency if linked_order is not None else None)
            )
            if not raw_currency:
                raise ValueError("A supported currency is required when the capture's order is not locally resolvable.")
            if linked_order is not None and raw_currency != linked_order.currency.upper():
                raise ValueError(
                    f"Refund currency '{raw_currency}' does not match order currency '{linked_order.currency}'."
                )

            # amount=None means a full refund and is valid only when the linked order supplies
            # the authoritative original amount. Otherwise callers must supply amount+currency.
            raw_amount = amount if amount is not None else (linked_order.amount if linked_order is not None else None)
            if raw_amount is None:
                raise ValueError("Refund amount is required when the original order amount is unavailable.")
            decimal_amount = validate_financial_amount(
                raw_amount, raw_currency, allow_zero=False,
                allowed_currencies=(
                    state_engine.supported_currencies
                    if state_engine is not None and hasattr(state_engine, "supported_currencies")
                    else PAYPAL_SUPPORTED_CURRENCIES
                ),
            )
            if linked_order is not None:
                order_amount = validate_financial_amount(
                    linked_order.amount, raw_currency, allow_zero=False,
                    allowed_currencies=(
                        state_engine.supported_currencies
                        if state_engine is not None and hasattr(state_engine, "supported_currencies")
                        else PAYPAL_SUPPORTED_CURRENCIES
                    ),
                )
                if decimal_amount > order_amount:
                    raise ValueError(
                        f"Refund amount '{decimal_amount}' exceeds original order amount '{order_amount}'."
                    )
            normalized_amount = _normalize_amount(decimal_amount, raw_currency)
            normalized_currency = raw_currency
            request_fingerprint = self._compute_request_fingerprint(
                target_capture, resolved_order, normalized_amount, normalized_currency, reason
            )

            # Exactly one operation row per capture. A retry must retain its original operation ID.
            existing_operation_id = self._active_capture_op.get(target_capture)
            existing_by_id = self._outbound_ops.get(supplied_operation_id) if supplied_operation_id else None
            existing = self._outbound_ops.get(existing_operation_id) if existing_operation_id else existing_by_id
            if existing_by_id is not None and existing is not None and existing_by_id.operation_id != existing.operation_id:
                raise ValueError("operation_id is already bound to another capture refund operation.")
            if existing is not None:
                if supplied_operation_id and supplied_operation_id != existing.operation_id:
                    raise ValueError(
                        f"CONFLICTING_REFUND_ON_SAME_CAPTURE: capture '{target_capture}' already belongs "
                        f"to logical operation '{existing.operation_id}'; retry with that same operation_id."
                    )
                if (
                    existing.capture_id != target_capture
                    or existing.request_fingerprint != request_fingerprint
                    or existing.reason != clean_reason
                ):
                    raise ValueError(
                        f"CONFLICTING_REFUND_ON_SAME_CAPTURE: existing refund payload or reason does not match "
                        f"the requested operation for capture '{target_capture}'."
                    )
                if existing.status == "SUCCEEDED":
                    return False, f"DUPLICATE_OUTBOUND_REFUND_ALREADY_SUCCEEDED:{existing.operation_id}", copy.deepcopy(existing)
                if existing.status in ("PENDING", "RECONCILIATION_REQUIRED"):
                    return False, f"OUTBOUND_REFUND_{existing.status}_RECONCILE_FIRST:{existing.operation_id}", copy.deepcopy(existing)
                if existing.status == "PROCESSING":
                    if current_time - existing.updated_at < self.outbound_op_lease_seconds:
                        return False, f"CONCURRENT_OUTBOUND_REFUND_IN_PROGRESS:{existing.operation_id}", copy.deepcopy(existing)
                    expired_operation = copy.deepcopy(existing)
                    expired_operation.status = "RECONCILIATION_REQUIRED"
                    expired_operation.reclaimed_count += 1
                    expired_operation.updated_at = current_time
                    new_generation = self._invalidate_claim_locked(expired_operation)
                    self._persist_op_locked(expired_operation)
                    self._outbound_ops[expired_operation.operation_id] = expired_operation
                    self._generation_counter = max(self._generation_counter, new_generation)
                    return False, f"OUTBOUND_REFUND_RECONCILIATION_REQUIRED_RECONCILE_FIRST:{expired_operation.operation_id}", copy.deepcopy(expired_operation)
                if existing.status in ("FAILED", "REJECTED"):
                    # Provider-confirmed FAILED and deterministic API REJECTED are terminal
                    # for this one-logical-refund-per-capture MVP operation.
                    label = "PROVIDER_REJECTED" if existing.status == "REJECTED" else "DEFINITIVELY_FAILED"
                    return (
                        False,
                        f"OUTBOUND_REFUND_{label}_ESCALATE_MANUALLY:{existing.operation_id}",
                        copy.deepcopy(existing),
                    )
                if existing.status == "NOT_SUBMITTED":
                    # OAuth failed before the refund POST was transmitted. Retrying this same
                    # logical operation and PayPal-Request-Id is safe; the previous attempt
                    # provably did not reach PayPal. Rotate only the local claim/fencing token.
                    operation_key = existing.operation_id
                    request_id = existing.paypal_request_id
                    reclaimed_count = existing.reclaimed_count
                    generation = max(self._generation_counter, existing.generation) + 1
                else:
                    return False, f"OUTBOUND_REFUND_STATE_NOT_RETRYABLE:{existing.status}", copy.deepcopy(existing)
            else:
                operation_key = supplied_operation_id or f"op:cap:{target_capture}"
                if operation_key in self._outbound_ops:
                    raise ValueError(f"operation_id '{operation_key}' is already used by another refund.")
                request_id = f"refund-{hashlib.sha256((operation_key + '|' + request_fingerprint).encode()).hexdigest()[:24]}"
                reclaimed_count = 0
                generation = max(self._generation_counter, 0) + 1

            self._generation_counter = generation
            claim_token = self._new_claim_token(operation_key, generation)
            operation = OutboundRefundOperation(
                operation_id=operation_key,
                capture_id=target_capture,
                order_id=resolved_order,
                amount=normalized_amount,
                currency=normalized_currency,
                request_fingerprint=request_fingerprint,
                status="PROCESSING",
                paypal_request_id=request_id,
                claim_token=claim_token,
                generation=generation,
                updated_at=current_time,
                reclaimed_count=reclaimed_count,
                paypal_refund_id=existing.paypal_refund_id if existing else None,
                provider_status=None,
                reason=clean_reason,
            )

            # SQLite's unique capture index is a second line of defence against accidental
            # duplicate reservations. The app is still explicitly single-instance/single-worker.
            self._persist_op_locked(operation)
            self._outbound_ops[operation_key] = operation
            self._active_capture_op[target_capture] = operation_key
            return True, "RESERVED_OUTBOUND_REFUND", copy.deepcopy(operation)

    def complete_outbound_refund(
        self,
        operation_id: str,
        succeeded: Optional[bool] = None,
        outcome: Optional[str] = None,
        claim_token: Optional[str] = None,
        paypal_refund_id: Optional[str] = None,
        provider_status: Optional[str] = None,
        now: Optional[float] = None,
        provider_submission_confirmed_absent: bool = False,
        provider_error_code: Optional[str] = None,
        provider_http_status: Optional[int] = None,
        provider_debug_id: Optional[str] = None,
    ) -> OutboundRefundOperation:
        current_time = _require_finite_time(now)
        clean_key = (operation_id or "").strip()
        if not clean_key:
            raise ValueError("operation_id is required.")
        with self._lock:
            operation = self._outbound_ops.get(clean_key)
            if operation is None:
                raise ValueError(f"Unknown outbound refund operation_id '{clean_key}'.")
            if not claim_token or not claim_token.strip() or claim_token.strip() != operation.claim_token:
                raise ValueError("A valid current claim_token is required to complete the refund operation.")
            if operation.status != "PROCESSING":
                raise ValueError(
                    f"Refund operation '{clean_key}' is not PROCESSING; current state is '{operation.status}'."
                )
            if current_time - operation.updated_at >= self.outbound_op_lease_seconds:
                expired_operation = copy.deepcopy(operation)
                expired_operation.status = "RECONCILIATION_REQUIRED"
                expired_operation.reclaimed_count += 1
                expired_operation.updated_at = current_time
                new_generation = self._invalidate_claim_locked(expired_operation)
                self._persist_op_locked(expired_operation)
                self._outbound_ops[clean_key] = expired_operation
                self._generation_counter = max(self._generation_counter, new_generation)
                raise ValueError(
                    f"Refund operation '{clean_key}' lease expired; reconcile with PayPal before any retry."
                )

            provider_to_internal = {
                "COMPLETED": "SUCCEEDED",
                "SUCCEEDED": "SUCCEEDED",
                "FAILED": "FAILED",
                "CANCELLED": "FAILED",
                "PENDING": "PENDING",
            }
            provider_outcome = None
            if provider_status and provider_status.strip():
                provider_key = provider_status.strip().upper()
                if provider_key not in provider_to_internal:
                    raise ValueError(f"Unrecognized PayPal refund status '{provider_status}'.")
                provider_outcome = provider_to_internal[provider_key]

            if outcome and outcome.strip():
                resolved_status = outcome.strip().upper()
            elif provider_outcome is not None:
                resolved_status = provider_outcome
            elif succeeded is True:
                resolved_status = "SUCCEEDED"
            elif succeeded is False:
                # Caller must use False only for a provider-confirmed definite failure,
                # never for a timeout or an ambiguous transport error.
                resolved_status = "FAILED"
            else:
                resolved_status = "RECONCILIATION_REQUIRED"
            if resolved_status not in VALID_OUTBOUND_OUTCOMES:
                raise ValueError(f"Invalid outbound refund outcome '{resolved_status}'.")
            if resolved_status == "NOT_SUBMITTED":
                if provider_submission_confirmed_absent is not True:
                    raise ValueError("NOT_SUBMITTED requires explicit provider_submission_confirmed_absent=True.")
                if provider_status or paypal_refund_id:
                    raise ValueError("NOT_SUBMITTED cannot carry a provider status or PayPal refund ID.")
            elif provider_submission_confirmed_absent:
                raise ValueError("provider_submission_confirmed_absent is only valid with NOT_SUBMITTED.")
            if resolved_status == "REJECTED":
                if provider_status or paypal_refund_id:
                    raise ValueError("REJECTED cannot carry a provider refund status or refund ID.")
                if not provider_error_code or provider_http_status is None:
                    raise ValueError("REJECTED requires a provider error code and HTTP status.")
                if isinstance(provider_http_status, bool) or not isinstance(provider_http_status, int):
                    raise ValueError("provider_http_status must be an integer.")
                if not 400 <= provider_http_status <= 499:
                    raise ValueError("REJECTED requires a deterministic HTTP 4xx status.")
            elif provider_error_code is not None or provider_http_status is not None or provider_debug_id is not None:
                raise ValueError("Provider error metadata is only valid for REJECTED outcomes.")
            if provider_outcome is not None and provider_outcome != resolved_status:
                raise ValueError(
                    f"PayPal provider status '{provider_status}' conflicts with requested internal outcome '{resolved_status}'."
                )
            if resolved_status in ("SUCCEEDED", "FAILED", "PENDING"):
                if provider_outcome != resolved_status:
                    raise ValueError(
                        f"A provider-confirmed PayPal refund status is required for '{resolved_status}'."
                    )
                if not paypal_refund_id or not paypal_refund_id.strip():
                    raise ValueError(
                        f"paypal_refund_id is required for provider-confirmed '{resolved_status}' outcomes."
                    )

            updated_operation = copy.deepcopy(operation)
            updated_operation.status = resolved_status
            updated_operation.updated_at = current_time
            if paypal_refund_id and paypal_refund_id.strip():
                updated_operation.paypal_refund_id = paypal_refund_id.strip()
            if provider_status and provider_status.strip():
                updated_operation.provider_status = provider_status.strip().upper()
            if provider_error_code is not None:
                clean_error_code = str(provider_error_code).strip().upper()[:128]
                updated_operation.provider_error_code = clean_error_code or None
            if provider_http_status is not None:
                updated_operation.provider_http_status = int(provider_http_status)
            if provider_debug_id is not None:
                clean_debug_id = str(provider_debug_id).strip()[:128]
                updated_operation.provider_debug_id = clean_debug_id or None
            # Completion tokens are one-time. Any later correction must use reconciliation.
            new_generation = self._invalidate_claim_locked(updated_operation)
            self._persist_op_locked(updated_operation)
            self._outbound_ops[clean_key] = updated_operation
            self._generation_counter = max(self._generation_counter, new_generation)
            return copy.deepcopy(updated_operation)

    def resolve_reconciliation_required_refund(
        self,
        operation_id: str,
        *,
        resolved_outcome: str,
        provider_status: str,
        paypal_refund_id: Optional[str] = None,
        now: Optional[float] = None,
    ) -> OutboundRefundOperation:
        """Resolve PENDING/RECONCILIATION_REQUIRED only after a fresh authoritative PayPal lookup.

        The caller must perform that lookup before invoking this method. Internal outcome is
        cross-checked against the provider's refund status string supplied by the caller.
        """
        current_time = _require_finite_time(now)
        clean_key = (operation_id or "").strip()
        target_status = (resolved_outcome or "").strip().upper()
        raw_provider_status = (provider_status or "").strip().upper()
        provider_to_internal = {
            "COMPLETED": "SUCCEEDED",
            "SUCCEEDED": "SUCCEEDED",
            "FAILED": "FAILED",
            "CANCELLED": "FAILED",
            "PENDING": "PENDING",
        }
        if target_status not in ("SUCCEEDED", "FAILED", "PENDING"):
            raise ValueError(f"Invalid resolved_outcome '{resolved_outcome}'.")
        if provider_to_internal.get(raw_provider_status) != target_status:
            raise ValueError(
                f"Provider status '{raw_provider_status}' does not support internal outcome '{target_status}'."
            )
        if not paypal_refund_id or not paypal_refund_id.strip():
            raise ValueError("paypal_refund_id is required to reconcile a concrete PayPal refund status.")
        with self._lock:
            operation = self._outbound_ops.get(clean_key)
            if operation is None:
                raise ValueError(f"Unknown outbound refund operation_id '{clean_key}'.")
            if operation.status not in ("PENDING", "RECONCILIATION_REQUIRED"):
                raise ValueError(
                    f"Only PENDING or RECONCILIATION_REQUIRED operations can be reconciled; "
                    f"current state is '{operation.status}'."
                )
            resolved_operation = copy.deepcopy(operation)
            resolved_operation.status = target_status
            resolved_operation.provider_status = raw_provider_status
            resolved_operation.updated_at = current_time
            resolved_operation.paypal_refund_id = paypal_refund_id.strip()
            new_generation = self._invalidate_claim_locked(resolved_operation)
            self._persist_op_locked(resolved_operation)
            self._outbound_ops[clean_key] = resolved_operation
            self._generation_counter = max(self._generation_counter, new_generation)
            return copy.deepcopy(resolved_operation)

    def get_outbound_operation(self, operation_id: str) -> Optional[OutboundRefundOperation]:
        with self._lock:
            operation = self._outbound_ops.get((operation_id or "").strip())
            return copy.deepcopy(operation) if operation is not None else None

    def get_blocked_echoes(self) -> List[BlockedRefundEchoEvent]:
        with self._lock:
            return [copy.deepcopy(event) for event in self._blocked_echo_log]
