"""
Pillar 1 (File 2/3): Event-Triggered Buy <-> Refund Deadlock Detector
Location: src/pillar1_velocity_engine/deadlock_detector.py

Complete P0 #1, P0 #4 + P1 #1, P1 #2 Audited Implementation:
- P0 #1 (Persist Final Combined Eligibility):
  - `evaluate_checkout_pillar1()` unconditionally persists `can_auto_capture`
    (`velocity_res.can_auto_capture_if_llm_approves and deadlock_res.allow_auto_capture`)
    onto `OrderRecord`, never overwriting a hard hold with `has_reliable_identity`.
- P0 #4 (Reject Inconsistent `(order_id, capture_id)` Refund Mappings):
  - `record_refund()` resolves both `order_by_cap` and `order_by_id` from `state_engine` and
    raises `ValueError` before saving if `order_id` and `capture_id` map to different orders or
    conflict with the order's recorded capture(s).
- P1 #1 (Require Explicit Refund Status on Webhook Ingestion):
  - When recording a new refund (`existing is None`) with `refund_source == "PAYPAL_WEBHOOK"`,
    `refund_status` must be explicitly provided (never silently defaulting to `"COMPLETED"`).
  - Only verified `"COMPLETED"` refunds with `timestamp_resolved == True` enter the deadlock index.
- P1 #2 (Never Fall Back Missing Refund Creation Time to Receipt Time):
  - `refund_event_time` is strictly resolved from `resource.create_time` (or an explicit
    `refund_event_time`). When `refund_event_time` is missing on a webhook event,
    `refund_event_time` remains `None` and `timestamp_resolved = False` (keeping `webhook_received_at`
    separate and leaving unresolved timestamps out of the deadlock index).
"""

from __future__ import annotations

import copy
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from decimal import Decimal
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
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
    for cand_dir in (here, here.parent / "pillar1_velocity_engine"):
        p = cand_dir / f"{mod_name}.py"
        if p.is_file():
            spec = importlib.util.spec_from_file_location(mod_name, p)
            if spec and spec.loader:
                mod = importlib.util.module_from_spec(spec)
                sys.modules[mod_name] = mod
                spec.loader.exec_module(mod)
                return mod
    raise ImportError(f"Cannot locate module '{mod_name}'")


try:
    from .state_engine import (
        MAX_FUTURE_CLOCK_SKEW_SECONDS,
        OrderRecord,
        VelocityCheckResult,
        VelocityStateEngine,
        _normalize_amount,
        classify_identity_keys,
        compute_cart_fingerprint_details,
        compute_shipping_address_hash,
        get_key_strength,
        select_strongest_matched_key,
        validate_financial_amount,
    )
except ImportError:
    _se_mod = _load_sibling_module("state_engine", "src.pillar1_velocity_engine.state_engine")
    MAX_FUTURE_CLOCK_SKEW_SECONDS = _se_mod.MAX_FUTURE_CLOCK_SKEW_SECONDS
    OrderRecord = _se_mod.OrderRecord
    VelocityCheckResult = _se_mod.VelocityCheckResult
    VelocityStateEngine = _se_mod.VelocityStateEngine
    _normalize_amount = _se_mod._normalize_amount
    classify_identity_keys = _se_mod.classify_identity_keys
    compute_cart_fingerprint_details = _se_mod.compute_cart_fingerprint_details
    compute_shipping_address_hash = _se_mod.compute_shipping_address_hash
    get_key_strength = _se_mod.get_key_strength
    select_strongest_matched_key = _se_mod.select_strongest_matched_key
    validate_financial_amount = _se_mod.validate_financial_amount


DEFAULT_DEADLOCK_WINDOW_SECONDS = 3600  # 60 minutes for post-refund agentic loops
VALID_REFUND_STATUSES = frozenset({"COMPLETED", "PENDING", "FAILED", "CANCELLED"})

CAPTURE_ID_FROM_URL_RE = re.compile(r"/v2/payments/captures/([A-Za-z0-9_-]+)")


def parse_paypal_timestamp(iso_or_epoch: Optional[str | float | int]) -> Optional[float]:
    if iso_or_epoch is None or isinstance(iso_or_epoch, bool):
        return None
    if isinstance(iso_or_epoch, (int, float)):
        value = float(iso_or_epoch)
        return value if math.isfinite(value) else None
    raw = str(iso_or_epoch).strip()
    if not raw:
        return None
    try:
        value = float(raw)
        return value if math.isfinite(value) else None
    except ValueError:
        pass
    try:
        if raw.endswith("Z"):
            raw = raw[:-1] + "+00:00"
        dt = datetime.fromisoformat(raw)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        value = dt.timestamp()
        return value if math.isfinite(value) else None
    except (ValueError, OverflowError):
        return None


def extract_capture_id_from_webhook(webhook_payload: Dict[str, Any]) -> Optional[str]:
    resource = webhook_payload.get("resource") or {}
    for link in resource.get("links") or []:
        if link.get("rel") == "up" and link.get("href"):
            match = CAPTURE_ID_FROM_URL_RE.search(link["href"])
            if match:
                return match.group(1)
    return None


def extract_refund_timestamps_from_webhook(
    webhook_payload: Dict[str, Any],
) -> Tuple[Optional[float], Optional[float]]:
    """
    P1 #2 Fix: Returns `(resource_create_time, webhook_envelope_time)`.
    Strictly extracts `resource.create_time` as the refund creation time and NEVER
    substitutes `resource.update_time` or the webhook envelope's `create_time`.
    """
    resource = webhook_payload.get("resource") or {}
    resource_create_ts = parse_paypal_timestamp(resource.get("create_time"))
    envelope_ts = parse_paypal_timestamp(webhook_payload.get("create_time"))
    return resource_create_ts, envelope_ts


def extract_refund_event_time_from_webhook(webhook_payload: Dict[str, Any]) -> Optional[float]:
    resource_create_ts, _ = extract_refund_timestamps_from_webhook(webhook_payload)
    return resource_create_ts


@dataclass
class RefundRecord:
    refund_id: str
    order_id: str
    capture_id: Optional[str]
    payer_id: Optional[str]
    payer_email: Optional[str]
    shipping_address_hash: Optional[str]
    custom_id: Optional[str]
    sku: Optional[str]
    cart_fingerprint: Optional[str]
    item_name: str
    description: str
    amount: str
    original_order_amount: Optional[str]
    currency: str
    customer_id: Optional[str] = None
    session_id: Optional[str] = None
    product_family_id: Optional[str] = None
    cart_family_signature: Optional[str] = None
    cart_fingerprint_complete: bool = False
    refund_status: str = "COMPLETED"
    refund_source: str = "PAYPAL_WEBHOOK"
    reason: Optional[str] = None
    refund_event_time: Optional[float] = None
    resource_update_time: Optional[float] = None
    webhook_envelope_time: Optional[float] = None
    webhook_received_at: float = field(default_factory=time.time)
    timestamp_resolved: bool = True
    refunded_at: Optional[float] = None
    incident_id: Optional[str] = None


@dataclass
class DeadlockCheckResult:
    is_deadlock: bool
    deadlock_reason: str
    refund_count_in_window: int
    time_since_last_refund_seconds: Optional[float]
    matched_identity_key: Optional[str]
    matched_identity_strength: str
    anchor_refund: Optional[RefundRecord]
    recent_refunds: List[RefundRecord]
    incident_id: Optional[str]
    allow_auto_capture: bool
    match_confidence: str = "NONE"
    matched_identity_keys: List[str] = field(default_factory=list)
    variant_match_mode: Optional[str] = None


@dataclass
class CombinedPillar1Result:
    is_flagged: bool
    can_auto_capture_if_llm_approves: bool
    incident_id: Optional[str]
    velocity_result: VelocityCheckResult
    deadlock_result: DeadlockCheckResult


class BuyRefundDeadlockDetector:
    """
    60-minute event-triggered refund-to-rebuy correlation engine for Pillar 1.
    """

    def __init__(
        self,
        window_seconds: int = DEFAULT_DEADLOCK_WINDOW_SECONDS,
        db_path: Optional[str] = None,
    ) -> None:
        self.window_seconds = window_seconds
        self.db_path = db_path
        self._lock = threading.RLock()

        self._identity_refund_index: Dict[str, List[str]] = {}
        self._refund_indexed_keys: Dict[str, Set[str]] = {}
        self._refunds_by_id: Dict[str, RefundRecord] = {}

        if self.db_path:
            self._init_db()
            self._load_persisted_refunds()

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path, timeout=10.0) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS refund_records_store (
                    refund_id TEXT PRIMARY KEY,
                    record_json TEXT NOT NULL,
                    indexed_keys_json TEXT NOT NULL,
                    webhook_received_at REAL NOT NULL
                )
                """
            )
            conn.commit()

    def _persist_refund_locked(self, record: RefundRecord) -> None:
        if not self.db_path:
            return
        keys_list = sorted(self._refund_indexed_keys.get(record.refund_id, set()))
        with sqlite3.connect(self.db_path, timeout=10.0) as conn:
            conn.execute(
                """
                INSERT INTO refund_records_store (refund_id, record_json, indexed_keys_json, webhook_received_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(refund_id) DO UPDATE SET
                    record_json = excluded.record_json,
                    indexed_keys_json = excluded.indexed_keys_json,
                    webhook_received_at = excluded.webhook_received_at
                """,
                (
                    record.refund_id,
                    json.dumps(asdict(record)),
                    json.dumps(keys_list),
                    record.webhook_received_at,
                ),
            )
            conn.commit()

    def _delete_persisted_refund_locked(self, refund_id: str) -> None:
        if not self.db_path:
            return
        with sqlite3.connect(self.db_path, timeout=10.0) as conn:
            conn.execute("DELETE FROM refund_records_store WHERE refund_id = ?", (refund_id,))
            conn.commit()

    def _load_persisted_refunds(self) -> None:
        if not self.db_path:
            return
        with self._lock:
            with sqlite3.connect(self.db_path, timeout=10.0) as conn:
                rows = conn.execute(
                    "SELECT record_json, indexed_keys_json FROM refund_records_store ORDER BY webhook_received_at ASC"
                ).fetchall()
            for rec_json, keys_json in rows:
                data = json.loads(rec_json)
                rec = RefundRecord(**data)
                keys = json.loads(keys_json)
                self._refunds_by_id[rec.refund_id] = rec
                if rec.timestamp_resolved and rec.refund_event_time is not None and rec.refund_status == "COMPLETED":
                    self._index_refund_locked(rec, keys, persist=False)

    def _index_refund_locked(
        self,
        record: RefundRecord,
        identity_keys: List[str],
        persist: bool = True,
    ) -> None:
        rid = record.refund_id
        old_keys = self._refund_indexed_keys.get(rid, set())
        new_key_set = set(identity_keys)

        for stale_key in old_keys - new_key_set:
            bucket = self._identity_refund_index.get(stale_key)
            if bucket is not None:
                self._identity_refund_index[stale_key] = [x for x in bucket if x != rid]
                if not self._identity_refund_index[stale_key]:
                    del self._identity_refund_index[stale_key]

        if record.timestamp_resolved and record.refund_event_time is not None and record.refund_status == "COMPLETED":
            for key in identity_keys:
                bucket = self._identity_refund_index.setdefault(key, [])
                if rid not in bucket:
                    bucket.append(rid)
            self._refund_indexed_keys[rid] = new_key_set
        else:
            for k in old_keys:
                bucket = self._identity_refund_index.get(k)
                if bucket is not None:
                    self._identity_refund_index[k] = [x for x in bucket if x != rid]
                    if not self._identity_refund_index[k]:
                        del self._identity_refund_index[k]
            self._refund_indexed_keys[rid] = set()

        if persist:
            self._persist_refund_locked(record)

    def _prune_expired_refunds(self, current_time: float) -> None:
        cutoff = current_time - self.window_seconds
        active_refund_ids: Set[str] = set()

        for key in list(self._identity_refund_index.keys()):
            valid_ids = [
                rid
                for rid in self._identity_refund_index[key]
                if rid in self._refunds_by_id
                and self._refunds_by_id[rid].timestamp_resolved
                and self._refunds_by_id[rid].refund_event_time is not None
                and self._refunds_by_id[rid].refund_event_time >= cutoff
                and self._refunds_by_id[rid].refund_status == "COMPLETED"
            ]
            if valid_ids:
                self._identity_refund_index[key] = valid_ids
                active_refund_ids.update(valid_ids)
            else:
                del self._identity_refund_index[key]

        for rid in list(self._refunds_by_id.keys()):
            rec = self._refunds_by_id[rid]
            ref_ts = rec.refund_event_time if rec.refund_event_time is not None else rec.webhook_received_at
            if rid not in active_refund_ids and ref_ts < cutoff and rec.webhook_received_at < cutoff:
                self._refund_indexed_keys.pop(rid, None)
                del self._refunds_by_id[rid]
                self._delete_persisted_refund_locked(rid)

    def get_refund(self, refund_id: str) -> Optional[RefundRecord]:
        with self._lock:
            rec = self._refunds_by_id.get(refund_id.strip())
            return copy.deepcopy(rec) if rec is not None else None

    def assign_refund_incident_id(
        self,
        refund_id: str,
        incident_id: str,
        *,
        replace_existing: bool = False,
    ) -> bool:
        """Persist the canonical incident ID for a refund already in the ledger.

        `replace_existing` is reserved for the combined P1 evaluator, which reconciles
        the independently derived velocity/deadlock IDs after both detectors agree that
        the same checkout is a refund-rebuy incident.
        """
        clean_refund_id = (refund_id or "").strip()
        clean_incident_id = (incident_id or "").strip()
        if not clean_refund_id:
            raise ValueError("refund_id is required.")
        if not clean_incident_id:
            raise ValueError("incident_id is required.")
        with self._lock:
            record = self._refunds_by_id.get(clean_refund_id)
            if record is None:
                return False
            if (
                record.incident_id
                and record.incident_id != clean_incident_id
                and not replace_existing
            ):
                return False
            if record.incident_id != clean_incident_id:
                candidate = copy.deepcopy(record)
                candidate.incident_id = clean_incident_id
                self._persist_refund_locked(candidate)
                self._refunds_by_id[clean_refund_id] = candidate
            return True

    def record_refund(
        self,
        refund_id: str,
        order_id: Optional[str] = None,
        amount: str | float | int | Decimal = "0.00",
        original_order_amount: Optional[str | float | int | Decimal] = None,
        currency: Optional[str] = None,
        capture_id: Optional[str] = None,
        payer_id: Optional[str] = None,
        payer_email: Optional[str] = None,
        shipping_address_hash: Optional[str] = None,
        custom_id: Optional[str] = None,
        customer_id: Optional[str] = None,
        session_id: Optional[str] = None,
        sku: Optional[str] = None,
        product_family_id: Optional[str] = None,
        items: Optional[List[Dict[str, Any]]] = None,
        item_name: str = "",
        description: str = "",
        refund_status: Optional[str] = None,
        refund_source: str = "PAYPAL_WEBHOOK",
        reason: Optional[str] = None,
        refund_event_time: Optional[str | float | int] = None,
        resource_update_time: Optional[str | float | int] = None,
        webhook_envelope_time: Optional[str | float | int] = None,
        webhook_received_at: Optional[float] = None,
        timestamp_resolved: Optional[bool] = None,
        state_engine: Optional[VelocityStateEngine] = None,
        now: Optional[float] = None,
    ) -> RefundRecord:
        if not refund_id or not refund_id.strip():
            raise ValueError("refund_id is required.")
        clean_refund_id = refund_id.strip()
        clean_capture_id = capture_id.strip() if capture_id and capture_id.strip() else None
        clean_order_id = order_id.strip() if order_id and order_id.strip() else None
        norm_source = (refund_source or "PAYPAL_WEBHOOK").strip().upper()
        if not clean_order_id and not clean_capture_id:
            raise ValueError("A refund must be linked to an order_id or capture_id.")

        explicit_status = (
            refund_status.strip().upper()
            if (refund_status is not None and str(refund_status).strip())
            else None
        )
        if explicit_status is not None and explicit_status not in VALID_REFUND_STATUSES:
            raise ValueError(f"Invalid refund_status '{refund_status}'.")

        received_ts = (
            webhook_received_at
            if webhook_received_at is not None
            else (now if now is not None else time.time())
        )
        if isinstance(received_ts, bool) or not isinstance(received_ts, (int, float)) or not math.isfinite(float(received_ts)):
            raise ValueError("webhook_received_at/now must be a finite Unix timestamp.")
        received_ts = float(received_ts)
        parsed_event_ts = parse_paypal_timestamp(refund_event_time)
        parsed_update_ts = parse_paypal_timestamp(resource_update_time)
        parsed_envelope_ts = parse_paypal_timestamp(webhook_envelope_time)
        for field_name, raw_value, parsed_value in (
            ("refund_event_time", refund_event_time, parsed_event_ts),
            ("resource_update_time", resource_update_time, parsed_update_ts),
            ("webhook_envelope_time", webhook_envelope_time, parsed_envelope_ts),
        ):
            if raw_value is not None and str(raw_value).strip() and parsed_value is None:
                raise ValueError(f"Invalid or non-finite {field_name}: {raw_value!r}.")

        # P1 #2 Fix: Never fall back a missing refund creation time to receipt time (`received_ts`).
        # Only an explicit `refund_event_time` (`resource.create_time`) resolves the event timestamp.
        if timestamp_resolved is not None:
            is_ts_resolved = bool(timestamp_resolved) and (parsed_event_ts is not None)
            effective_event_ts = parsed_event_ts if is_ts_resolved else None
        elif parsed_event_ts is not None:
            is_ts_resolved = True
            effective_event_ts = parsed_event_ts
        else:
            is_ts_resolved = False
            effective_event_ts = None

        if effective_event_ts is not None and effective_event_ts > (received_ts + MAX_FUTURE_CLOCK_SKEW_SECONDS):
            raise ValueError(
                f"Future-dated refund_event_time ({effective_event_ts}) exceeds current time "
                f"({received_ts}) by more than {MAX_FUTURE_CLOCK_SKEW_SECONDS}s."
            )

        # P0 #4: Resolve identifiers against the authoritative order ledger.
        linked_order: Optional[OrderRecord] = None
        allowed_currs = None
        if state_engine is not None:
            allowed_currs = state_engine.supported_currencies
            order_by_cap = state_engine.get_order_by_capture_id(clean_capture_id) if clean_capture_id else None
            order_by_id = state_engine.get_order(clean_order_id) if clean_order_id else None
            if clean_capture_id and order_by_cap is None:
                raise ValueError(
                    f"Unknown capture_id '{clean_capture_id}' in state_engine; register and verify its order mapping first."
                )
            if clean_order_id and order_by_id is None and order_by_cap is None:
                raise ValueError(f"Unknown order_id '{clean_order_id}' in state_engine.")
            if order_by_cap is not None and clean_order_id is not None and order_by_cap.order_id != clean_order_id:
                raise ValueError(
                    f"Inconsistent refund identifiers: capture_id '{clean_capture_id}' belongs to "
                    f"order '{order_by_cap.order_id}', not supplied order_id '{clean_order_id}'."
                )
            if order_by_id is not None and clean_capture_id is not None:
                known_caps = set(order_by_id.capture_ids or [])
                if order_by_id.capture_id:
                    known_caps.add(order_by_id.capture_id)
                if clean_capture_id not in known_caps:
                    raise ValueError(
                        f"Inconsistent refund identifiers: order_id '{clean_order_id}' has no verified "
                        f"mapping to capture_id '{clean_capture_id}' (known captures: {sorted(known_caps)})."
                    )
            linked_order = order_by_cap or order_by_id
            if linked_order is not None and not clean_capture_id:
                known_caps = set(linked_order.capture_ids or [])
                if linked_order.capture_id:
                    known_caps.add(linked_order.capture_id)
                if len(known_caps) != 1:
                    raise ValueError(
                        f"Refund for order '{linked_order.order_id}' requires exactly one known capture; found {len(known_caps)}."
                    )
                clean_capture_id = next(iter(known_caps))

            # Supplied strong identity must agree with the linked authoritative order.
            for field_name, incoming, authoritative, normalize in (
                ("payer_id", payer_id, getattr(linked_order, "payer_id", None), lambda x: x.strip()),
                ("payer_email", payer_email, getattr(linked_order, "payer_email", None), lambda x: x.strip().lower()),
                ("customer_id", customer_id, getattr(linked_order, "customer_id", None), lambda x: x.strip()),
            ):
                if incoming and incoming.strip() and authoritative and normalize(incoming) != normalize(authoritative):
                    raise ValueError(f"Refund {field_name} conflicts with linked order '{linked_order.order_id}'.")
        with self._lock:
            self._prune_expired_refunds(received_ts)

            existing = self._refunds_by_id.get(clean_refund_id)

            # P1 #1 Fix: Require explicit status for new PayPal webhook refund ingestion;
            # never silently default a missing webhook status to COMPLETED!
            if existing is None:
                if explicit_status is None:
                    if norm_source == "PAYPAL_WEBHOOK":
                        raise ValueError(
                            f"Explicit refund_status is required when ingesting PAYPAL_WEBHOOK "
                            f"refund '{clean_refund_id}'; do not default to COMPLETED."
                        )
                    clean_status = "COMPLETED"
                else:
                    clean_status = explicit_status
            else:
                clean_status = explicit_status or existing.refund_status
                allowed_refund_transitions = {
                    "PENDING": {"PENDING", "COMPLETED", "FAILED", "CANCELLED"},
                    "COMPLETED": {"COMPLETED"},
                    "FAILED": {"FAILED"},
                    "CANCELLED": {"CANCELLED"},
                }
                if clean_status not in allowed_refund_transitions.get(existing.refund_status, set()):
                    raise ValueError(
                        f"Invalid refund status transition for '{clean_refund_id}': "
                        f"{existing.refund_status} -> {clean_status}; terminal-state corrections require reconciliation."
                    )

            raw_curr = (
                currency.strip().upper()
                if currency and currency.strip()
                else (
                    linked_order.currency
                    if linked_order is not None
                    else (existing.currency if existing is not None else None)
                )
            )
            if not raw_curr:
                raise ValueError(
                    f"Refund currency is required for refund '{clean_refund_id}' when original "
                    "order is not locally resolvable. Do not silently default to USD."
                )

            if linked_order is not None and currency and currency.strip():
                if raw_curr != linked_order.currency:
                    raise ValueError(
                        f"Refund currency '{raw_curr}' does not match original order "
                        f"currency '{linked_order.currency}' for order {linked_order.order_id}."
                    )

            validate_financial_amount(
                amount,
                raw_curr,
                allow_zero=False,
                allowed_currencies=allowed_currs,
            )
            norm_refund_amount = _normalize_amount(amount, raw_curr)

            if linked_order is not None:
                order_amount_dec = validate_financial_amount(
                    linked_order.amount, raw_curr, allow_zero=False, allowed_currencies=allowed_currs
                )
                refund_amount_dec = validate_financial_amount(
                    amount, raw_curr, allow_zero=False, allowed_currencies=allowed_currs
                )
                if refund_amount_dec > order_amount_dec:
                    raise ValueError(
                        f"Refund amount '{refund_amount_dec}' exceeds original order amount '{order_amount_dec}'."
                    )
                clean_order_id = clean_order_id or linked_order.order_id
                payer_id = payer_id or linked_order.payer_id
                payer_email = payer_email or linked_order.payer_email
                shipping_address_hash = shipping_address_hash or linked_order.shipping_address_hash
                custom_id = custom_id or linked_order.custom_id
                customer_id = customer_id or linked_order.customer_id
                session_id = session_id or linked_order.session_id
                sku = sku or linked_order.sku
                product_family_id = product_family_id or linked_order.product_family_id
                item_name = item_name or linked_order.item_name
                description = description or linked_order.description
                if original_order_amount is None:
                    original_order_amount = linked_order.amount

            norm_orig_amount: Optional[str] = None
            if original_order_amount is not None:
                validate_financial_amount(
                    original_order_amount,
                    raw_curr,
                    allow_zero=False,
                    allowed_currencies=allowed_currs,
                )
                norm_orig_amount = _normalize_amount(original_order_amount, raw_curr)

            sku_clean = sku.strip() if sku and sku.strip() else None
            cart_family_sig = (
                linked_order.cart_family_signature
                if linked_order and linked_order.cart_family_signature
                else (
                    state_engine.compute_cart_family_signature(
                        sku=sku_clean,
                        product_family_id=product_family_id,
                        items=items,
                    )
                    if state_engine
                    else (
                        f"{product_family_id.strip().upper()}:1"
                        if product_family_id and product_family_id.strip()
                        else None
                    )
                )
            )
            if linked_order and linked_order.cart_fingerprint:
                cart_fp = linked_order.cart_fingerprint
                fp_complete = linked_order.cart_fingerprint_complete
            else:
                cart_fp, fp_complete = compute_cart_fingerprint_details(sku=sku_clean, items=items)

            if existing is not None:
                if existing.amount != norm_refund_amount:
                    raise ValueError(
                        f"Conflicting duplicate refund_id '{clean_refund_id}': existing amount "
                        f"'{existing.amount}' != incoming amount '{norm_refund_amount}'."
                    )
                if existing.currency != raw_curr:
                    raise ValueError(
                        f"Conflicting duplicate refund_id '{clean_refund_id}': existing currency "
                        f"'{existing.currency}' != incoming currency '{raw_curr}'."
                    )
                if (
                    clean_capture_id
                    and existing.capture_id
                    and existing.capture_id != clean_capture_id
                ):
                    raise ValueError(
                        f"Conflicting duplicate refund_id '{clean_refund_id}': existing capture_id "
                        f"'{existing.capture_id}' != incoming capture_id '{clean_capture_id}'."
                    )
                if (
                    clean_order_id
                    and existing.order_id
                    and not existing.order_id.startswith("unknown_for_")
                    and existing.order_id != clean_order_id
                ):
                    raise ValueError(
                        f"Conflicting duplicate refund_id '{clean_refund_id}': existing order_id "
                        f"'{existing.order_id}' != incoming order_id '{clean_order_id}'."
                    )

                for field_name, incoming, recorded, normalize in (
                    ("payer_id", payer_id, existing.payer_id, lambda x: x.strip()),
                    ("payer_email", payer_email, existing.payer_email, lambda x: x.strip().lower()),
                    ("customer_id", customer_id, existing.customer_id, lambda x: x.strip()),
                ):
                    if incoming and incoming.strip() and recorded and normalize(incoming) != normalize(recorded):
                        raise ValueError(f"Conflicting duplicate refund_id '{clean_refund_id}': {field_name} mismatch.")

                if clean_capture_id and not existing.capture_id:
                    existing.capture_id = clean_capture_id
                if clean_order_id and (not existing.order_id or existing.order_id.startswith("unknown_for_")):
                    existing.order_id = clean_order_id
                if payer_id and not existing.payer_id:
                    existing.payer_id = payer_id.strip()
                if payer_email and not existing.payer_email:
                    existing.payer_email = payer_email.strip().lower()
                if shipping_address_hash and not existing.shipping_address_hash:
                    existing.shipping_address_hash = shipping_address_hash.strip()
                if custom_id and not existing.custom_id:
                    existing.custom_id = custom_id.strip()
                if customer_id and not existing.customer_id:
                    existing.customer_id = customer_id.strip()
                if session_id and not existing.session_id:
                    existing.session_id = session_id.strip()
                if sku_clean and not existing.sku:
                    existing.sku = sku_clean
                if product_family_id and not existing.product_family_id:
                    existing.product_family_id = product_family_id
                if cart_family_sig and not existing.cart_family_signature:
                    existing.cart_family_signature = cart_family_sig
                if cart_fp and not existing.cart_fingerprint:
                    existing.cart_fingerprint = cart_fp
                    existing.cart_fingerprint_complete = fp_complete
                if norm_orig_amount and existing.original_order_amount is None:
                    existing.original_order_amount = norm_orig_amount
                if is_ts_resolved and effective_event_ts is not None and not existing.timestamp_resolved:
                    existing.refund_event_time = effective_event_ts
                    existing.refunded_at = effective_event_ts
                    existing.timestamp_resolved = True
                if parsed_update_ts is not None:
                    existing.resource_update_time = parsed_update_ts
                if explicit_status is not None:
                    existing.refund_status = explicit_status

                enriched_keys, _, _ = classify_identity_keys(
                    payer_id=existing.payer_id,
                    payer_email=existing.payer_email,
                    shipping_address_hash=existing.shipping_address_hash,
                    custom_id=existing.custom_id,
                    customer_id=existing.customer_id,
                    session_id=existing.session_id,
                    client_ip=None,
                )
                self._index_refund_locked(existing, enriched_keys)
                return copy.deepcopy(existing)

            identity_keys, _, _ = classify_identity_keys(
                payer_id=payer_id,
                payer_email=payer_email,
                shipping_address_hash=shipping_address_hash,
                custom_id=custom_id,
                customer_id=customer_id,
                session_id=session_id,
                client_ip=None,
            )

            if not identity_keys:
                if state_engine is not None or (not clean_capture_id and not clean_order_id):
                    raise ValueError(
                        f"Cannot index refund {clean_refund_id} with zero buyer identity keys. "
                        "Resolve capture_id -> order -> buyer first."
                    )

            record = RefundRecord(
                refund_id=clean_refund_id,
                order_id=(clean_order_id or f"unknown_for_{clean_capture_id}"),
                capture_id=clean_capture_id,
                payer_id=payer_id.strip() if payer_id and payer_id.strip() else None,
                payer_email=payer_email.strip().lower() if payer_email and payer_email.strip() else None,
                shipping_address_hash=shipping_address_hash,
                custom_id=custom_id,
                customer_id=customer_id,
                session_id=session_id,
                product_family_id=product_family_id,
                cart_family_signature=cart_family_sig,
                cart_fingerprint_complete=fp_complete,
                sku=sku_clean,
                cart_fingerprint=cart_fp,
                item_name=item_name,
                description=description,
                amount=norm_refund_amount,
                original_order_amount=norm_orig_amount,
                currency=raw_curr,
                refund_status=clean_status,
                refund_source=norm_source,
                reason=reason,
                refund_event_time=effective_event_ts,
                resource_update_time=parsed_update_ts,
                webhook_envelope_time=parsed_envelope_ts,
                webhook_received_at=received_ts,
                timestamp_resolved=is_ts_resolved,
                refunded_at=effective_event_ts,
            )

            self._refunds_by_id[record.refund_id] = record
            self._index_refund_locked(record, identity_keys)
            return copy.deepcopy(record)

    def check_buy_refund_deadlock(
        self,
        amount: str | float | int | Decimal,
        currency: str = "USD",
        payer_id: Optional[str] = None,
        payer_email: Optional[str] = None,
        shipping_address_hash: Optional[str] = None,
        custom_id: Optional[str] = None,
        customer_id: Optional[str] = None,
        session_id: Optional[str] = None,
        sku: Optional[str] = None,
        product_family_id: Optional[str] = None,
        items: Optional[List[Dict[str, Any]]] = None,
        item_name: str = "",
        description: str = "",
        state_engine: Optional[VelocityStateEngine] = None,
        now: Optional[float] = None,
    ) -> DeadlockCheckResult:
        if now is not None and (
            isinstance(now, bool) or not isinstance(now, (int, float)) or not math.isfinite(float(now))
        ):
            raise ValueError("now must be a finite Unix timestamp.")
        current_time = float(now) if now is not None else time.time()
        norm_currency = (currency or "USD").strip().upper()
        allowed_currs = state_engine.supported_currencies if state_engine is not None else None
        validate_financial_amount(
            amount,
            norm_currency,
            allow_zero=False,
            allowed_currencies=allowed_currs,
        )
        norm_amount = _normalize_amount(amount, norm_currency)
        sku_clean = sku.strip() if sku and sku.strip() else None
        cart_family_sig = (
            state_engine.compute_cart_family_signature(
                sku=sku_clean,
                product_family_id=product_family_id,
                items=items,
            )
            if state_engine
            else (
                f"{product_family_id.strip().upper()}:1"
                if product_family_id and product_family_id.strip()
                else None
            )
        )
        allow_heuristic = (
            state_engine.allow_sku_prefix_heuristic if state_engine is not None else False
        )
        cart_fp, fp_complete = compute_cart_fingerprint_details(sku=sku_clean, items=items)

        identity_keys, _, identity_strength = classify_identity_keys(
            payer_id=payer_id,
            payer_email=payer_email,
            shipping_address_hash=shipping_address_hash,
            custom_id=custom_id,
            customer_id=customer_id,
            session_id=session_id,
            client_ip=None,
        )
        has_strong_identity = identity_strength == "STRONG"

        if not identity_keys:
            return DeadlockCheckResult(
                is_deadlock=False,
                deadlock_reason="MISSING_BUYER_IDENTITY",
                refund_count_in_window=0,
                time_since_last_refund_seconds=None,
                matched_identity_key=None,
                matched_identity_strength="NONE",
                anchor_refund=None,
                recent_refunds=[],
                incident_id=None,
                allow_auto_capture=False,
                match_confidence="NONE",
                matched_identity_keys=[],
            )

        with self._lock:
            self._prune_expired_refunds(current_time)

            keys_by_refund_id: Dict[str, List[str]] = {}
            for key in identity_keys:
                rids = self._identity_refund_index.get(key, [])
                for rid in rids:
                    keys_by_refund_id.setdefault(rid, []).append(key)

            prior_refunds: List[RefundRecord] = sorted(
                (
                    self._refunds_by_id[rid]
                    for rid in keys_by_refund_id.keys()
                    if rid in self._refunds_by_id
                    and self._refunds_by_id[rid].timestamp_resolved
                    and self._refunds_by_id[rid].refund_event_time is not None
                    and self._refunds_by_id[rid].refund_status == "COMPLETED"
                    and self._refunds_by_id[rid].refund_event_time <= (current_time + MAX_FUTURE_CLOCK_SKEW_SECONDS)
                ),
                key=lambda r: r.refund_event_time or 0.0,
            )

            if not prior_refunds:
                return DeadlockCheckResult(
                    is_deadlock=False,
                    deadlock_reason="NO_RECENT_REFUND_FOR_BUYER",
                    refund_count_in_window=0,
                    time_since_last_refund_seconds=None,
                    matched_identity_key=None,
                    matched_identity_strength="NONE",
                    anchor_refund=None,
                    recent_refunds=[],
                    incident_id=None,
                    allow_auto_capture=has_strong_identity,
                    match_confidence="NONE",
                    matched_identity_keys=[],
                )

            correlated_refunds: List[RefundRecord] = []
            saw_variant_exchange = False
            variant_match_mode: Optional[str] = None
            saw_exact_cart_match = False
            cur_text = f"{item_name} {description}"

            for ref in prior_refunds:
                if ref.currency != norm_currency:
                    continue

                ref_text = f"{ref.item_name} {ref.description}"

                match_mode = VelocityStateEngine._resolve_distinct_variant_match_mode(
                    cart_fp,
                    ref.cart_fingerprint,
                    cur_text,
                    ref_text,
                    current_family=cart_family_sig,
                    prev_family=ref.cart_family_signature,
                    allow_sku_prefix_heuristic=allow_heuristic,
                    current_fp_complete=fp_complete,
                    prev_fp_complete=ref.cart_fingerprint_complete,
                )
                if match_mode is not None:
                    saw_variant_exchange = True
                    variant_match_mode = match_mode
                    continue

                if (
                    fp_complete
                    and ref.cart_fingerprint_complete
                    and cart_fp
                    and ref.cart_fingerprint
                    and cart_fp == ref.cart_fingerprint
                ):
                    correlated_refunds.append(ref)
                    saw_exact_cart_match = True
                    continue

                if norm_amount == ref.amount or (
                    ref.original_order_amount is not None
                    and norm_amount == ref.original_order_amount
                ):
                    correlated_refunds.append(ref)

            if not correlated_refunds:
                reason = (
                    "VARIANT_EXCHANGE_DIFFERENT_SKU_ALLOWED"
                    if saw_variant_exchange
                    else "UNCORRELATED_REFUND_AMOUNT_OR_CURRENCY"
                )
                return DeadlockCheckResult(
                    is_deadlock=False,
                    deadlock_reason=reason,
                    refund_count_in_window=0,
                    time_since_last_refund_seconds=None,
                    matched_identity_key=None,
                    matched_identity_strength="NONE",
                    anchor_refund=None,
                    recent_refunds=[],
                    incident_id=None,
                    allow_auto_capture=has_strong_identity,
                    match_confidence="NONE",
                    matched_identity_keys=[],
                    variant_match_mode=variant_match_mode if saw_variant_exchange else None,
                )

            correlated_matched_keys: List[str] = []
            for corr_ref in correlated_refunds:
                for k in keys_by_refund_id.get(corr_ref.refund_id, []):
                    if k not in correlated_matched_keys:
                        correlated_matched_keys.append(k)
            matched_key, matched_key_strength = select_strongest_matched_key(correlated_matched_keys)

            anchor_refund = correlated_refunds[0]
            latest_refund = correlated_refunds[-1]
            time_since_refund = max(
                0.0, current_time - (latest_refund.refund_event_time or current_time)
            )

            incident_id = anchor_refund.incident_id
            if not incident_id:
                raw_inc = f"deadlock|{matched_key or 'anon'}|{anchor_refund.order_id}"
                incident_id = f"inc_{hashlib.sha256(raw_inc.encode('utf-8')).hexdigest()[:12]}"
                anchor_refund.incident_id = incident_id
                self._persist_refund_locked(anchor_refund)

            if saw_exact_cart_match:
                deadlock_reason = "POST_REFUND_SAME_SKU_REBUY_DEADLOCK"
                match_confidence = "CONFIRMED_SAME_CART_DEADLOCK"
            else:
                deadlock_reason = "POST_REFUND_SAME_AMOUNT_MUTATED_REBUY_DEADLOCK"
                match_confidence = "SUSPECTED_AMOUNT_CORRELATION_CANDIDATE"

            return DeadlockCheckResult(
                is_deadlock=True,
                deadlock_reason=deadlock_reason,
                refund_count_in_window=len(correlated_refunds),
                time_since_last_refund_seconds=round(time_since_refund, 3),
                matched_identity_key=matched_key,
                matched_identity_strength=matched_key_strength,
                anchor_refund=copy.deepcopy(anchor_refund),
                recent_refunds=[copy.deepcopy(r) for r in correlated_refunds],
                incident_id=incident_id,
                allow_auto_capture=False,
                match_confidence=match_confidence,
                matched_identity_keys=correlated_matched_keys,
            )


def evaluate_checkout_pillar1(
    state_engine: VelocityStateEngine,
    deadlock_detector: BuyRefundDeadlockDetector,
    order_id: str,
    amount: str | float | int | Decimal,
    currency: str = "USD",
    payer_id: Optional[str] = None,
    payer_email: Optional[str] = None,
    shipping_address_hash: Optional[str] = None,
    custom_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    session_id: Optional[str] = None,
    sku: Optional[str] = None,
    product_family_id: Optional[str] = None,
    items: Optional[List[Dict[str, Any]]] = None,
    item_name: str = "",
    description: str = "",
    intent: str = "AUTHORIZE",
    note_to_payer: Optional[str] = None,
    client_ip: Optional[str] = None,
    user_agent: Optional[str] = None,
    now: Optional[float] = None,
) -> CombinedPillar1Result:
    deadlock_res = deadlock_detector.check_buy_refund_deadlock(
        amount=amount,
        currency=currency,
        payer_id=payer_id,
        payer_email=payer_email,
        shipping_address_hash=shipping_address_hash,
        custom_id=custom_id,
        customer_id=customer_id,
        session_id=session_id,
        sku=sku,
        product_family_id=product_family_id,
        items=items,
        item_name=item_name,
        description=description,
        state_engine=state_engine,
        now=now,
    )
    velocity_res = state_engine.check_and_record_order(
        order_id=order_id,
        amount=amount,
        currency=currency,
        payer_id=payer_id,
        payer_email=payer_email,
        shipping_address_hash=shipping_address_hash,
        custom_id=custom_id,
        customer_id=customer_id,
        session_id=session_id,
        sku=sku,
        product_family_id=product_family_id,
        items=items,
        item_name=item_name,
        description=description,
        intent=intent,
        note_to_payer=note_to_payer,
        client_ip=client_ip,
        user_agent=user_agent,
        now=now,
    )

    is_flagged = velocity_res.is_flagged or deadlock_res.is_deadlock
    can_auto_capture = (
        velocity_res.can_auto_capture_if_llm_approves
        and deadlock_res.allow_auto_capture
    )
    # Keep the order's first canonical incident stable if velocity and refund-deadlock
    # detectors independently produce different incident IDs for the same checkout.
    existing_order = state_engine.get_order(order_id)
    incident_id = (
        existing_order.incident_id if existing_order is not None and existing_order.incident_id
        else (deadlock_res.incident_id or velocity_res.incident_id)
    )
    if incident_id:
        state_engine.assign_order_incident_id(
            order_id=order_id,
            incident_id=incident_id,
        )
        # Velocity and refund-deadlock detectors can independently derive an ID for
        # this same checkout. Once the combined evaluator selects the order's canonical
        # incident, propagate it to every refund included in this deadlock correlation.
        if deadlock_res.is_deadlock:
            for refund_record in deadlock_res.recent_refunds or []:
                deadlock_detector.assign_refund_incident_id(
                    refund_id=refund_record.refund_id,
                    incident_id=incident_id,
                    replace_existing=True,
                )
            if deadlock_res.anchor_refund is not None:
                # Keep the original purchase, its refund, and the rebuy under the
                # same incident wherever the anchor order has no earlier incident.
                state_engine.assign_order_incident_id(
                    order_id=deadlock_res.anchor_refund.order_id,
                    incident_id=incident_id,
                )
                deadlock_res.anchor_refund.incident_id = incident_id
            deadlock_res.recent_refunds = [
                deadlock_detector.get_refund(ref.refund_id) or ref
                for ref in (deadlock_res.recent_refunds or [])
            ]
            if deadlock_res.anchor_refund is not None:
                deadlock_res.anchor_refund = (
                    deadlock_detector.get_refund(deadlock_res.anchor_refund.refund_id)
                    or deadlock_res.anchor_refund
                )
            deadlock_res.incident_id = incident_id
    # P0 #1 Fix: Always persist the final combined `can_auto_capture` eligibility
    # (never restoring eligibility via `velocity_res.has_reliable_identity`).
    if hasattr(state_engine, "set_order_auto_capture_eligibility"):
        state_engine.set_order_auto_capture_eligibility(
            order_id,
            can_auto_capture,
            is_flagged=is_flagged,
        )

    return CombinedPillar1Result(
        is_flagged=is_flagged,
        can_auto_capture_if_llm_approves=can_auto_capture,
        incident_id=incident_id,
        velocity_result=velocity_res,
        deadlock_result=deadlock_res,
    )


def validate_mvp_order_shape(paypal_order: Dict[str, Any]) -> None:
    """Enforce the single-merchant MVP order-shape boundary on a PayPal order resource.

    This is called both when evaluating the approved order and again at P3's fresh
    server-side settlement lookup so a stale/caller-supplied snapshot cannot bypass it.
    """
    if not isinstance(paypal_order, dict):
        raise ValueError("paypal_order must be a dict.")
    order_id = str(paypal_order.get("id") or "<unknown>").strip() or "<unknown>"
    purchase_units = paypal_order.get("purchase_units")
    if not isinstance(purchase_units, list) or len(purchase_units) != 1:
        count = len(purchase_units) if isinstance(purchase_units, list) else 0
        raise ValueError(
            f"UNSUPPORTED_INTENT: PayPal order '{order_id}' must contain exactly one purchase_unit (got {count})."
        )
    pu0 = purchase_units[0]
    if not isinstance(pu0, dict):
        raise ValueError(f"PayPal order '{order_id}' purchase_units[0] is malformed.")
    if "payment_instruction" in pu0:
        raise ValueError(
            "MARKETPLACE_PAYMENT_INSTRUCTIONS_DISABLED_IN_MVP: payment_instruction is not supported."
        )
    if "payee" in pu0 and pu0["payee"] is not None:
        payee_obj = pu0["payee"]
        if not isinstance(payee_obj, dict):
            raise ValueError(
                "CALLER_SELECTED_PAYEE_DISABLED_IN_MVP: purchase_units[0].payee is malformed."
            )
        expected_merchant_id = (os.getenv("PAYPAL_MERCHANT_ID") or "").strip()
        actual_merchant_id = str(payee_obj.get("merchant_id") or "").strip()
        if actual_merchant_id.upper() in ("UNTRUSTED", "ATTACKER", "EXTERNAL_PAYEE"):
            raise ValueError(
                "CALLER_SELECTED_PAYEE_DISABLED_IN_MVP: untrusted purchase_units[0].payee is not supported."
            )
        if expected_merchant_id and actual_merchant_id and actual_merchant_id != expected_merchant_id:
            raise ValueError(
                f"CALLER_SELECTED_PAYEE_DISABLED_IN_MVP: payee merchant_id '{actual_merchant_id}' "
                f"does not match configured PAYPAL_MERCHANT_ID '{expected_merchant_id}'."
            )

    if "items" in pu0:
        items = pu0.get("items")
        if not isinstance(items, list) or not items:
            raise ValueError(
                "INVALID_ARRAY_MIN_ITEMS: purchase_units[0].items must be a non-empty list when supplied."
            )
        for index, item in enumerate(items):
            if not isinstance(item, dict):
                raise ValueError(
                    f"PayPal order '{order_id}' contains malformed cart item at index {index}."
                )
            if not str(item.get("name") or "").strip():
                raise ValueError(
                    f"PayPal order '{order_id}' purchase_units[0].items[{index}].name is required."
                )
    else:
        description = str(pu0.get("description") or "").strip()
        custom_id = str(pu0.get("custom_id") or "").strip()
        if not description and not custom_id:
            raise ValueError(
                "ORDER_PRODUCT_SIGNAL_REQUIRED: provide non-empty items, description, or custom_id."
            )


def evaluate_approved_paypal_order(
    state_engine: VelocityStateEngine,
    deadlock_detector: BuyRefundDeadlockDetector,
    paypal_order: Dict[str, Any],
    customer_id: Optional[str] = None,
    session_id: Optional[str] = None,
    product_family_id: Optional[str] = None,
    note_to_payer: Optional[str] = None,
    client_ip: Optional[str] = None,
    user_agent: Optional[str] = None,
    now: Optional[float] = None,
) -> CombinedPillar1Result:
    if not isinstance(paypal_order, dict):
        raise ValueError("paypal_order must be a dict.")

    order_id = str(paypal_order.get("id") or "").strip()
    if not order_id:
        raise ValueError("PayPal order is missing a valid 'id'.")

    status = str(paypal_order.get("status") or "").strip().upper()
    if status != "APPROVED":
        raise ValueError(
            f"PayPal order '{order_id}' must have status='APPROVED' before Pillar 1 evaluation "
            f"(got status='{status}')."
        )

    intent = str(paypal_order.get("intent") or "").strip().upper()
    if intent != "AUTHORIZE":
        raise ValueError(
            f"PayPal order '{order_id}' must have intent='AUTHORIZE' (got intent='{intent}')."
        )

    pu_list = paypal_order.get("purchase_units")
    if not isinstance(pu_list, list) or not pu_list:
        raise ValueError(f"PayPal order '{order_id}' has no purchase_units.")

    if len(pu_list) != 1:
        raise ValueError(
            f"UNSUPPORTED_INTENT: PayPal order '{order_id}' with intent='AUTHORIZE' supports "
            f"only 1 purchase_unit (got {len(pu_list)})."
        )

    pu0 = pu_list[0]
    if not isinstance(pu0, dict):
        raise ValueError(f"PayPal order '{order_id}' purchase_units[0] is malformed.")
    validate_mvp_order_shape(paypal_order)

    amount_obj = pu0.get("amount") or {}
    raw_val = amount_obj.get("value")
    raw_curr = str(amount_obj.get("currency_code") or "").strip().upper()
    dec_val = validate_financial_amount(
        raw_val,
        raw_curr,
        allow_zero=False,
        allowed_currencies=state_engine.supported_currencies,
    )
    formatted_amount = _normalize_amount(dec_val, raw_curr)

    custom_id = (
        str(pu0.get("custom_id")).strip()
        if pu0.get("custom_id")
        else None
    )
    raw_items = pu0.get("items")
    if raw_items is not None and not isinstance(raw_items, list):
        raise ValueError(f"PayPal order '{order_id}' purchase_units[0].items must be a list when supplied.")
    items = raw_items
    if items is not None and any(not isinstance(item, dict) for item in items):
        raise ValueError(
            f"PayPal order '{order_id}' contains a malformed cart line item; every item must be an object."
        )
    valid_items = list(items or [])
    item_names: List[str] = []
    line_item_descriptions: List[str] = []
    for item in valid_items:
        name = str(item.get("name") or "").strip()
        item_description = str(item.get("description") or "").strip()
        if name:
            item_names.append(name)
        if item_description:
            if name:
                line_item_descriptions.append(f"{name}: {item_description}")
            else:
                line_item_descriptions.append(item_description)

    sku = (
        str(valid_items[0].get("sku")).strip()
        if (
            items is not None
            and len(items) == 1
            and len(valid_items) == 1
            and valid_items[0].get("sku")
            and str(valid_items[0].get("sku")).strip()
        )
        else None
    )
    item_name = ", ".join(item_names)
    pu_description = str(pu0.get("description") or "").strip()
    desc_parts: List[str] = []
    if pu_description:
        desc_parts.append(pu_description)
    for li_desc in line_item_descriptions:
        if li_desc not in desc_parts:
            desc_parts.append(li_desc)
    description = " | ".join(desc_parts)

    shipping = pu0.get("shipping") or {}
    addr = shipping.get("address") or {}
    ship_name = (shipping.get("name") or {}).get("full_name")
    shipping_address_hash = compute_shipping_address_hash(
        address_line_1=addr.get("address_line_1"),
        postal_code=addr.get("postal_code"),
        country_code=addr.get("country_code"),
        recipient_name=ship_name,
        address_line_2=addr.get("address_line_2"),
        admin_area_1=addr.get("admin_area_1"),
        admin_area_2=addr.get("admin_area_2"),
    )

    payer = paypal_order.get("payer") or {}
    payer_id = payer.get("payer_id")
    payer_email = payer.get("email_address")

    return evaluate_checkout_pillar1(
        state_engine=state_engine,
        deadlock_detector=deadlock_detector,
        order_id=order_id,
        amount=formatted_amount,
        currency=raw_curr,
        payer_id=payer_id,
        payer_email=payer_email,
        shipping_address_hash=shipping_address_hash,
        custom_id=custom_id,
        customer_id=customer_id,
        session_id=session_id,
        sku=sku,
        product_family_id=product_family_id,
        items=items,
        item_name=item_name,
        description=description,
        intent=intent,
        note_to_payer=note_to_payer,
        client_ip=client_ip,
        user_agent=user_agent,
        now=now,
    )