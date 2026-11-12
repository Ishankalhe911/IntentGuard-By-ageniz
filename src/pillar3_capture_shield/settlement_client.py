"""
Phase 3 (File 3/3): Post-Approval Settlement Orchestrator & 1-Tap Kill Switch Client
Location: src/pillar3_capture_shield/settlement_client.py

Complete Section B, C, D + Round 2 Audited Implementation:
1. Idempotent `settle_approved_order` with Per-Order Locking & Forward-Only State Guard (Must-Fix #2):
   - Serializes concurrent calls on the same `order_id` (`_get_order_lock(order_id)`).
   - If the ledger record is already settled (`CAPTURED`, `PARTIALLY_CAPTURED`, `VOIDED`,
     `AUTHORIZED_HOLD`, or `NEEDS_ATTENTION` with an existing `authorization_id`), returns the
     existing `SettlementOutcome` immediately so duplicate webhook/return-URL calls never flip a
     captured or voided order back into a hold.
   - If an order is in `NEEDS_ATTENTION` with `authorization_id is None` (failed `/authorize`),
     allows retrying `settle_approved_order()` with a rotated `PayPal-Request-Id` (Minor #8 & #3c).
   - Fetches the authoritative order from `paypal_client.get_order(order_id)` by default unless
     `trusted_order_snapshot=True` is explicitly passed (Should-Fix #3i).
2. Request-ID Rotation Only After Definite 4xx Failures (Should-Fix #3c):
   - Preserves the exact same `PayPal-Request-Id` while an operation is `IN_FLIGHT` or
     `RECONCILIATION_REQUIRED`. Rotates `PayPal-Request-Id` (`-r1`, `-r2`, ...) only when
     re-running an operation whose prior attempt ended in a definite `FAILED` state.
3. True AI Classification Preservation & Sanitized LLM Context (Should-Fix #3d & #3e):
   - In `EXPLANATION_ONLY` mode, stores `verdict.classification` verbatim in `pillar2_classification`
     (or `None` if AI did not run / failed) and stores the deterministic reason separately in
     `deterministic_hold_reason` so Bulk Void (`voidable_only=True`) skips orders the AI classified
     as `LEGITIMATE_REPEAT_BUYER`.
   - Removes raw `sku` and `cart_fingerprint` from `UntrustedOrderContextForLLM`, leaving only
     `<untrusted_buyer_data>`-wrapped fields with `r"<\\s*/?\\s*untrusted_buyer_data\\b[^>]*>"` filtering.
   - Sanitizes `llm_err` before storing in `merchant_summary` or `error_reason`.
4. Complete `reconcile_stuck_holds()` Sweep & 60s Background Scheduler (Should-Fix #3f):
   - Resumes `settle_approved_order()` when an `APPROVED_PENDING_SETTLEMENT` order has not yet
     been authorized on PayPal (`status == "APPROVED"`, `eff_auth_id is None`).
   - Marks `RECONCILIATION_REQUIRED` `AUTHORIZE` operations `SUCCEEDED` when `eff_auth_id` exists.
   - Updates only `IN_FLIGHT` / `RECONCILIATION_REQUIRED` `CAPTURE` operations (never overwriting
     historical `FAILED` operations), tracks `PENDING` captures without resetting ops to `FAILED`,
     and finalizes `PENDING` captures once PayPal reports `COMPLETED`.
"""

from __future__ import annotations

from concurrent.futures import Future, ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
import copy
from dataclasses import asdict, dataclass, field
from decimal import Decimal
import hashlib
import importlib.util
import inspect
import json
import math
from pathlib import Path
import re
import sqlite3
import sys
import threading
import time
from typing import Any, Callable, Dict, FrozenSet, List, Optional, Set, Tuple


def _load_sibling_module(mod_name: str, pkg_import_name: str, subdirs: Tuple[str, ...]) -> Any:
    if pkg_import_name in sys.modules:
        sys.modules.setdefault(mod_name, sys.modules[pkg_import_name])
        return sys.modules[pkg_import_name]
    if mod_name in sys.modules:
        return sys.modules[mod_name]
    here = Path(__file__).resolve().parent
    search_dirs = [here, here.parent] + [here.parent / sd for sd in subdirs]
    for cand_dir in search_dirs:
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
    from ..config.paypal_client import (
        PayPalAPIError,
        PayPalAmbiguousNetworkError,
        PayPalAuthError,
        PayPalError,
        PayPalSandboxClient,
    )
    from ..pillar1_velocity_engine.deadlock_detector import (
        BuyRefundDeadlockDetector,
        CombinedPillar1Result,
        evaluate_approved_paypal_order,
        validate_mvp_order_shape,
    )
    from ..pillar1_velocity_engine.state_engine import (
        ZERO_DECIMAL_CURRENCIES,
        OrderRecord,
        VelocityStateEngine,
        _normalize_amount,
        validate_order_ready_for_capture,
    )
    from ..pillar1_velocity_engine.webhook_mutex import (
        OutboundRefundOperation,
        WebhookRefundMutex,
    )
except ImportError:
    _pp_mod = _load_sibling_module("paypal_client", "src.config.paypal_client", ("config",))
    _se_mod = _load_sibling_module(
        "state_engine",
        "src.pillar1_velocity_engine.state_engine",
        ("pillar1_velocity_engine",),
    )
    _dd_mod = _load_sibling_module(
        "deadlock_detector",
        "src.pillar1_velocity_engine.deadlock_detector",
        ("pillar1_velocity_engine",),
    )
    _wm_mod = _load_sibling_module(
        "webhook_mutex",
        "src.pillar1_velocity_engine.webhook_mutex",
        ("pillar1_velocity_engine",),
    )
    PayPalAPIError = _pp_mod.PayPalAPIError
    PayPalAmbiguousNetworkError = _pp_mod.PayPalAmbiguousNetworkError
    PayPalAuthError = getattr(_pp_mod, "PayPalAuthError", _pp_mod.PayPalError)
    PayPalError = _pp_mod.PayPalError
    PayPalSandboxClient = _pp_mod.PayPalSandboxClient
    BuyRefundDeadlockDetector = _dd_mod.BuyRefundDeadlockDetector
    CombinedPillar1Result = _dd_mod.CombinedPillar1Result
    evaluate_approved_paypal_order = _dd_mod.evaluate_approved_paypal_order
    validate_mvp_order_shape = _dd_mod.validate_mvp_order_shape
    ZERO_DECIMAL_CURRENCIES = _se_mod.ZERO_DECIMAL_CURRENCIES
    OrderRecord = _se_mod.OrderRecord
    VelocityStateEngine = _se_mod.VelocityStateEngine
    _normalize_amount = _se_mod._normalize_amount
    validate_order_ready_for_capture = _se_mod.validate_order_ready_for_capture
    OutboundRefundOperation = _wm_mod.OutboundRefundOperation
    WebhookRefundMutex = _wm_mod.WebhookRefundMutex


DEFAULT_LLM_TRIAGE_TIMEOUT_SECONDS = 5.0
AUTO_CAPTURE_CONFIDENCE_THRESHOLD = 0.85
PAYPAL_US_FEE_RATE = Decimal("0.0349")
PAYPAL_US_FIXED_FEE = Decimal("0.49")
MAX_UNTRUSTED_FIELD_LENGTH = 2000
MAX_MERCHANT_SUMMARY_LENGTH = 500
MAX_PAYPAL_REQUEST_ID_LENGTH = 100

# Approximate FX rates to USD so `estimated_fee_saved_usd` is always expressed in USD (Minor #6)
APPROX_USD_FX_RATES: Dict[str, Decimal] = {
    "USD": Decimal("1.00"),
    "EUR": Decimal("1.08"),
    "GBP": Decimal("1.27"),
    "CAD": Decimal("0.74"),
    "AUD": Decimal("0.66"),
    "SGD": Decimal("0.74"),
    "CHF": Decimal("1.13"),
    "JPY": Decimal("0.0067"),
    "HUF": Decimal("0.0027"),
    "TWD": Decimal("0.031"),
    "HKD": Decimal("0.128"),
    "NZD": Decimal("0.60"),
    "SEK": Decimal("0.095"),
    "NOK": Decimal("0.093"),
    "DKK": Decimal("0.145"),
    "PLN": Decimal("0.25"),
    "CZK": Decimal("0.043"),
    "ILS": Decimal("0.27"),
    "MXN": Decimal("0.058"),
    "BRL": Decimal("0.20"),
    "MYR": Decimal("0.21"),
    "PHP": Decimal("0.018"),
    "THB": Decimal("0.028"),
    "CNY": Decimal("0.14"),
    "RUB": Decimal("0.011"),
}

VALID_CLASSIFICATIONS: FrozenSet[str] = frozenset({
    "AGENT_RETRY_LOOP",
    "BUY_REFUND_DEADLOCK",
    "PROMPT_INJECTION",
    "LEGITIMATE_REPEAT_BUYER",
})

VALID_ACTIONS: FrozenSet[str] = frozenset({
    "HOLD_AUTHORIZE",
    "VOID_IMMEDIATELY",
    "GATE_MCP_TOOL",
    "ALLOW_CAPTURE",
})

# Catches `<untrusted_buyer_data>`, `</untrusted_buyer_data>`, `< /untrusted_buyer_data>`,
# and tags with attributes `<untrusted_buyer_data attr="1">` (Should-Fix #3e)
UNTRUSTED_TAG_RE = re.compile(r"<\s*/?\s*untrusted_buyer_data\b[^>]*>", re.IGNORECASE)
CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def estimate_paypal_fee_saved_usd(
    amount: str | float | int | Decimal,
    currency: str = "USD",
) -> float:
    """
    Calculates the estimated non-refundable PayPal processing fee saved in USD
    (`3.49% + $0.49` USD equivalent), converting non-USD currencies via `APPROX_USD_FX_RATES`
    so the returned value is always in USD (Minor #6).
    """
    try:
        dec = Decimal(str(amount).strip())
        if dec <= Decimal("0.00"):
            return 0.0
        curr = (currency or "USD").strip().upper()
        fx_to_usd = APPROX_USD_FX_RATES.get(curr, Decimal("1.00"))
        amount_in_usd = dec * fx_to_usd
        fee_usd = (amount_in_usd * PAYPAL_US_FEE_RATE) + PAYPAL_US_FIXED_FEE
        return float(round(fee_usd, 2))
    except Exception:
        return 0.49


def sanitize_dashboard_summary(text: str) -> str:
    """Collapses whitespace, strips control/HTML angle brackets, and caps summary length."""
    cleaned = CONTROL_CHARS_RE.sub("", text or "")
    cleaned = cleaned.replace("<", "[").replace(">", "]")
    cleaned = " ".join(cleaned.split())
    return cleaned[:MAX_MERCHANT_SUMMARY_LENGTH]


def wrap_untrusted_buyer_data(raw_text: Optional[str]) -> str:
    """
    Case-insensitively neutralizes any `<untrusted_buyer_data>` or `< /untrusted_buyer_data ...>`
    tags, strips control characters, caps length at 2,000 chars, and wraps in `<untrusted_buyer_data>`.
    """
    cleaned = CONTROL_CHARS_RE.sub("", raw_text or "")
    cleaned = UNTRUSTED_TAG_RE.sub("[REDACTED_TAG]", cleaned).strip()
    if len(cleaned) > MAX_UNTRUSTED_FIELD_LENGTH:
        cleaned = cleaned[:MAX_UNTRUSTED_FIELD_LENGTH]
    return f"<untrusted_buyer_data>{cleaned}</untrusted_buyer_data>"


@dataclass
class Pillar2TriageVerdict:
    """
    Locked 5-field schema contract shared with `src/pillar2_llm_copilot/schema.py`
    and `frontend/src/api/types.ts`.
    """

    classification: str  # "AGENT_RETRY_LOOP" | "BUY_REFUND_DEADLOCK" | "PROMPT_INJECTION" | "LEGITIMATE_REPEAT_BUYER"
    confidence: float
    recommended_action: str  # "HOLD_AUTHORIZE" | "VOID_IMMEDIATELY" | "GATE_MCP_TOOL" | "ALLOW_CAPTURE"
    estimated_fee_saved_usd: float
    merchant_summary: str


def parse_pillar2_verdict(
    raw: Any,
    fee_saved_usd: float,
    default_summary: Optional[str] = None,
) -> Pillar2TriageVerdict:
    """
    Strictly validates raw Pillar 2 output (whether a `Pillar2TriageVerdict` instance or `dict`).
    - Closes and rejects unawaited coroutines/awaitables.
    - Rejects `bool`, `None`, strings, `NaN`, `Inf`, and out-of-range `< 0.0` or `> 1.0` confidence.
    - Requires explicit valid `classification` and `recommended_action` (never silently defaults).
    - Sanitizes and caps `merchant_summary` at 500 chars (falling back to `default_summary` when
      supplied if `merchant_summary` is omitted/empty — Minor #7).
    - Ignores any AI-supplied `estimated_fee_saved_usd`, substituting the deterministic `fee_saved_usd`.
    """
    if inspect.iscoroutine(raw):
        raw.close()
        raise ValueError("coroutine_returned")
    if inspect.isawaitable(raw):
        raise ValueError("awaitable_returned")

    if isinstance(raw, Pillar2TriageVerdict):
        raw = asdict(raw)
    if not isinstance(raw, dict):
        raise ValueError("verdict_not_dict")

    conf = raw.get("confidence")
    if (
        isinstance(conf, bool)
        or not isinstance(conf, (int, float))
        or not math.isfinite(conf)
        or not (0.0 <= float(conf) <= 1.0)
    ):
        raise ValueError("confidence_invalid")

    raw_cls = raw.get("classification")
    if not isinstance(raw_cls, str) or not raw_cls.strip():
        raise ValueError("classification_invalid")
    cls = raw_cls.strip().upper()
    if cls not in VALID_CLASSIFICATIONS:
        raise ValueError("classification_invalid")

    raw_act = raw.get("recommended_action")
    if not isinstance(raw_act, str) or not raw_act.strip():
        raise ValueError("recommended_action_invalid")
    act = raw_act.strip().upper()
    if act not in VALID_ACTIONS:
        raise ValueError("recommended_action_invalid")

    raw_summary = raw.get("merchant_summary")
    if not isinstance(raw_summary, str) or not raw_summary.strip():
        if default_summary and default_summary.strip():
            raw_summary = default_summary
        else:
            raise ValueError("merchant_summary_invalid")
    summary = sanitize_dashboard_summary(raw_summary)
    if not summary:
        if default_summary and default_summary.strip():
            summary = sanitize_dashboard_summary(default_summary)
        if not summary:
            raise ValueError("merchant_summary_invalid")

    return Pillar2TriageVerdict(
        classification=cls,
        confidence=float(conf),
        recommended_action=act,
        estimated_fee_saved_usd=float(fee_saved_usd),
        merchant_summary=summary,
    )


@dataclass
class UntrustedOrderContextForLLM:
    """
    Sanitized context passed to the Pillar 2 callback with all untrusted buyer/merchant text
    wrapped in `<untrusted_buyer_data>` tags. Raw `sku` and `cart_fingerprint` are intentionally
    omitted so serializing the dataclass directly into a prompt can never leak raw untrusted text
    (Should-Fix #3e).
    """

    order_id: str
    incident_id: Optional[str]
    decision_mode: str  # "EXPLANATION_ONLY" | "DECISION_ASSISTED"
    amount: str
    currency: str
    sku_category: str
    repeat_count: int
    time_delta_seconds: Optional[float]
    is_deadlock: bool
    deadlock_reason: str
    velocity_flag_reason: str
    address_changed_vs_anchor: bool
    identity_strength: str
    untrusted_sku_xml: str
    # Kept for positional/keyword compatibility with earlier P3 callbacks. P2 deliberately omits it.
    untrusted_cart_fingerprint_xml: str = ""
    untrusted_item_name_xml: str = ""
    untrusted_description_xml: str = ""
    untrusted_note_to_payer_xml: str = ""
    anchor_order_id: Optional[str] = None
    anchor_untrusted_description_xml: Optional[str] = None

    # Additive P1 -> P3 -> P2 evidence. Defaults preserve existing positional/keyword callers.
    matched_identity_strength: str = "NONE"
    has_reliable_identity: bool = False
    used_ip_fallback: bool = False
    variant_match_mode: Optional[str] = None
    cart_fingerprint_complete: bool = False
    refund_count_in_window: int = 0
    time_since_last_refund_seconds: Optional[float] = None
    deadlock_match_confidence: str = "NONE"
    has_prompt_injection_signal: Optional[bool] = None
    has_retry_marker_signal: Optional[bool] = None
    cart_relationship: str = "UNKNOWN"
    same_amount_as_anchor: Optional[bool] = None
    same_currency_as_anchor: Optional[bool] = None
    anchor_cart_fingerprint_complete: Optional[bool] = None
    p1_auto_capture_eligible: bool = False
    anchor_untrusted_sku_xml: str = ""
    anchor_untrusted_item_name_xml: str = ""
    anchor_untrusted_note_to_payer_xml: str = ""


@dataclass
class PaymentOperationRecord:
    operation_id: str
    operation_type: str  # "AUTHORIZE" | "CAPTURE" | "VOID"
    order_id: str
    authorization_id: Optional[str]
    paypal_request_id: str
    payload_json: str
    status: str  # "IN_FLIGHT" | "SUCCEEDED" | "FAILED" | "RECONCILIATION_REQUIRED"
    updated_at: float
    capture_id: Optional[str] = None
    error_detail: Optional[str] = None
    retry_count: int = 0
    provider_status: Optional[str] = None


@dataclass
class SettlementOutcome:
    order_id: str
    authorization_id: Optional[str]
    capture_id: Optional[str]
    final_status: str  # "CAPTURED" | "PARTIALLY_CAPTURED" | "AUTHORIZED_HOLD" | "VOIDED" | "NEEDS_ATTENTION"
    decision_mode: str  # ordinary modes plus explicit recovery/hold labels used after crash recovery
    capture_allowed: bool
    deterministic_override_applied: bool
    incident_id: Optional[str]
    pillar1_result: Optional[CombinedPillar1Result]
    pillar2_verdict: Optional[Pillar2TriageVerdict]
    merchant_summary: str
    estimated_fee_saved_usd: float
    authorize_request_id: Optional[str] = None
    capture_request_id: Optional[str] = None
    capture_operation_id: Optional[str] = None
    reconciliation_required: bool = False
    error_reason: Optional[str] = None


@dataclass
class VoidOutcome:
    order_id: str
    authorization_id: str
    status: str  # "VOIDED"
    incident_id: Optional[str]
    estimated_fee_saved_usd: float
    merchant_actor: str
    reason: str


@dataclass
class BulkVoidOutcome:
    incident_id: str
    voided_orders: List[VoidOutcome] = field(default_factory=list)
    skipped_order_ids: List[str] = field(default_factory=list)
    failed_orders: Dict[str, str] = field(default_factory=dict)
    total_estimated_fee_saved_usd: float = 0.0


@dataclass
class ReconciliationSweepReport:
    checked_order_ids: List[str] = field(default_factory=list)
    resumed_settlement_order_ids: List[str] = field(default_factory=list)
    resolved_captured_order_ids: List[str] = field(default_factory=list)
    resolved_voided_order_ids: List[str] = field(default_factory=list)
    pending_capture_order_ids: List[str] = field(default_factory=list)
    escalated_needs_attention_order_ids: List[str] = field(default_factory=list)
    errors_by_order_id: Dict[str, str] = field(default_factory=dict)


@dataclass
class RefundExecutionOutcome:
    allowed: bool
    status: str  # includes NOT_SUBMITTED for an OAuth failure proven to occur before the refund POST
    message: str
    operation: Optional[OutboundRefundOperation] = None
    paypal_refund_id: Optional[str] = None


LLMTriageCallback = Callable[[UntrustedOrderContextForLLM], Pillar2TriageVerdict | Dict[str, Any]]


def _p2_cart_sku_set(fingerprint: Optional[str]) -> set[str]:
    """Read only the SKU set from an internal fingerprint; never expose the fingerprint to P2."""
    if not fingerprint:
        return set()
    found: set[str] = set()
    for part in fingerprint.split("|"):
        segment = part.strip()
        if not segment:
            continue
        sku_part = segment.rsplit(":", 1)[0].strip().upper()
        if sku_part:
            found.add(sku_part)
    return found


def _p2_same_amount(current_amount: Any, anchor: Any) -> Optional[bool]:
    if anchor is None:
        return None
    candidates = [getattr(anchor, "amount", None), getattr(anchor, "original_order_amount", None)]
    normalized = []
    for value in candidates:
        if value is None:
            continue
        try:
            normalized.append(Decimal(str(value).strip()))
        except Exception:
            continue
    if not normalized:
        return None
    try:
        current = Decimal(str(current_amount).strip())
    except Exception:
        return None
    return any(current == candidate for candidate in normalized)


def _p2_cart_relationship(order_rec: OrderRecord, anchor: Any, vel: Any, dl: Any) -> str:
    """Derive a compact relationship enum locally without sending raw fingerprints to the model."""
    if anchor is None:
        return "UNKNOWN"

    variant_mode = (getattr(dl, "variant_match_mode", None) or getattr(vel, "variant_match_mode", None) or "").upper()
    if variant_mode in {"EXPLICIT_FAMILY", "EXPLICIT_VARIANT_FAMILY"}:
        return "EXPLICIT_VARIANT_FAMILY"
    if variant_mode in {"HEURISTIC_STEM", "HEURISTIC_VARIANT_STEM"}:
        return "HEURISTIC_VARIANT_STEM"

    if getattr(dl, "is_deadlock", False):
        if getattr(dl, "match_confidence", "") == "CONFIRMED_SAME_CART_DEADLOCK":
            return "EXACT_CART"
        return "SAME_AMOUNT_UNVERIFIED_CART"

    current_fp = getattr(order_rec, "cart_fingerprint", None)
    anchor_fp = getattr(anchor, "cart_fingerprint", None)
    current_complete = bool(getattr(order_rec, "cart_fingerprint_complete", False))
    anchor_complete = bool(getattr(anchor, "cart_fingerprint_complete", False))
    if current_complete and anchor_complete and current_fp and anchor_fp and current_fp == anchor_fp:
        return "EXACT_CART"

    current_skus = _p2_cart_sku_set(current_fp)
    anchor_skus = _p2_cart_sku_set(anchor_fp)
    if current_skus and anchor_skus and current_skus == anchor_skus:
        return "SAME_SKU_SET_MUTATED_CART"

    if getattr(vel, "flag_reason", "") == "DIFFERENT_PRODUCT_SKU_FAST_PATH":
        return "DIFFERENT_PRODUCT"

    same_currency = str(getattr(order_rec, "currency", "")).upper() == str(getattr(anchor, "currency", "")).upper()
    same_amount = _p2_same_amount(getattr(order_rec, "amount", None), anchor)
    if same_currency and same_amount is True:
        return "SAME_AMOUNT_UNVERIFIED_CART"
    return "UNKNOWN"


class SettlementClient:
    """
    Pillar 3 Money-Movement & Hold Lifecycle Orchestrator.
    Coordinates Pillar 1 deterministic evaluation, PayPal `/authorize` holds, conditional
    Pillar 2 (`EXPLANATION_ONLY` vs `DECISION_ASSISTED`) triage, and one verified full `/capture`
    per authorization. Includes guarded refund/void reconciliation. Manual/partial capture is disabled.
    """

    def __init__(
        self,
        paypal_client: PayPalSandboxClient,
        state_engine: VelocityStateEngine,
        deadlock_detector: BuyRefundDeadlockDetector,
        webhook_mutex: Optional[WebhookRefundMutex] = None,
        llm_triage_callback: Optional[LLMTriageCallback] = None,
        llm_timeout_seconds: float = DEFAULT_LLM_TRIAGE_TIMEOUT_SECONDS,
        db_path: Optional[str] = None,
    ) -> None:
        self.paypal_client = paypal_client
        self.state_engine = state_engine
        self.deadlock_detector = deadlock_detector
        self.webhook_mutex = webhook_mutex
        self.llm_triage_callback = llm_triage_callback
        self.llm_timeout_seconds = llm_timeout_seconds
        self.db_path = db_path or state_engine.db_path
        self._lock = threading.RLock()
        self._order_locks: Dict[str, threading.RLock] = {}
        self._operations: Dict[str, PaymentOperationRecord] = {}
        self._sweep_stop_event: Optional[threading.Event] = None
        self._sweep_thread: Optional[threading.Thread] = None

        if self.db_path:
            self._init_db()
            self._load_persisted_operations()

    def _get_order_lock(self, order_id: str) -> threading.RLock:
        clean_id = (order_id or "").strip()
        with self._lock:
            lock = self._order_locks.get(clean_id)
            if lock is None:
                lock = threading.RLock()
                self._order_locks[clean_id] = lock
            return lock

    def _init_db(self) -> None:
        if not self.db_path:
            return
        with sqlite3.connect(self.db_path, timeout=10.0) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS settlement_operations_store (
                    operation_id TEXT PRIMARY KEY,
                    record_json TEXT NOT NULL,
                    updated_at REAL NOT NULL
                )
                """
            )
            conn.commit()

    def _persist_operation_locked(self, op: PaymentOperationRecord) -> None:
        if not self.db_path:
            return
        with sqlite3.connect(self.db_path, timeout=10.0) as conn:
            conn.execute(
                """
                INSERT INTO settlement_operations_store (operation_id, record_json, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(operation_id) DO UPDATE SET
                    record_json = excluded.record_json,
                    updated_at = excluded.updated_at
                """,
                (op.operation_id, json.dumps(asdict(op)), op.updated_at),
            )
            conn.commit()

    def _load_persisted_operations(self) -> None:
        if not self.db_path:
            return
        with self._lock:
            with sqlite3.connect(self.db_path, timeout=10.0) as conn:
                rows = conn.execute(
                    "SELECT record_json FROM settlement_operations_store ORDER BY updated_at ASC"
                ).fetchall()
            for (rec_json,) in rows:
                data = json.loads(rec_json)
                # Backward-compatible load for rows written before provider_status was persisted.
                data.setdefault("provider_status", None)
                op = PaymentOperationRecord(**data)
                self._operations[op.operation_id] = op

    def get_operation_record(self, operation_id: str) -> Optional[PaymentOperationRecord]:
        with self._lock:
            op = self._operations.get(operation_id.strip())
            return copy.deepcopy(op) if op is not None else None

    def _get_succeeded_capture_ids_for_auth(self, authorization_id: str) -> Set[str]:
        with self._lock:
            return {
                op.capture_id
                for op in self._operations.values()
                if op.authorization_id == authorization_id
                and op.status == "SUCCEEDED"
                and op.capture_id
            }

    @staticmethod
    def _rotate_request_id(base_request_id: str, retry_count: int) -> str:
        if retry_count <= 0:
            return base_request_id[:MAX_PAYPAL_REQUEST_ID_LENGTH]
        suffix = f"-r{retry_count}"
        head = base_request_id[: max(1, MAX_PAYPAL_REQUEST_ID_LENGTH - len(suffix))]
        return f"{head}{suffix}"

    def _get_or_create_operation(
        self,
        *,
        operation_id: str,
        operation_type: str,
        order_id: str,
        authorization_id: Optional[str],
        default_paypal_request_id: str,
        payload: Dict[str, Any],
        now: float,
    ) -> PaymentOperationRecord:
        """
        Retrieves or creates a persisted `PaymentOperationRecord`.
        Should-Fix #3c:
        - If `existing.status` is `IN_FLIGHT`, `RECONCILIATION_REQUIRED`, or `SUCCEEDED`,
          keeps `existing.paypal_request_id` untouched so ambiguous network retries deduplicate.
        - If `existing.status == "FAILED"` (a prior definite 4xx rejection or reconciled non-execution),
          increments `retry_count` and rotates `paypal_request_id` (`{base}-r{retry_count}`) so
          PayPal does not replay a cached 4xx failure.
        """
        canonical_payload = json.dumps(payload, sort_keys=True)
        with self._lock:
            existing = self._operations.get(operation_id)
            if existing is not None:
                if existing.payload_json != canonical_payload:
                    raise ValueError(
                        f"Conflicting payload for existing payment operation_id '{operation_id}': "
                        f"stored={existing.payload_json} vs incoming={canonical_payload}."
                    )
                if existing.status == "FAILED":
                    existing.retry_count += 1
                    existing.paypal_request_id = self._rotate_request_id(
                        default_paypal_request_id,
                        existing.retry_count,
                    )
                    existing.status = "IN_FLIGHT"
                    existing.error_detail = None
                    existing.updated_at = now
                    self._persist_operation_locked(existing)
                return copy.deepcopy(existing)

            op = PaymentOperationRecord(
                operation_id=operation_id,
                operation_type=operation_type,
                order_id=order_id,
                authorization_id=authorization_id,
                paypal_request_id=default_paypal_request_id[:MAX_PAYPAL_REQUEST_ID_LENGTH],
                payload_json=canonical_payload,
                status="IN_FLIGHT",
                updated_at=now,
                retry_count=0,
            )
            self._operations[operation_id] = op
            self._persist_operation_locked(op)
            return copy.deepcopy(op)

    def _update_operation_status(
        self,
        operation_id: str,
        status: str,
        *,
        authorization_id: Optional[str] = None,
        capture_id: Optional[str] = None,
        error_detail: Optional[str] = None,
        provider_status: Optional[str] = None,
        now: Optional[float] = None,
    ) -> PaymentOperationRecord:
        ts = now if now is not None else time.time()
        with self._lock:
            op = self._operations[operation_id]
            op.status = status
            op.updated_at = ts
            if authorization_id:
                op.authorization_id = authorization_id
            if capture_id:
                op.capture_id = capture_id
            if error_detail is not None:
                op.error_detail = error_detail
            if provider_status is not None:
                op.provider_status = provider_status.strip().upper() or None
            self._persist_operation_locked(op)
            return copy.deepcopy(op)

    @staticmethod
    def _extract_authorization_from_order_response(
        order_or_auth_resp: Dict[str, Any],
    ) -> Tuple[Optional[str], Optional[str]]:
        if not isinstance(order_or_auth_resp, dict):
            return None, None
        authorizations: List[Dict[str, Any]] = []
        for purchase_unit in order_or_auth_resp.get("purchase_units") or []:
            if not isinstance(purchase_unit, dict):
                continue
            payments = purchase_unit.get("payments") or {}
            if not isinstance(payments, dict):
                continue
            for authorization in payments.get("authorizations") or []:
                if isinstance(authorization, dict):
                    authorizations.append(authorization)
        if len(authorizations) > 1:
            raise ValueError(
                "MVP supports exactly one authorization per order; refusing to select an arbitrary authorization."
            )
        if not authorizations:
            return None, None
        auth_id = str(authorizations[0].get("id") or "").strip() or None
        auth_status = str(authorizations[0].get("status") or "").strip().upper() or None
        return auth_id, auth_status

    @staticmethod
    def _extract_capture_objects_from_order_response(
        order_resp: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        pu_list = order_resp.get("purchase_units") or []
        if pu_list and isinstance(pu_list[0], dict):
            payments = pu_list[0].get("payments") or {}
            for cap in payments.get("captures") or []:
                if isinstance(cap, dict) and cap.get("id"):
                    out.append(cap)
        return out

    def _find_matching_unclaimed_capture(
        self,
        *,
        order_id: str,
        authorization_id: str,
        remote_order: Dict[str, Any],
        expected_amount: str,
        expected_currency: str,
        expected_invoice_id: Optional[str] = None,
    ) -> Optional[Tuple[str, str]]:
        order_rec = self.state_engine.get_order(order_id)
        if order_rec is None or order_rec.authorization_id != authorization_id:
            return None

        claimed_ids: Set[str] = set()
        if order_rec.capture_id:
            claimed_ids.add(order_rec.capture_id)
        claimed_ids.update(order_rec.capture_ids or [])
        claimed_ids.update(self._get_succeeded_capture_ids_for_auth(authorization_id))

        expected_amt = _normalize_amount(expected_amount, expected_currency)
        expected_curr = expected_currency.strip().upper()
        matches: List[Tuple[str, str]] = []

        for cap in self._extract_capture_objects_from_order_response(remote_order):
            capture_id = str(cap.get("id") or "").strip()
            if not capture_id or capture_id in claimed_ids:
                continue
            status = str(cap.get("status") or "").strip().upper()
            if status not in ("COMPLETED", "PENDING"):
                continue

            amount_obj = cap.get("amount")
            if not isinstance(amount_obj, dict) or amount_obj.get("value") is None or not amount_obj.get("currency_code"):
                continue
            remote_currency = str(amount_obj.get("currency_code") or "").strip().upper()
            if remote_currency != expected_curr:
                continue
            try:
                remote_amount = _normalize_amount(amount_obj.get("value"), remote_currency)
            except (TypeError, ValueError):
                continue
            if remote_amount != expected_amt:
                continue

            if expected_invoice_id:
                remote_invoice = str(cap.get("invoice_id") or "").strip()
                if not remote_invoice or remote_invoice != expected_invoice_id.strip():
                    continue

            matches.append((capture_id, status))

        return matches[0] if len(matches) == 1 else None

    def _authorize_with_reconciliation(
        self,
        order_id: str,
        now: float,
        paypal_order: Optional[Dict[str, Any]] = None,
    ) -> Tuple[Optional[str], Optional[str], str, bool, Optional[str]]:
        operation_id = f"authorize:{order_id}"
        default_request_id = f"auth-{order_id}"
        op = self._get_or_create_operation(
            operation_id=operation_id,
            operation_type="AUTHORIZE",
            order_id=order_id,
            authorization_id=None,
            default_paypal_request_id=default_request_id,
            payload={},
            now=now,
        )

        # Reuse a single authorization already attached to the authoritative PayPal
        # order (e.g. a crash after /authorize but before the local ledger commit).
        try:
            remote_order = copy.deepcopy(paypal_order) if paypal_order is not None else self.paypal_client.get_order(order_id)
            remote_auth_id, _remote_auth_status = self._extract_authorization_from_order_response(remote_order)
        except ValueError as exc:
            message = sanitize_dashboard_summary(f"MULTIPLE_OR_INVALID_REMOTE_AUTHORIZATIONS:{exc}")
            self._update_operation_status(
                operation_id, "RECONCILIATION_REQUIRED", error_detail=message, now=now,
            )
            return None, None, op.paypal_request_id, True, message
        except PayPalError as exc:
            message = sanitize_dashboard_summary(f"AUTHORIZE_ORDER_LOOKUP_FAILED:{exc}")
            self._update_operation_status(
                operation_id, "RECONCILIATION_REQUIRED", error_detail=message, now=now,
            )
            return None, None, op.paypal_request_id, True, message

        if remote_auth_id:
            if op.authorization_id and op.authorization_id != remote_auth_id:
                message = "REMOTE_AUTHORIZATION_ID_CONFLICTS_WITH_PERSISTED_OPERATION"
                self._update_operation_status(operation_id, "RECONCILIATION_REQUIRED", error_detail=message, now=now)
                return None, None, op.paypal_request_id, True, message
            try:
                live_auth = self.paypal_client.get_authorization(remote_auth_id)
                live_id = str(live_auth.get("id") or "").strip()
                live_status = str(live_auth.get("status") or "").strip().upper() or None
            except PayPalError as exc:
                message = sanitize_dashboard_summary(f"EXISTING_AUTHORIZATION_LOOKUP_FAILED:{exc}")
                self._update_operation_status(operation_id, "RECONCILIATION_REQUIRED", error_detail=message, now=now)
                return remote_auth_id, None, op.paypal_request_id, True, message
            if live_id != remote_auth_id or not live_status:
                message = "EXISTING_AUTHORIZATION_RESOURCE_ID_OR_STATUS_MISSING"
                self._update_operation_status(operation_id, "RECONCILIATION_REQUIRED", error_detail=message, now=now)
                return remote_auth_id, None, op.paypal_request_id, True, message
            self._update_operation_status(
                operation_id, "SUCCEEDED", authorization_id=remote_auth_id,
                provider_status=live_status, now=now,
            )
            return remote_auth_id, live_status, op.paypal_request_id, False, None

        # A prior successful operation can be recovered from its persisted auth ID even
        # if the order response no longer embeds the authorization object.
        if op.status == "SUCCEEDED" and op.authorization_id:
            try:
                live_auth = self.paypal_client.get_authorization(op.authorization_id)
                live_id = str(live_auth.get("id") or "").strip()
                live_status = str(live_auth.get("status") or "").strip().upper() or None
                if live_id != op.authorization_id or not live_status:
                    return op.authorization_id, None, op.paypal_request_id, True, "CACHED_AUTHORIZATION_LOOKUP_INCOMPLETE"
                return op.authorization_id, live_status, op.paypal_request_id, False, None
            except PayPalError as exc:
                return op.authorization_id, None, op.paypal_request_id, True, sanitize_dashboard_summary(f"CACHED_AUTHORIZATION_LOOKUP_FAILED:{exc}")

        if op.status == "RECONCILIATION_REQUIRED":
            return None, None, op.paypal_request_id, True, op.error_detail or "AUTHORIZE_RECONCILIATION_REQUIRED"

        for attempt in range(2):
            try:
                response = self.paypal_client.authorize_order(
                    order_id=order_id,
                    paypal_request_id=op.paypal_request_id,
                    payload={},
                )
                try:
                    auth_id, auth_status = self._extract_authorization_from_order_response(response)
                except ValueError as exc:
                    message = sanitize_dashboard_summary(f"MULTIPLE_AUTHORIZATIONS_IN_AUTHORIZE_RESPONSE:{exc}")
                    self._update_operation_status(operation_id, "RECONCILIATION_REQUIRED", error_detail=message, now=now)
                    return None, None, op.paypal_request_id, True, message
                if not auth_id:
                    # A nominally successful POST with an incomplete body is not a definite
                    # failure. Re-read the authoritative order once to recover the created auth.
                    try:
                        remote_after = self.paypal_client.get_order(order_id)
                        recovered_id, recovered_status = self._extract_authorization_from_order_response(remote_after)
                    except (PayPalError, ValueError):
                        recovered_id, recovered_status = None, None
                    if recovered_id:
                        try:
                            live_auth = self.paypal_client.get_authorization(recovered_id)
                            live_id = str(live_auth.get("id") or "").strip()
                            recovered_status = str(live_auth.get("status") or "").strip().upper() or None
                            if live_id != recovered_id or not recovered_status:
                                recovered_status = None
                        except PayPalError:
                            recovered_status = None
                        if recovered_status:
                            self._update_operation_status(
                                operation_id, "SUCCEEDED", authorization_id=recovered_id,
                                provider_status=recovered_status, now=now,
                            )
                            return recovered_id, recovered_status, op.paypal_request_id, False, None
                    message = "PayPal authorize response omitted the authorization ID and the order GET did not recover a verified one."
                    self._update_operation_status(operation_id, "RECONCILIATION_REQUIRED", error_detail=message, now=now)
                    return None, None, op.paypal_request_id, True, message

                self._update_operation_status(
                    operation_id, "SUCCEEDED", authorization_id=auth_id,
                    provider_status=auth_status, now=now,
                )
                return auth_id, auth_status, op.paypal_request_id, False, None

            except PayPalAuthError as exc:
                message = sanitize_dashboard_summary(f"AUTHORIZE_OAUTH_ERROR:{exc.error_name or exc}")
                self._update_operation_status(operation_id, "FAILED", error_detail=message, now=now)
                return None, None, op.paypal_request_id, False, message

            except PayPalAmbiguousNetworkError as exc:
                try:
                    remote_after = self.paypal_client.get_order(order_id)
                    remote_auth_id, _ = self._extract_authorization_from_order_response(remote_after)
                    if remote_auth_id:
                        live_auth = self.paypal_client.get_authorization(remote_auth_id)
                        live_id = str(live_auth.get("id") or "").strip()
                        live_status = str(live_auth.get("status") or "").strip().upper() or None
                        if live_id == remote_auth_id and live_status:
                            self._update_operation_status(
                                operation_id, "SUCCEEDED", authorization_id=remote_auth_id,
                                provider_status=live_status, now=now,
                            )
                            return remote_auth_id, live_status, op.paypal_request_id, False, None
                except (PayPalError, ValueError):
                    pass
                if attempt == 0:
                    continue
                message = sanitize_dashboard_summary(f"AUTHORIZE_RECONCILIATION_REQUIRED:{exc}")
                self._update_operation_status(operation_id, "RECONCILIATION_REQUIRED", error_detail=message, now=now)
                return None, None, op.paypal_request_id, True, message

            except PayPalAPIError as exc:
                message = sanitize_dashboard_summary(
                    f"AUTHORIZE_API_ERROR:{exc.issue or exc.error_name or exc.status_code}"
                )
                self._update_operation_status(operation_id, "FAILED", error_detail=message, now=now)
                return None, None, op.paypal_request_id, False, message

        return None, None, op.paypal_request_id, True, "AUTHORIZE_EXHAUSTED_RETRIES"

    def _build_capture_operation_ids(
        self,
        authorization_id: str,
        operation_key: Optional[str],
        payload: Dict[str, Any],
    ) -> Tuple[str, str]:
        if operation_key and operation_key.strip():
            clean_key = operation_key.strip()
        elif not payload:
            clean_key = "full"
        else:
            digest = hashlib.sha256(
                json.dumps(payload, sort_keys=True).encode("utf-8")
            ).hexdigest()[:12]
            clean_key = f"part-{digest}"

        logical_op_id = f"capture:{authorization_id}:{clean_key}"
        if clean_key == "full":
            pp_req_id = f"capture-{authorization_id}"
        else:
            req_hash = hashlib.sha256(logical_op_id.encode("utf-8")).hexdigest()[:20]
            pp_req_id = f"capture-{authorization_id}-{req_hash}"
        return logical_op_id, pp_req_id[:MAX_PAYPAL_REQUEST_ID_LENGTH]

    def _execute_capture_with_reconciliation(
        self,
        *,
        order_id: str,
        authorization_id: str,
        paypal_auth_status: str,
        capture_mode: str,
        decision_allows_capture: bool,
        merchant_actor: Optional[str] = None,
        override_reason: Optional[str] = None,
        capture_payload: Optional[Dict[str, Any]] = None,
        operation_key: Optional[str] = None,
        final_capture: bool = True,
        now: Optional[float] = None,
    ) -> Tuple[Optional[str], str, str, bool, Optional[str], str]:
        """Perform the MVP's single full capture only after a fresh provider-side auth check."""
        current_time = now if now is not None else time.time()
        payload = copy.deepcopy(capture_payload) if capture_payload else {}
        logical_op_id, default_request_id = self._build_capture_operation_ids(
            authorization_id=authorization_id,
            operation_key=operation_key,
            payload=payload,
        )

        order_rec = self.state_engine.get_order(order_id)
        if order_rec is None:
            raise ValueError(f"Unknown order '{order_id}' cannot be captured.")
        if not order_rec.authorization_id or order_rec.authorization_id != authorization_id:
            raise ValueError(
                f"Authorization mismatch for order '{order_id}': ledger='{order_rec.authorization_id}', "
                f"requested='{authorization_id}'. Refusing to send capture."
            )

        if operation_key not in (None, "", "full"):
            raise ValueError("MVP supports exactly one logical full-capture operation per authorization.")
        if final_capture is not True:
            raise ValueError("PARTIAL_CAPTURES_DISABLED_IN_MVP: final_capture must be True.")
        if set(payload) - {"amount", "invoice_id", "final_capture"}:
            raise ValueError("Unsupported capture payload fields in the one-full-capture MVP.")
        if payload.get("final_capture") is False:
            raise ValueError("PARTIAL_CAPTURES_DISABLED_IN_MVP: final_capture must be True.")
        payload["final_capture"] = True

        expected_amount = _normalize_amount(order_rec.amount, order_rec.currency)
        expected_currency = order_rec.currency.strip().upper()
        amount_obj = payload.get("amount")
        if amount_obj is not None:
            if not isinstance(amount_obj, dict):
                raise ValueError("capture_payload.amount must be an object in the MVP.")
            incoming_currency = str(amount_obj.get("currency_code") or "").strip().upper()
            if incoming_currency != expected_currency:
                raise ValueError("Capture amount currency must exactly match the order currency.")
            incoming_amount = _normalize_amount(amount_obj.get("value"), incoming_currency)
            if incoming_amount != expected_amount:
                raise ValueError("PARTIAL_CAPTURES_DISABLED_IN_MVP: capture amount must equal the full order amount.")
            amount_obj["currency_code"] = expected_currency
            amount_obj["value"] = expected_amount

        existing_op = self.get_operation_record(logical_op_id)
        if existing_op is not None:
            if existing_op.status == "FAILED" and not existing_op.capture_id:
                if order_rec.resolution_status == "NEEDS_ATTENTION":
                    transitioned = self.state_engine.update_order_resolution(
                        order_id, "AUTHORIZED_HOLD", now=current_time,
                    )
                    if not transitioned:
                        return None, logical_op_id, existing_op.paypal_request_id, True, "FAILED_CAPTURE_RETRY_STATE_TRANSITION_REFUSED", "UNKNOWN"
                    order_rec = self.state_engine.get_order(order_id)
                    if order_rec is None:
                        return None, logical_op_id, existing_op.paypal_request_id, True, "ORDER_DISAPPEARED_BEFORE_CAPTURE_RETRY", "UNKNOWN"
            canonical_payload_json = json.dumps(payload, sort_keys=True)
            if existing_op.payload_json != canonical_payload_json:
                # Older full-capture operations were persisted before final_capture=True
                # was made explicit. Treat only that exact additive difference as compatible.
                try:
                    old_payload = json.loads(existing_op.payload_json or "{}")
                except (TypeError, json.JSONDecodeError) as exc:
                    raise ValueError(
                        f"Stored capture payload for operation '{logical_op_id}' is not valid JSON."
                    ) from exc
                old_payload.setdefault("final_capture", True)
                if old_payload != payload:
                    raise ValueError(f"Conflicting capture payload for operation '{logical_op_id}'.")

                if existing_op.status == "FAILED":
                    # A definite FAILED result proves the previous request did not execute.
                    # Persist the canonical full-capture body before _get_or_create_operation
                    # rotates the request ID and permits a fresh attempt.
                    with self._lock:
                        stored = self._operations.get(logical_op_id)
                        if stored is None or stored.status != "FAILED":
                            return None, logical_op_id, existing_op.paypal_request_id, True, \
                                "CAPTURE_OPERATION_CHANGED_DURING_LEGACY_PAYLOAD_MIGRATION", "UNKNOWN"
                        candidate = copy.deepcopy(stored)
                        candidate.payload_json = canonical_payload_json
                        candidate.updated_at = current_time
                        self._persist_operation_locked(candidate)
                        self._operations[logical_op_id] = candidate
                        existing_op = copy.deepcopy(candidate)
                elif existing_op.status == "IN_FLIGHT":
                    # The prior process may have sent the old-body request before crashing.
                    # Do not replay with a changed body or reuse its idempotency key blindly.
                    message = "LEGACY_IN_FLIGHT_CAPTURE_PAYLOAD_REQUIRES_RECONCILIATION"
                    self._update_operation_status(
                        logical_op_id, "RECONCILIATION_REQUIRED", error_detail=message, now=current_time,
                    )
                    self.state_engine.update_order_resolution(order_id, "NEEDS_ATTENTION", now=current_time)
                    return None, logical_op_id, existing_op.paypal_request_id, True, message, "UNKNOWN"
            if existing_op.status == "SUCCEEDED" and existing_op.capture_id:
                return (
                    existing_op.capture_id,
                    existing_op.operation_id,
                    existing_op.paypal_request_id,
                    False,
                    None,
                    existing_op.provider_status or "UNKNOWN",
                )
            if existing_op.status == "RECONCILIATION_REQUIRED":
                return (
                    None,
                    existing_op.operation_id,
                    existing_op.paypal_request_id,
                    True,
                    existing_op.error_detail or "PRIOR_CAPTURE_RECONCILIATION_REQUIRED",
                    existing_op.provider_status or "UNKNOWN",
                )

        # Always query PayPal here. A status copied from the authorize response or cache is stale evidence.
        try:
            live_auth = self.paypal_client.get_authorization(authorization_id)
        except PayPalError as exc:
            message = sanitize_dashboard_summary(f"LIVE_AUTHORIZATION_LOOKUP_FAILED:{exc}")
            self.state_engine.update_order_resolution(order_id, "NEEDS_ATTENTION", now=current_time)
            return None, logical_op_id, default_request_id, True, message, "UNKNOWN"
        live_auth_id = str(live_auth.get("id") or "").strip()
        live_auth_status = str(live_auth.get("status") or "").strip().upper()
        if live_auth_id != authorization_id or live_auth_status != "CREATED":
            message = (
                "LIVE_AUTHORIZATION_MISMATCH_OR_NOT_CAPTURABLE: "
                f"id={live_auth_id or 'MISSING'}, status={live_auth_status or 'MISSING'}"
            )
            self.state_engine.update_order_resolution(order_id, "NEEDS_ATTENTION", now=current_time)
            return None, logical_op_id, default_request_id, False, message, live_auth_status or "UNKNOWN"

        ready, reason = validate_order_ready_for_capture(
            order=order_rec,
            decision_allows_capture=decision_allows_capture,
            capture_mode=capture_mode,
            paypal_auth_status=live_auth_status,
            merchant_actor=merchant_actor,
            override_reason=override_reason,
            paypal_auth_status_verified=True,
            allow_partial_captures=False,
        )
        if not ready:
            if (capture_mode or "AUTO").strip().upper() == "MANUAL_MERCHANT_OVERRIDE":
                raise PermissionError(f"Manual capture blocked by deterministic validator: {reason}")
            self.state_engine.update_order_resolution(order_id, "NEEDS_ATTENTION", now=current_time)
            return None, logical_op_id, default_request_id, False, f"AUTO_CAPTURE_GATE_BLOCKED:{reason}", "BLOCKED"

        op = self._get_or_create_operation(
            operation_id=logical_op_id,
            operation_type="CAPTURE",
            order_id=order_id,
            authorization_id=authorization_id,
            default_paypal_request_id=default_request_id,
            payload=payload,
            now=current_time,
        )
        if not self.state_engine.update_order_resolution(order_id, "AUTO_CAPTURING", now=current_time):
            self._update_operation_status(
                logical_op_id,
                "RECONCILIATION_REQUIRED",
                error_detail="LOCAL_ORDER_STATE_TRANSITION_REFUSED_BEFORE_CAPTURE",
                now=current_time,
            )
            return None, op.operation_id, op.paypal_request_id, True, "LOCAL_ORDER_STATE_TRANSITION_REFUSED_BEFORE_CAPTURE", "UNKNOWN"

        for attempt in range(2):
            try:
                response = self.paypal_client.capture_authorization(
                    authorization_id=authorization_id,
                    paypal_request_id=op.paypal_request_id,
                    payload=payload,
                )
                capture_id = str(response.get("id") or "").strip() or None
                capture_status = str(response.get("status") or "").strip().upper() or None
                if not capture_id or capture_status not in ("COMPLETED", "PENDING"):
                    recovered = None
                    try:
                        remote_order = self.paypal_client.get_order(order_id)
                        recovered = self._find_matching_unclaimed_capture(
                            order_id=order_id, authorization_id=authorization_id,
                            remote_order=remote_order, expected_amount=expected_amount,
                            expected_currency=expected_currency,
                            expected_invoice_id=str(payload.get("invoice_id") or "").strip() or None,
                        )
                    except (PayPalError, ValueError):
                        recovered = None
                    if recovered:
                        capture_id, capture_status = recovered
                        self._update_operation_status(
                            logical_op_id, "SUCCEEDED", capture_id=capture_id,
                            provider_status=capture_status, now=current_time,
                        )
                        self._register_completed_capture(
                            order_id=order_id, authorization_id=authorization_id,
                            capture_id=capture_id,
                            resolution_status="CAPTURED" if capture_status == "COMPLETED" else "NEEDS_ATTENTION",
                            now=current_time,
                        )
                        if capture_status == "PENDING":
                            return capture_id, op.operation_id, op.paypal_request_id, False, "CAPTURE_STATUS_PENDING", "PENDING"
                        return capture_id, op.operation_id, op.paypal_request_id, False, None, "COMPLETED"
                    message = "Capture response omitted a usable capture ID or explicit supported status; provider outcome remains ambiguous."
                    self._update_operation_status(
                        logical_op_id, "RECONCILIATION_REQUIRED",
                        capture_id=capture_id, provider_status=capture_status,
                        error_detail=message, now=current_time,
                    )
                    self.state_engine.update_order_resolution(order_id, "NEEDS_ATTENTION", now=current_time)
                    return capture_id, op.operation_id, op.paypal_request_id, True, message, capture_status or "UNKNOWN"

                self._update_operation_status(
                    logical_op_id,
                    "SUCCEEDED",
                    capture_id=capture_id,
                    provider_status=capture_status,
                    now=current_time,
                )
                target_status = "CAPTURED" if capture_status == "COMPLETED" else "NEEDS_ATTENTION"
                try:
                    self._register_completed_capture(
                        order_id=order_id,
                        authorization_id=authorization_id,
                        capture_id=capture_id,
                        resolution_status=target_status,
                        now=current_time,
                    )
                except Exception as exc:
                    self._update_operation_status(
                        logical_op_id,
                        "RECONCILIATION_REQUIRED",
                        capture_id=capture_id,
                        provider_status=capture_status,
                        error_detail=sanitize_dashboard_summary(f"CAPTURE_LEDGER_REGISTRATION_FAILED:{exc}"),
                        now=current_time,
                    )
                    self.state_engine.update_order_resolution(order_id, "NEEDS_ATTENTION", now=current_time)
                    return capture_id, op.operation_id, op.paypal_request_id, True, "CAPTURE_LEDGER_REGISTRATION_FAILED", capture_status
                if capture_status == "PENDING":
                    return capture_id, op.operation_id, op.paypal_request_id, False, "CAPTURE_STATUS_PENDING", "PENDING"
                return capture_id, op.operation_id, op.paypal_request_id, False, None, "COMPLETED"

            except PayPalAuthError as exc:
                message = sanitize_dashboard_summary(f"CAPTURE_OAUTH_ERROR:{exc.error_name or exc}")
                self._update_operation_status(logical_op_id, "FAILED", error_detail=message, now=current_time)
                self.state_engine.update_order_resolution(order_id, "NEEDS_ATTENTION", now=current_time)
                return None, op.operation_id, op.paypal_request_id, False, message, "FAILED"

            except PayPalAmbiguousNetworkError as exc:
                try:
                    remote_order = self.paypal_client.get_order(order_id)
                    matched = self._find_matching_unclaimed_capture(
                        order_id=order_id,
                        authorization_id=authorization_id,
                        remote_order=remote_order,
                        expected_amount=expected_amount,
                        expected_currency=expected_currency,
                        expected_invoice_id=str(payload.get("invoice_id") or "").strip() or None,
                    )
                    if matched:
                        found_id, found_status = matched
                        self._update_operation_status(
                            logical_op_id,
                            "SUCCEEDED",
                            capture_id=found_id,
                            provider_status=found_status,
                            now=current_time,
                        )
                        self._register_completed_capture(
                            order_id=order_id,
                            authorization_id=authorization_id,
                            capture_id=found_id,
                            resolution_status="CAPTURED" if found_status == "COMPLETED" else "NEEDS_ATTENTION",
                            now=current_time,
                        )
                        return found_id, op.operation_id, op.paypal_request_id, False, ("CAPTURE_STATUS_PENDING" if found_status == "PENDING" else None), found_status
                except (PayPalError, ValueError):
                    pass
                message = sanitize_dashboard_summary(f"CAPTURE_RECONCILIATION_REQUIRED:{exc}")
                self._update_operation_status(
                    logical_op_id,
                    "RECONCILIATION_REQUIRED",
                    error_detail=message,
                    now=current_time,
                )
                self.state_engine.update_order_resolution(order_id, "NEEDS_ATTENTION", now=current_time)
                return None, op.operation_id, op.paypal_request_id, True, message, "UNKNOWN"

            except PayPalAPIError as exc:
                message = sanitize_dashboard_summary(
                    f"CAPTURE_API_ERROR:{exc.issue or exc.error_name or exc.status_code}"
                )
                self._update_operation_status(logical_op_id, "FAILED", error_detail=message, now=current_time)
                self.state_engine.update_order_resolution(order_id, "NEEDS_ATTENTION", now=current_time)
                return None, op.operation_id, op.paypal_request_id, False, message, "FAILED"

        self.state_engine.update_order_resolution(order_id, "NEEDS_ATTENTION", now=current_time)
        return None, op.operation_id, op.paypal_request_id, True, "CAPTURE_EXHAUSTED_RETRIES", "UNKNOWN"

    def _register_completed_capture(
        self,
        *,
        order_id: str,
        authorization_id: str,
        capture_id: str,
        manual_override_actor: Optional[str] = None,
        manual_override_reason: Optional[str] = None,
        resolution_status: str = "CAPTURED",
        now: float,
    ) -> None:
        self.state_engine.register_capture(
            order_id=order_id,
            capture_id=capture_id,
            authorization_id=authorization_id,
            manual_override_actor=manual_override_actor,
            manual_override_reason=manual_override_reason,
            resolution_status=resolution_status,
            now=now,
        )
        if self.webhook_mutex is not None:
            self.webhook_mutex.register_order_capture_link(
                order_id=order_id,
                capture_id=capture_id,
                state_engine=self.state_engine,
                now=now,
            )

    def _build_llm_context(
        self,
        *,
        order_rec: OrderRecord,
        pillar1_result: CombinedPillar1Result,
        decision_mode: str,
    ) -> UntrustedOrderContextForLLM:
        vel = pillar1_result.velocity_result
        dl = pillar1_result.deadlock_result
        anchor = (
            dl.anchor_refund
            if (dl.is_deadlock and dl.anchor_refund is not None)
            else (vel.anchor_order if vel.anchor_order is not None else None)
        )
        anchor_id = getattr(anchor, "order_id", None)
        anchor_desc = getattr(anchor, "description", None)
        anchor_sku = getattr(anchor, "sku", None)
        anchor_name = getattr(anchor, "item_name", None)
        anchor_note = getattr(anchor, "note_to_payer", None)
        anchor_fp_complete = (
            bool(getattr(anchor, "cart_fingerprint_complete")) if anchor is not None else None
        )
        same_currency: Optional[bool] = None
        if anchor is not None and getattr(anchor, "currency", None) is not None:
            same_currency = str(order_rec.currency).upper() == str(anchor.currency).upper()

        return UntrustedOrderContextForLLM(
            order_id=order_rec.order_id,
            incident_id=pillar1_result.incident_id,
            decision_mode=decision_mode,
            amount=order_rec.amount,
            currency=order_rec.currency,
            sku_category=vel.sku_category,
            repeat_count=vel.repeat_count,
            time_delta_seconds=vel.time_delta_seconds,
            is_deadlock=dl.is_deadlock,
            deadlock_reason=dl.deadlock_reason,
            velocity_flag_reason=vel.flag_reason,
            address_changed_vs_anchor=vel.address_changed_vs_anchor,
            identity_strength=vel.identity_strength,
            untrusted_sku_xml=wrap_untrusted_buyer_data(order_rec.sku),
            # Legacy DTO compatibility only; context_builder.py must never serialize this field.
            untrusted_cart_fingerprint_xml=wrap_untrusted_buyer_data(order_rec.cart_fingerprint),
            untrusted_item_name_xml=wrap_untrusted_buyer_data(order_rec.item_name),
            untrusted_description_xml=wrap_untrusted_buyer_data(order_rec.description),
            untrusted_note_to_payer_xml=wrap_untrusted_buyer_data(order_rec.note_to_payer),
            anchor_order_id=anchor_id,
            anchor_untrusted_description_xml=(
                wrap_untrusted_buyer_data(anchor_desc) if anchor_desc is not None else None
            ),
            matched_identity_strength=getattr(vel, "matched_identity_strength", "NONE"),
            has_reliable_identity=bool(getattr(vel, "has_reliable_identity", False)),
            used_ip_fallback=bool(getattr(vel, "used_ip_fallback", False)),
            variant_match_mode=(
                getattr(dl, "variant_match_mode", None) or getattr(vel, "variant_match_mode", None)
            ),
            cart_fingerprint_complete=bool(order_rec.cart_fingerprint_complete),
            refund_count_in_window=int(getattr(dl, "refund_count_in_window", 0) or 0),
            time_since_last_refund_seconds=getattr(dl, "time_since_last_refund_seconds", None),
            deadlock_match_confidence=str(getattr(dl, "match_confidence", "NONE") or "NONE"),
            has_prompt_injection_signal=getattr(vel, "has_prompt_injection_signal", None),
            has_retry_marker_signal=getattr(vel, "has_retry_marker_signal", None),
            cart_relationship=_p2_cart_relationship(order_rec, anchor, vel, dl),
            same_amount_as_anchor=_p2_same_amount(order_rec.amount, anchor),
            same_currency_as_anchor=same_currency,
            anchor_cart_fingerprint_complete=anchor_fp_complete,
            p1_auto_capture_eligible=bool(pillar1_result.can_auto_capture_if_llm_approves),
            anchor_untrusted_sku_xml=(wrap_untrusted_buyer_data(anchor_sku) if anchor_sku is not None else ""),
            anchor_untrusted_item_name_xml=(wrap_untrusted_buyer_data(anchor_name) if anchor_name is not None else ""),
            anchor_untrusted_note_to_payer_xml=(wrap_untrusted_buyer_data(anchor_note) if anchor_note is not None else ""),
        )

    def _await_pillar2_future(
        self,
        *,
        pool: Optional[ThreadPoolExecutor],
        future: Optional[Future[Any]],
        fee_saved_usd: float,
        default_summary: Optional[str] = None,
    ) -> Tuple[Optional[Pillar2TriageVerdict], bool, Optional[str]]:
        if pool is None or future is None:
            return None, False, None

        try:
            raw_res = future.result(timeout=self.llm_timeout_seconds)
        except FuturesTimeoutError:
            pool.shutdown(wait=False, cancel_futures=True)
            return None, True, f"PILLAR2_LLM_TIMEOUT_AFTER_{self.llm_timeout_seconds}S"
        except Exception as exc:
            pool.shutdown(wait=False, cancel_futures=True)
            clean_err = sanitize_dashboard_summary(f"PILLAR2_LLM_ERROR:{type(exc).__name__}:{exc}")
            return None, True, clean_err
        finally:
            pool.shutdown(wait=False)

        try:
            verdict = parse_pillar2_verdict(
                raw_res,
                fee_saved_usd=fee_saved_usd,
                default_summary=default_summary,
            )
            return verdict, False, None
        except (ValueError, TypeError) as exc:
            clean_err = sanitize_dashboard_summary(f"PILLAR2_INVALID_OUTPUT:{exc}")
            return None, True, clean_err

    @staticmethod
    def _build_default_deterministic_summary(
        order_rec: OrderRecord,
        pillar1_result: CombinedPillar1Result,
        decision_mode: str,
    ) -> str:
        dl = pillar1_result.deadlock_result
        vel = pillar1_result.velocity_result
        if dl.is_deadlock:
            return (
                f"Post-refund repurchase detected ({dl.deadlock_reason}) within 60m window; "
                "automatic capture is disabled pending merchant 1-tap Void or Capture."
            )
        return (
            f"Flagged by Pillar 1 ({vel.flag_reason}, repeat_count={vel.repeat_count}, "
            f"mode={decision_mode}); held in zero-fee AUTHORIZE pending review."
        )

    def _build_outcome_from_existing_record(self, rec: OrderRecord) -> SettlementOutcome:
        """Reconstructs a `SettlementOutcome` for an order that was already settled (Must-Fix #2)."""
        fee_saved = (
            0.0
            if rec.resolution_status in ("CAPTURED", "PARTIALLY_CAPTURED")
            else estimate_paypal_fee_saved_usd(rec.amount, rec.currency)
        )
        if not rec.is_flagged:
            mode = "NO_LLM_REQUIRED"
        elif not rec.can_auto_capture_if_llm_approves:
            mode = "EXPLANATION_ONLY"
        else:
            mode = "DECISION_ASSISTED"

        return SettlementOutcome(
            order_id=rec.order_id,
            authorization_id=rec.authorization_id,
            capture_id=rec.capture_id,
            final_status=rec.resolution_status,
            decision_mode=mode,
            capture_allowed=rec.resolution_status in ("CAPTURED", "PARTIALLY_CAPTURED"),
            deterministic_override_applied=bool(
                mode == "EXPLANATION_ONLY"
                and rec.pillar2_classification == "LEGITIMATE_REPEAT_BUYER"
            ),
            incident_id=rec.incident_id,
            pillar1_result=None,
            pillar2_verdict=None,
            merchant_summary=f"Order '{rec.order_id}' already settled in status '{rec.resolution_status}'.",
            estimated_fee_saved_usd=fee_saved,
        )

    def settle_approved_order(
        self,
        order_id: str,
        *,
        paypal_order: Optional[Dict[str, Any]] = None,
        trusted_order_snapshot: bool = False,
        customer_id: Optional[str] = None,
        session_id: Optional[str] = None,
        product_family_id: Optional[str] = None,
        note_to_payer: Optional[str] = None,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        now: Optional[float] = None,
    ) -> SettlementOutcome:
        current_time = now if now is not None else time.time()
        clean_oid = (order_id or "").strip()
        if not clean_oid:
            raise ValueError("order_id is required.")

        order_lock = self._get_order_lock(clean_oid)
        with order_lock:
            # Must-Fix #2: Early return if the order was already settled (prevents double-settle
            # from flipping CAPTURED / VOIDED / AUTHORIZED_HOLD orders back into hold states).
            # Minor #8: If the order is in NEEDS_ATTENTION with authorization_id is None (failed
            # authorize), allow settle_approved_order to retry authorization.
            existing_rec = self.state_engine.get_order(clean_oid)
            retryable_failed_capture_op: Optional[PaymentOperationRecord] = None
            orphaned_authorize_op: Optional[PaymentOperationRecord] = None
            pre_capture_recovery = False
            if existing_rec is not None:
                if existing_rec.resolution_status == "APPROVED_PENDING_SETTLEMENT" and not existing_rec.authorization_id:
                    persisted_authorize = self.get_operation_record(f"authorize:{clean_oid}")
                    if (
                        persisted_authorize is not None
                        and persisted_authorize.operation_type == "AUTHORIZE"
                        and persisted_authorize.order_id == clean_oid
                        and persisted_authorize.status == "SUCCEEDED"
                        and persisted_authorize.authorization_id
                    ):
                        orphaned_authorize_op = persisted_authorize
                if existing_rec.resolution_status in (
                    "CAPTURED",
                    "PARTIALLY_CAPTURED",
                    "VOIDED",
                ):
                    return self._build_outcome_from_existing_record(existing_rec)

                if existing_rec.resolution_status == "NEEDS_ATTENTION" and existing_rec.authorization_id is not None:
                    with self._lock:
                        failed_capture_ops = [
                            copy.deepcopy(op)
                            for op in self._operations.values()
                            if op.order_id == clean_oid
                            and op.operation_type == "CAPTURE"
                            and op.authorization_id == existing_rec.authorization_id
                            and op.status == "FAILED"
                            and not op.capture_id
                            and op.operation_id == f"capture:{existing_rec.authorization_id}:full"
                        ]
                    if len(failed_capture_ops) == 1:
                        retryable_failed_capture_op = failed_capture_ops[0]
                    else:
                        return self._build_outcome_from_existing_record(existing_rec)

                elif existing_rec.resolution_status in ("AUTHORIZED_HOLD", "ANALYZING_HOLD"):
                    # Resume only a durable, already-approved pre-capture checkpoint:
                    # clean orders are AUTHORIZED_HOLD + not flagged; flagged orders
                    # are ANALYZING_HOLD + the explicit P2 approval classification.
                    # A pending/failed P2 decision and a hard hold cannot enter this path.
                    clean_auto_eligible = (
                        existing_rec.resolution_status == "AUTHORIZED_HOLD"
                        and not existing_rec.is_flagged
                        and existing_rec.can_auto_capture_if_llm_approves
                        and not existing_rec.deterministic_hold_reason
                    )
                    p2_approved_checkpoint = (
                        existing_rec.resolution_status == "ANALYZING_HOLD"
                        and existing_rec.is_flagged
                        and existing_rec.can_auto_capture_if_llm_approves
                        and existing_rec.pillar2_classification == "LEGITIMATE_REPEAT_BUYER"
                    )
                    with self._lock:
                        any_capture_operation = any(
                            op.order_id == clean_oid
                            and op.operation_type == "CAPTURE"
                            and op.authorization_id == existing_rec.authorization_id
                            for op in self._operations.values()
                        )
                    pre_capture_recovery = bool(
                        existing_rec.authorization_id
                        and (clean_auto_eligible or p2_approved_checkpoint)
                        and not any_capture_operation
                        and not existing_rec.capture_id
                        and not existing_rec.capture_ids
                    )
                    if not pre_capture_recovery:
                        return self._build_outcome_from_existing_record(existing_rec)

                elif existing_rec.resolution_status not in ("APPROVED_PENDING_SETTLEMENT",):
                    return self._build_outcome_from_existing_record(existing_rec)

            if paypal_order is not None:
                if not isinstance(paypal_order, dict):
                    raise ValueError("paypal_order must be a dictionary.")
                supplied_id = str(paypal_order.get("id") or "").strip()
                if supplied_id != clean_oid:
                    raise ValueError(
                        f"Order ID mismatch: order_id='{clean_oid}' does not match "
                        f"paypal_order['id']='{supplied_id}'."
                    )

            # Every settlement decision is based on a fresh server-side PayPal GET.
            # `trusted_order_snapshot` is retained for API compatibility only; it is not
            # authority to bypass the provider lookup.
            authoritative_order = copy.deepcopy(self.paypal_client.get_order(clean_oid))
            authoritative_order_id = str(authoritative_order.get("id") or "").strip()
            if authoritative_order_id != clean_oid:
                raise ValueError(
                    f"Authoritative PayPal order ID mismatch: requested='{clean_oid}', returned='{authoritative_order_id}'."
                )
            remote_status = str(authoritative_order.get("status") or "").strip().upper()

            # Re-validate the fresh provider resource at the money-movement boundary.
            # `COMPLETED` is a normal PayPal Orders v2 status after /authorize, so it must
            # receive the same single-merchant/order-shape checks as an APPROVED order
            # before any recovery path can capture its authorization.
            if remote_status in ("APPROVED", "COMPLETED"):
                try:
                    validate_mvp_order_shape(authoritative_order)
                except ValueError as shape_exc:
                    # Some authoritative order GET responses omit optional `items`,
                    # `description`, and `custom_id` even though P1 already persisted a
                    # validated product signal from the original approved checkout. Permit
                    # only that specific omission when the local order ledger still has
                    # a product identifier/name/description; marketplace fields, empty
                    # item arrays, malformed items, and multiple purchase units remain
                    # hard failures from validate_mvp_order_shape().
                    missing_remote_product_signal = str(shape_exc).startswith(
                        "ORDER_PRODUCT_SIGNAL_REQUIRED:"
                    )
                    local_product_signal = bool(
                        existing_rec is not None
                        and any(str(value or "").strip() for value in (
                            getattr(existing_rec, "sku", None),
                            getattr(existing_rec, "item_name", None),
                            getattr(existing_rec, "description", None),
                            getattr(existing_rec, "custom_id", None),
                        ))
                    )
                    if not (missing_remote_product_signal and local_product_signal):
                        raise

            # Recover the narrow crash window where PayPal accepted /authorize and P3
            # persisted its successful operation, but the process died before P1's local
            # OrderRecord was bound to that authorization. A successful persisted P3
            # AUTHORIZE record plus an exact matching remote authorization is required.
            if orphaned_authorize_op is not None and existing_rec is not None:
                if remote_status not in ("APPROVED", "COMPLETED"):
                    self._update_operation_status(
                        orphaned_authorize_op.operation_id,
                        "RECONCILIATION_REQUIRED",
                        error_detail=f"ORPHANED_AUTHORIZATION_RECOVERY_UNEXPECTED_ORDER_STATUS:{remote_status or 'MISSING'}",
                        now=current_time,
                    )
                    self.state_engine.update_order_resolution(clean_oid, "NEEDS_ATTENTION", now=current_time)
                    return self._build_outcome_from_existing_record(self.state_engine.get_order(clean_oid))
                try:
                    remote_auth_id, _ = self._extract_authorization_from_order_response(authoritative_order)
                except ValueError as exc:
                    remote_auth_id = None
                    auth_recovery_error = sanitize_dashboard_summary(f"ORPHANED_AUTHORIZATION_AMBIGUOUS:{exc}")
                else:
                    auth_recovery_error = "ORPHANED_AUTHORIZATION_ID_MISSING_OR_MISMATCHED"
                if remote_auth_id != orphaned_authorize_op.authorization_id:
                    self._update_operation_status(
                        orphaned_authorize_op.operation_id,
                        "RECONCILIATION_REQUIRED",
                        error_detail=auth_recovery_error,
                        now=current_time,
                    )
                    self.state_engine.update_order_resolution(clean_oid, "NEEDS_ATTENTION", now=current_time)
                    return self._build_outcome_from_existing_record(self.state_engine.get_order(clean_oid))
                if self._extract_capture_objects_from_order_response(authoritative_order):
                    self._update_operation_status(
                        orphaned_authorize_op.operation_id,
                        "RECONCILIATION_REQUIRED",
                        error_detail="REMOTE_CAPTURE_EXISTS_DURING_ORPHANED_AUTHORIZATION_RECOVERY",
                        now=current_time,
                    )
                    self.state_engine.update_order_resolution(clean_oid, "NEEDS_ATTENTION", now=current_time)
                    return self._build_outcome_from_existing_record(self.state_engine.get_order(clean_oid))
                try:
                    live_auth = self.paypal_client.get_authorization(orphaned_authorize_op.authorization_id)
                    live_auth_id = str(live_auth.get("id") or "").strip()
                    live_auth_status = str(live_auth.get("status") or "").strip().upper()
                except PayPalError:
                    live_auth_id, live_auth_status = "", ""
                if live_auth_id != orphaned_authorize_op.authorization_id or live_auth_status != "CREATED":
                    self._update_operation_status(
                        orphaned_authorize_op.operation_id,
                        "RECONCILIATION_REQUIRED",
                        error_detail="ORPHANED_AUTHORIZATION_LIVE_LOOKUP_NOT_CAPTURABLE",
                        provider_status=live_auth_status or None,
                        now=current_time,
                    )
                    self.state_engine.update_order_resolution(clean_oid, "NEEDS_ATTENTION", now=current_time)
                    return self._build_outcome_from_existing_record(self.state_engine.get_order(clean_oid))

                initial_hold_status = (
                    "ANALYZING_HOLD"
                    if existing_rec.is_flagged or not existing_rec.can_auto_capture_if_llm_approves
                    else "AUTHORIZED_HOLD"
                )
                marked = self.state_engine.mark_order_authorized(
                    clean_oid,
                    orphaned_authorize_op.authorization_id,
                    status=initial_hold_status,
                    now=current_time,
                )
                if not marked:
                    self.state_engine.update_order_resolution(clean_oid, "NEEDS_ATTENTION", now=current_time)
                    return self._build_outcome_from_existing_record(self.state_engine.get_order(clean_oid))
                existing_rec = self.state_engine.get_order(clean_oid)
                if existing_rec is None:
                    raise RuntimeError("OrderRecord disappeared during orphaned authorization recovery.")
                if initial_hold_status == "ANALYZING_HOLD":
                    # P2's result was not durably recorded before the crash. Preserve the
                    # authorization as a hold, but never infer AI approval or capture.
                    return SettlementOutcome(
                        order_id=clean_oid,
                        authorization_id=orphaned_authorize_op.authorization_id,
                        capture_id=None,
                        final_status="ANALYZING_HOLD",
                        decision_mode=("EXPLANATION_ONLY_RECOVERY_HOLD" if not existing_rec.can_auto_capture_if_llm_approves else "DECISION_ASSISTED_RECOVERY_HOLD"),
                        capture_allowed=False,
                        deterministic_override_applied=False,
                        incident_id=existing_rec.incident_id,
                        pillar1_result=None,
                        pillar2_verdict=None,
                        merchant_summary="Authorization recovered after interruption. P2 approval was not durably recorded, so the order remains on hold and is not captured.",
                        estimated_fee_saved_usd=estimate_paypal_fee_saved_usd(existing_rec.amount, existing_rec.currency),
                        authorize_request_id=orphaned_authorize_op.paypal_request_id,
                        reconciliation_required=False,
                    )
                pre_capture_recovery = True

            # PayPal marks an AUTHORIZE order COMPLETED after /authorize, even while its
            # underlying authorization remains CREATED and capturable. Permit that status
            # only for a recovery of one exact, locally persisted, definitively FAILED full
            # capture. This path does not re-run /authorize or re-run P1/P2; the failed
            # capture record proves the earlier P1/P2 gates were passed. P1's capture
            # validator still runs again immediately before the retry.
            if (retryable_failed_capture_op is not None or pre_capture_recovery) and existing_rec is not None:
                if remote_status not in ("APPROVED", "COMPLETED"):
                    # The provider's current order state is not a valid recovery checkpoint.
                    # Persist the fail-closed state, then build the returned outcome from the
                    # refreshed ledger record (not the stale AUTHORIZED_HOLD/ANALYZING_HOLD
                    # snapshot fetched before the remote GET).
                    self.state_engine.update_order_resolution(
                        clean_oid, "NEEDS_ATTENTION", now=current_time
                    )
                    refreshed_rec = self.state_engine.get_order(clean_oid)
                    if refreshed_rec is None:
                        raise RuntimeError(
                            f"OrderRecord '{clean_oid}' disappeared during pre-capture recovery."
                        )
                    outcome = self._build_outcome_from_existing_record(refreshed_rec)
                    outcome.final_status = "NEEDS_ATTENTION"
                    outcome.capture_allowed = False
                    outcome.reconciliation_required = False
                    outcome.error_reason = (
                        f"PRE_CAPTURE_RECOVERY_UNEXPECTED_REMOTE_ORDER_STATUS:{remote_status or 'MISSING'}"
                    )
                    outcome.merchant_summary = (
                        "Pre-capture recovery stopped because the authoritative PayPal order "
                        f"reported unexpected status '{remote_status or 'MISSING'}'. "
                        "The existing authorization was not captured or reauthorized."
                    )
                    return outcome
                def _recovery_needs_attention(reason: str) -> SettlementOutcome:
                    # A pre-capture checkpoint can exist without a failed capture operation.
                    # Never dereference/update a nonexistent operation; preserve the already
                    # bound authorization and fail closed without creating a new payment action.
                    if retryable_failed_capture_op is not None:
                        self._update_operation_status(
                            retryable_failed_capture_op.operation_id,
                            "RECONCILIATION_REQUIRED",
                            error_detail=sanitize_dashboard_summary(reason),
                            now=current_time,
                        )
                    self.state_engine.update_order_resolution(
                        clean_oid, "NEEDS_ATTENTION", now=current_time
                    )
                    outcome = self._build_outcome_from_existing_record(
                        self.state_engine.get_order(clean_oid) or existing_rec
                    )
                    outcome.final_status = "NEEDS_ATTENTION"
                    outcome.capture_allowed = False
                    outcome.reconciliation_required = True
                    outcome.error_reason = sanitize_dashboard_summary(reason)
                    outcome.merchant_summary = (
                        "Capture recovery was stopped because the authoritative PayPal order "
                        "did not prove the exact previously bound authorization/capture state. "
                        "No new authorization or capture was created."
                    )
                    return outcome

                try:
                    remote_auth_id, _ = self._extract_authorization_from_order_response(authoritative_order)
                except ValueError as exc:
                    return _recovery_needs_attention(
                        f"RECOVERY_AUTHORIZATION_AMBIGUOUS:{exc}"
                    )
                if remote_auth_id != existing_rec.authorization_id:
                    return _recovery_needs_attention(
                        "RECOVERY_AUTHORIZATION_ID_MISSING_OR_MISMATCHED"
                    )
                remote_captures = self._extract_capture_objects_from_order_response(authoritative_order)
                if remote_captures:
                    return _recovery_needs_attention(
                        "REMOTE_CAPTURE_EXISTS_DURING_FAILED_CAPTURE_RECOVERY; RECONCILE_BEFORE_RETRY"
                    )

                amount_fee = estimate_paypal_fee_saved_usd(existing_rec.amount, existing_rec.currency)
                recovery_decision_mode = (
                    "AUTHORIZED_CAPTURE_RETRY"
                    if retryable_failed_capture_op is not None
                    else ("DECISION_ASSISTED_RECOVERY" if existing_rec.is_flagged else "NO_LLM_REQUIRED_RECOVERY")
                )
                cap_id, cap_op_id, cap_req_id, cap_reconcile, cap_err, cap_status = (
                    self._execute_capture_with_reconciliation(
                        order_id=clean_oid,
                        authorization_id=existing_rec.authorization_id,
                        paypal_auth_status="CREATED",  # helper performs an independent live GET
                        capture_mode="AUTO",
                        decision_allows_capture=True,  # recovery admission requires durable P1/P2 approval state or a definitive prior capture failure
                        operation_key="full",
                        now=current_time,
                    )
                )
                authorize_op = self.get_operation_record(f"authorize:{clean_oid}")
                authorize_req_id = authorize_op.paypal_request_id if authorize_op else None
                if cap_id and cap_status == "COMPLETED":
                    return SettlementOutcome(
                        order_id=clean_oid, authorization_id=existing_rec.authorization_id,
                        capture_id=cap_id, final_status="CAPTURED", decision_mode=recovery_decision_mode,
                        capture_allowed=True, deterministic_override_applied=False,
                        incident_id=existing_rec.incident_id, pillar1_result=None, pillar2_verdict=None,
                        merchant_summary=(
                            "Full capture retry succeeded after a definitive prior PayPal failure; no new authorization was created."
                            if retryable_failed_capture_op is not None
                            else "Previously approved capture checkpoint recovered after interruption; no new authorization was created."
                        ),
                        estimated_fee_saved_usd=0.0, authorize_request_id=authorize_req_id,
                        capture_request_id=cap_req_id, capture_operation_id=cap_op_id,
                    )
                return SettlementOutcome(
                    order_id=clean_oid, authorization_id=existing_rec.authorization_id,
                    capture_id=cap_id, final_status="NEEDS_ATTENTION", decision_mode=recovery_decision_mode,
                    capture_allowed=bool(cap_id and cap_status == "PENDING"), deterministic_override_applied=False,
                    incident_id=existing_rec.incident_id, pillar1_result=None, pillar2_verdict=None,
                    merchant_summary="Capture recovery did not complete. The existing authorization remains under review; do not create another authorization.",
                    estimated_fee_saved_usd=amount_fee, authorize_request_id=authorize_req_id,
                    capture_request_id=cap_req_id, capture_operation_id=cap_op_id,
                    reconciliation_required=cap_reconcile, error_reason=cap_err,
                )

            if remote_status != "APPROVED":
                raise ValueError(
                    f"PayPal order '{clean_oid}' must be APPROVED before a new authorization; status='{remote_status or 'MISSING'}'."
                )

            pillar1_res = evaluate_approved_paypal_order(
                state_engine=self.state_engine,
                deadlock_detector=self.deadlock_detector,
                paypal_order=authoritative_order,
                customer_id=customer_id,
                session_id=session_id,
                product_family_id=product_family_id,
                note_to_payer=note_to_payer,
                client_ip=client_ip,
                user_agent=user_agent,
                now=current_time,
            )

            order_rec = self.state_engine.get_order(clean_oid)
            assert order_rec is not None
            fee_saved = estimate_paypal_fee_saved_usd(order_rec.amount, order_rec.currency)

            if not pillar1_res.can_auto_capture_if_llm_approves:
                decision_mode = "EXPLANATION_ONLY"
            elif not pillar1_res.is_flagged:
                decision_mode = "NO_LLM_REQUIRED"
            else:
                decision_mode = "DECISION_ASSISTED"

            default_summary = self._build_default_deterministic_summary(
                order_rec, pillar1_res, decision_mode
            )

            # Start Pillar 2 in parallel with PayPal /authorize at t = 0ms when flagged
            llm_pool: Optional[ThreadPoolExecutor] = None
            llm_future: Optional[Future[Any]] = None
            if decision_mode in ("EXPLANATION_ONLY", "DECISION_ASSISTED") and self.llm_triage_callback is not None:
                ctx = self._build_llm_context(
                    order_rec=order_rec,
                    pillar1_result=pillar1_res,
                    decision_mode=decision_mode,
                )
                llm_pool = ThreadPoolExecutor(max_workers=1)
                llm_future = llm_pool.submit(self.llm_triage_callback, ctx)

            try:
                auth_id, auth_status, auth_req_id, auth_reconcile_req, auth_err = (
                    self._authorize_with_reconciliation(clean_oid, now=current_time, paypal_order=authoritative_order)
                )
            except Exception:
                if llm_pool is not None:
                    llm_pool.shutdown(wait=False, cancel_futures=True)
                raise

            if auth_reconcile_req or not auth_id:
                if llm_pool is not None:
                    llm_pool.shutdown(wait=False, cancel_futures=True)
                self.state_engine.update_order_resolution(clean_oid, "NEEDS_ATTENTION", now=current_time)
                return SettlementOutcome(
                    order_id=clean_oid,
                    authorization_id=auth_id,
                    capture_id=None,
                    final_status="NEEDS_ATTENTION",
                    decision_mode=decision_mode,
                    capture_allowed=False,
                    deterministic_override_applied=False,
                    incident_id=pillar1_res.incident_id,
                    pillar1_result=pillar1_res,
                    pillar2_verdict=None,
                    merchant_summary="PayPal authorization failed or remained ambiguous; manual review or retry required.",
                    estimated_fee_saved_usd=fee_saved,
                    authorize_request_id=auth_req_id,
                    reconciliation_required=auth_reconcile_req,
                    error_reason=auth_err,
                )

            initial_hold_status = "ANALYZING_HOLD" if pillar1_res.is_flagged else "AUTHORIZED_HOLD"
            marked_authorized = self.state_engine.mark_order_authorized(
                order_id=clean_oid,
                authorization_id=auth_id,
                status=initial_hold_status,
                now=current_time,
            )
            if not marked_authorized:
                if llm_pool is not None:
                    llm_pool.shutdown(wait=False, cancel_futures=True)
                self.state_engine.update_order_resolution(clean_oid, "NEEDS_ATTENTION", now=current_time)
                return SettlementOutcome(
                    order_id=clean_oid, authorization_id=auth_id, capture_id=None,
                    final_status="NEEDS_ATTENTION", decision_mode=decision_mode,
                    capture_allowed=False, deterministic_override_applied=False,
                    incident_id=pillar1_res.incident_id, pillar1_result=pillar1_res,
                    pillar2_verdict=None, merchant_summary="PayPal authorization exists but local authorization binding was refused.",
                    estimated_fee_saved_usd=fee_saved, authorize_request_id=auth_req_id,
                    reconciliation_required=True, error_reason="LOCAL_AUTHORIZATION_BINDING_REFUSED",
                )

            # Mode 1: Clean Order (NO_LLM_REQUIRED) -> Immediate 0ms Capture
            if decision_mode == "NO_LLM_REQUIRED":
                cap_id, cap_op_id, cap_req_id, cap_reconcile, cap_err, cap_status = (
                    self._execute_capture_with_reconciliation(
                        order_id=clean_oid,
                        authorization_id=auth_id,
                        paypal_auth_status=auth_status,
                        capture_mode="AUTO",
                        decision_allows_capture=True,
                        operation_key="full",
                        now=current_time,
                    )
                )
                if cap_id and cap_status == "COMPLETED":
                    return SettlementOutcome(
                        order_id=clean_oid,
                        authorization_id=auth_id,
                        capture_id=cap_id,
                        final_status="CAPTURED",
                        decision_mode="NO_LLM_REQUIRED",
                        capture_allowed=True,
                        deterministic_override_applied=False,
                        incident_id=pillar1_res.incident_id,
                        pillar1_result=pillar1_res,
                        pillar2_verdict=None,
                        merchant_summary="Clean transaction authorized and captured immediately.",
                        estimated_fee_saved_usd=0.0,
                        authorize_request_id=auth_req_id,
                        capture_request_id=cap_req_id,
                        capture_operation_id=cap_op_id,
                    )
                if cap_id and cap_status == "PENDING":
                    return SettlementOutcome(
                        order_id=clean_oid,
                        authorization_id=auth_id,
                        capture_id=cap_id,
                        final_status="NEEDS_ATTENTION",
                        decision_mode="NO_LLM_REQUIRED",
                        capture_allowed=True,
                        deterministic_override_applied=False,
                        incident_id=pillar1_res.incident_id,
                        pillar1_result=pillar1_res,
                        pillar2_verdict=None,
                        merchant_summary="PayPal capture is PENDING (awaiting settlement); do not re-capture.",
                        estimated_fee_saved_usd=0.0,
                        authorize_request_id=auth_req_id,
                        capture_request_id=cap_req_id,
                        capture_operation_id=cap_op_id,
                        error_reason=cap_err,
                    )
                return SettlementOutcome(
                    order_id=clean_oid,
                    authorization_id=auth_id,
                    capture_id=None,
                    final_status="NEEDS_ATTENTION",
                    decision_mode="NO_LLM_REQUIRED",
                    capture_allowed=False,
                    deterministic_override_applied=False,
                    incident_id=pillar1_res.incident_id,
                    pillar1_result=pillar1_res,
                    pillar2_verdict=None,
                    merchant_summary="Automatic capture failed after authorization; reconcile the provider operation before further action.",
                    estimated_fee_saved_usd=fee_saved,
                    authorize_request_id=auth_req_id,
                    capture_request_id=cap_req_id,
                    capture_operation_id=cap_op_id,
                    reconciliation_required=cap_reconcile,
                    error_reason=cap_err,
                )

            # Collect Pillar 2 result for EXPLANATION_ONLY or DECISION_ASSISTED
            verdict, llm_failed, llm_err = self._await_pillar2_future(
                pool=llm_pool,
                future=llm_future,
                fee_saved_usd=fee_saved,
                default_summary=default_summary,
            )
            summary_text = (
                verdict.merchant_summary
                if (verdict is not None and not llm_failed)
                else (
                    sanitize_dashboard_summary(f"AI Co-Pilot unavailable ({llm_err}); {default_summary}")
                    if llm_failed
                    else default_summary
                )
            )

            # Mode 2: EXPLANATION_ONLY (Hard Deterministic Ceiling)
            if decision_mode == "EXPLANATION_ONLY":
                capture_allowed = False
                llm_tried_to_approve = bool(
                    verdict is not None
                    and (
                        verdict.classification == "LEGITIMATE_REPEAT_BUYER"
                        or verdict.recommended_action == "ALLOW_CAPTURE"
                    )
                )
                final_hold_state = "NEEDS_ATTENTION" if llm_failed else "AUTHORIZED_HOLD"
                # Should-Fix #3d: Preserve the AI's true classification (or None if AI did not run / failed)
                # and store the deterministic hold reason separately so Bulk Void skips AI-legitimate orders.
                stored_classification: Optional[str] = (
                    verdict.classification if (verdict is not None and not llm_failed) else None
                )
                velocity_result = pillar1_res.velocity_result
                if pillar1_res.deadlock_result.is_deadlock:
                    det_reason = "BUY_REFUND_DEADLOCK"
                elif velocity_result.is_hard_hold_category:
                    det_reason = "NON_STACKABLE_CATALOG_HARD_HOLD"
                elif not velocity_result.has_reliable_identity:
                    det_reason = "IDENTITY_NOT_RELIABLE"
                else:
                    det_reason = "DETERMINISTIC_P1_HARD_HOLD"

                self.state_engine.update_order_resolution(
                    clean_oid,
                    final_hold_state,
                    now=current_time,
                    pillar2_classification=stored_classification,
                    deterministic_hold_reason=det_reason,
                )
                return SettlementOutcome(
                    order_id=clean_oid,
                    authorization_id=auth_id,
                    capture_id=None,
                    final_status=final_hold_state,
                    decision_mode="EXPLANATION_ONLY",
                    capture_allowed=capture_allowed,
                    deterministic_override_applied=llm_tried_to_approve,
                    incident_id=pillar1_res.incident_id,
                    pillar1_result=pillar1_res,
                    pillar2_verdict=verdict,
                    merchant_summary=summary_text,
                    estimated_fee_saved_usd=fee_saved,
                    authorize_request_id=auth_req_id,
                    error_reason=llm_err,
                )

            # Mode 3: DECISION_ASSISTED
            if llm_failed or verdict is None:
                target_state = "NEEDS_ATTENTION" if llm_failed else "AUTHORIZED_HOLD"
                self.state_engine.update_order_resolution(
                    clean_oid,
                    target_state,
                    now=current_time,
                    pillar2_classification=None,
                )
                return SettlementOutcome(
                    order_id=clean_oid,
                    authorization_id=auth_id,
                    capture_id=None,
                    final_status=target_state,
                    decision_mode="DECISION_ASSISTED",
                    capture_allowed=False,
                    deterministic_override_applied=False,
                    incident_id=pillar1_res.incident_id,
                    pillar1_result=pillar1_res,
                    pillar2_verdict=None,
                    merchant_summary=summary_text,
                    estimated_fee_saved_usd=fee_saved,
                    authorize_request_id=auth_req_id,
                    error_reason=llm_err,
                )

            llm_approves_auto_capture = (
                verdict.classification == "LEGITIMATE_REPEAT_BUYER"
                and verdict.recommended_action == "ALLOW_CAPTURE"
                and verdict.confidence >= AUTO_CAPTURE_CONFIDENCE_THRESHOLD
            )

            if not llm_approves_auto_capture:
                self.state_engine.update_order_resolution(
                    clean_oid,
                    "AUTHORIZED_HOLD",
                    now=current_time,
                    pillar2_classification=verdict.classification,
                )
                return SettlementOutcome(
                    order_id=clean_oid,
                    authorization_id=auth_id,
                    capture_id=None,
                    final_status="AUTHORIZED_HOLD",
                    decision_mode="DECISION_ASSISTED",
                    capture_allowed=False,
                    deterministic_override_applied=False,
                    incident_id=pillar1_res.incident_id,
                    pillar1_result=pillar1_res,
                    pillar2_verdict=verdict,
                    merchant_summary=summary_text,
                    estimated_fee_saved_usd=fee_saved,
                    authorize_request_id=auth_req_id,
                )

            # Both Pillar 1 and Pillar 2 approve automatic capture
            self.state_engine.update_order_resolution(
                clean_oid,
                "ANALYZING_HOLD",
                now=current_time,
                pillar2_classification="LEGITIMATE_REPEAT_BUYER",
            )
            cap_id, cap_op_id, cap_req_id, cap_reconcile, cap_err, cap_status = (
                self._execute_capture_with_reconciliation(
                    order_id=clean_oid,
                    authorization_id=auth_id,
                    paypal_auth_status=(auth_status or "CREATED"),
                    capture_mode="AUTO",
                    decision_allows_capture=True,
                    operation_key="full",
                    now=current_time,
                )
            )
            if cap_id and cap_status == "COMPLETED":
                return SettlementOutcome(
                    order_id=clean_oid,
                    authorization_id=auth_id,
                    capture_id=cap_id,
                    final_status="CAPTURED",
                    decision_mode="DECISION_ASSISTED",
                    capture_allowed=True,
                    deterministic_override_applied=False,
                    incident_id=pillar1_res.incident_id,
                    pillar1_result=pillar1_res,
                    pillar2_verdict=verdict,
                    merchant_summary=summary_text,
                    estimated_fee_saved_usd=0.0,
                    authorize_request_id=auth_req_id,
                    capture_request_id=cap_req_id,
                    capture_operation_id=cap_op_id,
                )
            if cap_id and cap_status == "PENDING":
                return SettlementOutcome(
                    order_id=clean_oid,
                    authorization_id=auth_id,
                    capture_id=cap_id,
                    final_status="NEEDS_ATTENTION",
                    decision_mode="DECISION_ASSISTED",
                    capture_allowed=True,
                    deterministic_override_applied=False,
                    incident_id=pillar1_res.incident_id,
                    pillar1_result=pillar1_res,
                    pillar2_verdict=verdict,
                    merchant_summary="PayPal capture is PENDING (awaiting settlement); do not re-capture.",
                    estimated_fee_saved_usd=0.0,
                    authorize_request_id=auth_req_id,
                    capture_request_id=cap_req_id,
                    capture_operation_id=cap_op_id,
                    error_reason=cap_err,
                )

            return SettlementOutcome(
                order_id=clean_oid,
                authorization_id=auth_id,
                capture_id=None,
                final_status="NEEDS_ATTENTION",
                decision_mode="DECISION_ASSISTED",
                capture_allowed=False,
                deterministic_override_applied=False,
                incident_id=pillar1_res.incident_id,
                pillar1_result=pillar1_res,
                pillar2_verdict=verdict,
                merchant_summary=sanitize_dashboard_summary(
                    f"AI approved repeat buyer, but PayPal capture call failed ({cap_err}); retry needed."
                ),
                estimated_fee_saved_usd=fee_saved,
                authorize_request_id=auth_req_id,
                capture_request_id=cap_req_id,
                capture_operation_id=cap_op_id,
                reconciliation_required=cap_reconcile,
                error_reason=cap_err,
            )

    # ------------------------------------------------------------------
    # Background Reconciliation Sweep (`reconcile_stuck_holds`) & Scheduler
    # ------------------------------------------------------------------
    def reconcile_stuck_holds(
        self,
        *,
        older_than_seconds: float = 60.0,
        now: Optional[float] = None,
    ) -> ReconciliationSweepReport:
        """
        Queries PayPal for any order stuck in `APPROVED_PENDING_SETTLEMENT`, `ANALYZING_HOLD`,
        `AUTO_CAPTURING`, `NEEDS_ATTENTION` (with a `PENDING` capture), or with an operation in
        `RECONCILIATION_REQUIRED` (Should-Fix #3f):
        - If an order in `APPROVED_PENDING_SETTLEMENT` has no authorization yet (`eff_auth_id is None`)
          and PayPal reports `status == "APPROVED"`, resumes `settle_approved_order()`.
        - If `eff_auth_id` exists on PayPal, marks any `IN_FLIGHT`/`RECONCILIATION_REQUIRED`
          `AUTHORIZE` operation `SUCCEEDED` (never `FAILED`).
        - If PayPal reports a `COMPLETED` capture, registers the capture (`CAPTURED`) and updates
          only `IN_FLIGHT`/`RECONCILIATION_REQUIRED` capture operations (preserving `FAILED` history).
        - If PayPal reports a `PENDING` capture, records the `PENDING` capture ID and keeps the
          order in `NEEDS_ATTENTION` without resetting the capture operation to `FAILED`.
        """
        current_time = now if now is not None else time.time()
        stuck_orders = {
            o.order_id: o
            for o in self.state_engine.get_unresolved_holds(
                older_than_seconds=older_than_seconds,
                now=current_time,
            )
        }
        # Also include NEEDS_ATTENTION orders that have a recorded PENDING capture_id
        for hold_ord in self.state_engine.get_active_holds(voidable_only=False):
            if hold_ord.resolution_status == "NEEDS_ATTENTION" and hold_ord.capture_id:
                stuck_orders[hold_ord.order_id] = hold_ord

        with self._lock:
            for op in self._operations.values():
                if op.status == "RECONCILIATION_REQUIRED":
                    rec = self.state_engine.get_order(op.order_id)
                    if rec is not None and rec.resolution_status not in ("CAPTURED", "VOIDED"):
                        stuck_orders[rec.order_id] = rec

        report = ReconciliationSweepReport()
        for oid, ord_rec in stuck_orders.items():
            report.checked_order_ids.append(oid)
            order_lock = self._get_order_lock(oid)
            with order_lock:
                try:
                    remote_order = self.paypal_client.get_order(oid)
                    r_auth_id, r_auth_status = self._extract_authorization_from_order_response(remote_order)
                    eff_auth_id = ord_rec.authorization_id or r_auth_id

                    # Should-Fix #3f-1: Order never got authorized on PayPal -> resume settle_approved_order
                    remote_order_status = str(remote_order.get("status") or "").strip().upper()
                    if (
                        not eff_auth_id
                        and ord_rec.resolution_status == "APPROVED_PENDING_SETTLEMENT"
                        and remote_order_status == "APPROVED"
                    ):
                        with self._lock:
                            for op in self._operations.values():
                                if op.order_id == oid and op.operation_type == "AUTHORIZE" and op.status == "RECONCILIATION_REQUIRED":
                                    op.status = "FAILED"
                                    op.updated_at = current_time
                                    self._persist_operation_locked(op)
                        resumed = self.settle_approved_order(
                            oid,
                            paypal_order=remote_order,
                            trusted_order_snapshot=True,
                            now=current_time,
                        )
                        report.resumed_settlement_order_ids.append(oid)
                        if resumed.final_status == "CAPTURED":
                            report.resolved_captured_order_ids.append(oid)
                        elif resumed.final_status == "NEEDS_ATTENTION":
                            report.escalated_needs_attention_order_ids.append(oid)
                        continue

                    # Should-Fix #3f-3: If authorization exists on PayPal, mark any stuck AUTHORIZE op SUCCEEDED
                    if eff_auth_id:
                        if not ord_rec.authorization_id:
                            self.state_engine.mark_order_authorized(
                                oid,
                                authorization_id=eff_auth_id,
                                status=ord_rec.resolution_status,
                                now=current_time,
                            )
                        with self._lock:
                            for op in self._operations.values():
                                if (
                                    op.order_id == oid
                                    and op.operation_type == "AUTHORIZE"
                                    and op.status in ("IN_FLIGHT", "RECONCILIATION_REQUIRED")
                                ):
                                    op.status = "SUCCEEDED"
                                    op.authorization_id = eff_auth_id
                                    op.updated_at = current_time
                                    self._persist_operation_locked(op)

                    if ord_rec.authorization_id and r_auth_id and ord_rec.authorization_id != r_auth_id:
                        self.state_engine.update_order_resolution(oid, "NEEDS_ATTENTION", now=current_time)
                        report.escalated_needs_attention_order_ids.append(oid)
                        report.errors_by_order_id[oid] = "REMOTE_LOCAL_AUTHORIZATION_ID_MISMATCH"
                        continue

                    remote_caps = self._extract_capture_objects_from_order_response(remote_order)
                    if len(remote_caps) > 1:
                        self.state_engine.update_order_resolution(oid, "NEEDS_ATTENTION", now=current_time)
                        report.escalated_needs_attention_order_ids.append(oid)
                        report.errors_by_order_id[oid] = "MULTIPLE_REMOTE_CAPTURES_OUTSIDE_MVP"
                        continue

                    if len(remote_caps) == 1 and eff_auth_id:
                        remote_cap = remote_caps[0]
                        remote_cap_id = str(remote_cap.get("id") or "").strip()
                        remote_cap_status = str(remote_cap.get("status") or "").strip().upper()
                        remote_amount = remote_cap.get("amount")
                        evidence_valid = bool(remote_cap_id and remote_cap_status in ("COMPLETED", "PENDING"))
                        if not isinstance(remote_amount, dict) or not remote_amount.get("value") or not remote_amount.get("currency_code"):
                            evidence_valid = False
                        else:
                            remote_currency = str(remote_amount.get("currency_code") or "").strip().upper()
                            try:
                                evidence_valid = evidence_valid and remote_currency == ord_rec.currency.strip().upper()
                                evidence_valid = evidence_valid and _normalize_amount(remote_amount.get("value"), remote_currency) == _normalize_amount(ord_rec.amount, ord_rec.currency)
                            except (TypeError, ValueError):
                                evidence_valid = False
                        if not evidence_valid:
                            self.state_engine.update_order_resolution(oid, "NEEDS_ATTENTION", now=current_time)
                            report.escalated_needs_attention_order_ids.append(oid)
                            report.errors_by_order_id[oid] = "REMOTE_CAPTURE_EVIDENCE_INCOMPLETE_OR_MISMATCHED"
                            continue

                        target_resolution = "CAPTURED" if remote_cap_status == "COMPLETED" else "NEEDS_ATTENTION"
                        self._register_completed_capture(
                            order_id=oid,
                            authorization_id=eff_auth_id,
                            capture_id=remote_cap_id,
                            resolution_status=target_resolution,
                            now=current_time,
                        )
                        with self._lock:
                            for op in self._operations.values():
                                if (
                                    op.order_id == oid
                                    and op.operation_type == "CAPTURE"
                                    and op.status in ("IN_FLIGHT", "RECONCILIATION_REQUIRED")
                                ):
                                    op.status = "SUCCEEDED"
                                    op.capture_id = remote_cap_id
                                    op.provider_status = remote_cap_status
                                    op.updated_at = current_time
                                    self._persist_operation_locked(op)
                        if remote_cap_status == "COMPLETED":
                            report.resolved_captured_order_ids.append(oid)
                        else:
                            report.pending_capture_order_ids.append(oid)
                        continue

                    if eff_auth_id and not r_auth_status:
                        try:
                            auth_obj = self.paypal_client.get_authorization(eff_auth_id)
                            r_auth_status = str(auth_obj.get("status") or "").strip().upper() or None
                        except PayPalError:
                            pass

                    if r_auth_status in ("VOIDED", "EXPIRED"):
                        self.state_engine.update_order_resolution(oid, "VOIDED", now=current_time)
                        report.resolved_voided_order_ids.append(oid)
                        continue

                    # Authorization is still CREATED (or never authorized and not APPROVED):
                    # Reset only stuck CAPTURE (or unverified AUTHORIZE) ops in RECONCILIATION_REQUIRED to FAILED
                    with self._lock:
                        for op_key in list(self._operations.keys()):
                            op = self._operations[op_key]
                            if op.order_id == oid and op.status == "RECONCILIATION_REQUIRED":
                                # A single order snapshot cannot prove a prior mutation was not accepted.
                                # Keep the operation fenced for a later authoritative reconciliation.
                                continue

                    self.state_engine.update_order_resolution(oid, "NEEDS_ATTENTION", now=current_time)
                    report.escalated_needs_attention_order_ids.append(oid)
                except Exception as exc:
                    report.errors_by_order_id[oid] = sanitize_dashboard_summary(str(exc))

        return report

    def start_reconciliation_scheduler(
        self,
        interval_seconds: float = 60.0,
        older_than_seconds: float = 60.0,
    ) -> None:
        """Starts a daemon background thread running `reconcile_stuck_holds()` every `interval_seconds`."""
        with self._lock:
            if self._sweep_thread is not None and self._sweep_thread.is_alive():
                return
            stop_evt = threading.Event()
            self._sweep_stop_event = stop_evt

            def _loop() -> None:
                while not stop_evt.wait(timeout=max(1.0, interval_seconds)):
                    try:
                        self.reconcile_stuck_holds(older_than_seconds=older_than_seconds)
                    except Exception:
                        pass

            t = threading.Thread(
                target=_loop,
                name="paypal-shield-reconcile-sweep",
                daemon=True,
            )
            self._sweep_thread = t
            t.start()

    def stop_reconciliation_scheduler(self) -> None:
        with self._lock:
            if self._sweep_stop_event is not None:
                self._sweep_stop_event.set()
            self._sweep_thread = None

    # ------------------------------------------------------------------
    # Merchant 1-Tap Kill Switch: Void, Scoped Bulk Void, Manual Capture
    # ------------------------------------------------------------------
    def void_authorization(
        self,
        authorization_id: str,
        *,
        merchant_actor: str = "merchant_dashboard",
        reason: str = "Merchant voided flagged authorization hold",
        now: Optional[float] = None,
    ) -> VoidOutcome:
        current_time = now if now is not None else time.time()
        clean_auth = (authorization_id or "").strip()
        if not clean_auth:
            raise ValueError("authorization_id is required.")

        order_rec = self.state_engine.get_order_by_auth_id(clean_auth)
        if order_rec is None:
            raise ValueError(f"No order found in StateEngine for authorization_id '{clean_auth}'.")

        order_lock = self._get_order_lock(order_rec.order_id)
        with order_lock:
            order_rec = self.state_engine.get_order(order_rec.order_id) or order_rec
            if order_rec.resolution_status == "VOIDED":
                return VoidOutcome(
                    order_id=order_rec.order_id,
                    authorization_id=clean_auth,
                    status="VOIDED",
                    incident_id=order_rec.incident_id,
                    estimated_fee_saved_usd=estimate_paypal_fee_saved_usd(order_rec.amount, order_rec.currency),
                    merchant_actor=merchant_actor,
                    reason=reason,
                )

            if order_rec.resolution_status not in ("AUTHORIZED_HOLD", "NEEDS_ATTENTION"):
                raise PermissionError(
                    f"Cannot void authorization '{clean_auth}' on order '{order_rec.order_id}' "
                    f"while in status '{order_rec.resolution_status}'."
                )

            try:
                self.paypal_client.void_authorization(
                    authorization_id=clean_auth,
                    paypal_request_id=f"void-{clean_auth}"[:MAX_PAYPAL_REQUEST_ID_LENGTH],
                )
            except PayPalAPIError as exc:
                # Should-Fix #3g: On any 400/409/422 from void, also query get_authorization
                # and trust PayPal's authoritative status if it is already VOIDED.
                already_voided = exc.issue in ("AUTHORIZATION_ALREADY_VOIDED", "PREVIOUSLY_VOIDED")
                if not already_voided and exc.status_code in (400, 409, 422):
                    try:
                        remote_auth = self.paypal_client.get_authorization(clean_auth)
                        if str(remote_auth.get("status") or "").strip().upper() == "VOIDED":
                            already_voided = True
                    except PayPalError:
                        pass
                if not already_voided:
                    self.state_engine.update_order_resolution(
                        order_rec.order_id,
                        "NEEDS_ATTENTION",
                        now=current_time,
                        manual_override_actor=merchant_actor,
                        manual_override_reason=sanitize_dashboard_summary(
                            f"VOID_FAILED:{exc.issue or exc.error_name}"
                        ),
                    )
                    raise
            except (PayPalAmbiguousNetworkError, PayPalAuthError):
                self.state_engine.update_order_resolution(
                    order_rec.order_id,
                    "NEEDS_ATTENTION",
                    now=current_time,
                    manual_override_actor=merchant_actor,
                    manual_override_reason="VOID_NETWORK_OR_AUTH_ERROR",
                )
                raise

            self.state_engine.update_order_resolution(
                order_rec.order_id,
                "VOIDED",
                now=current_time,
                manual_override_actor=merchant_actor,
                manual_override_reason=reason,
            )
            fee_saved = estimate_paypal_fee_saved_usd(order_rec.amount, order_rec.currency)
            return VoidOutcome(
                order_id=order_rec.order_id,
                authorization_id=clean_auth,
                status="VOIDED",
                incident_id=order_rec.incident_id,
                estimated_fee_saved_usd=fee_saved,
                merchant_actor=merchant_actor,
                reason=reason,
            )

    def bulk_void_incident_holds(
        self,
        incident_id: str,
        *,
        merchant_actor: str = "merchant_dashboard",
        reason: str = "Scoped bulk void of incident loop holds",
        now: Optional[float] = None,
    ) -> BulkVoidOutcome:
        """
        SOP Scoped Bulk Void Rule:
        Voids ONLY eligible holds (`AUTHORIZED_HOLD` where `pillar2_classification != 'LEGITIMATE_REPEAT_BUYER'`)
        belonging to `incident_id` via `state_engine.get_active_holds(incident_id=..., voidable_only=True)`.
        Never touches orders in `ANALYZING_HOLD`, `NEEDS_ATTENTION`, `AUTO_CAPTURING`, `CAPTURED`, or
        other incidents, and catches per-order void errors so one failed order never stops the batch.
        """
        current_time = now if now is not None else time.time()
        clean_inc = (incident_id or "").strip()
        if not clean_inc:
            raise ValueError("incident_id is required for bulk_void_incident_holds.")

        all_incident_holds = self.state_engine.get_active_holds(
            incident_id=clean_inc,
            voidable_only=False,
        )
        voidable_holds = self.state_engine.get_active_holds(
            incident_id=clean_inc,
            voidable_only=True,
        )
        voidable_ids = {o.order_id for o in voidable_holds}
        skipped_ids = [o.order_id for o in all_incident_holds if o.order_id not in voidable_ids]

        outcome = BulkVoidOutcome(
            incident_id=clean_inc,
            skipped_order_ids=skipped_ids,
        )

        for hold_order in voidable_holds:
            if not hold_order.authorization_id:
                outcome.skipped_order_ids.append(hold_order.order_id)
                continue
            try:
                void_res = self.void_authorization(
                    authorization_id=hold_order.authorization_id,
                    merchant_actor=merchant_actor,
                    reason=reason,
                    now=current_time,
                )
                outcome.voided_orders.append(void_res)
                outcome.total_estimated_fee_saved_usd = round(
                    outcome.total_estimated_fee_saved_usd + void_res.estimated_fee_saved_usd,
                    2,
                )
            except Exception as exc:
                outcome.failed_orders[hold_order.order_id] = sanitize_dashboard_summary(str(exc))

        return outcome

    def manual_capture_authorization(
        self,
        authorization_id: str,
        *,
        merchant_actor: str,
        override_reason: str,
        amount: Optional[str | float | int | Decimal] = None,
        currency: Optional[str] = None,
        final_capture: bool = True,
        invoice_id: Optional[str] = None,
        operation_key: Optional[str] = None,
        paypal_auth_status: Optional[str] = None,
        now: Optional[float] = None,
    ) -> SettlementOutcome:
        """Disabled MVP endpoint retained for backward-compatible route imports."""
        raise PermissionError(
            "MANUAL_CAPTURE_OVERRIDE_DISABLED_IN_MVP: only the guarded automatic full-capture path is enabled."
        )

    def execute_guarded_refund(
        self,
        *,
        capture_id: Optional[str] = None,
        order_id: Optional[str] = None,
        operation_id: Optional[str] = None,
        amount: Optional[str | float | int] = None,
        currency: Optional[str] = None,
        reason: Optional[str] = None,
        caller_source: str = "MERCHANT_OR_MCP",
        now: Optional[float] = None,
    ) -> RefundExecutionOutcome:
        if self.webhook_mutex is None:
            raise RuntimeError("WebhookRefundMutex is required for execute_guarded_refund.")

        start_time = now if now is not None else time.time()
        started_monotonic = time.monotonic()
        reserved, message, operation = self.webhook_mutex.reserve_outbound_refund(
            capture_id=capture_id,
            order_id=order_id,
            operation_id=operation_id,
            amount=amount,
            currency=currency,
            reason=reason,
            state_engine=self.state_engine,
            caller_source=caller_source,
            now=start_time,
        )
        if not reserved or operation is None:
            if "BLOCKED_WEBHOOK_ECHO" in message:
                status = "BLOCKED_WEBHOOK_ECHO"
            elif "ALREADY_SUCCEEDED" in message:
                status = "DUPLICATE_ALREADY_SUCCEEDED"
            elif "PENDING" in message:
                status = "PENDING"
            elif "RECONCILIATION_REQUIRED" in message:
                status = "RECONCILIATION_REQUIRED"
            elif "PROVIDER_REJECTED" in message:
                status = "REJECTED"
            else:
                status = "FAILED"
            return RefundExecutionOutcome(
                allowed=False, status=status, message=message, operation=operation,
                paypal_refund_id=operation.paypal_refund_id if operation else None,
            )

        completion_time = lambda: start_time + max(0.0, time.monotonic() - started_monotonic)

        def complete_refund_safely(**kwargs: Any) -> OutboundRefundOperation:
            try:
                return self.webhook_mutex.complete_outbound_refund(**kwargs)
            except ValueError:
                # P1 may have expired/reclaimed the lease and invalidated this claim token.
                # Preserve that RECONCILIATION_REQUIRED state rather than turning it into an exception.
                current = self.webhook_mutex.get_outbound_operation(operation.operation_id)
                if current is not None and current.status == "RECONCILIATION_REQUIRED":
                    return current
                raise

        if not operation.capture_id:
            # This is an invariant failure before POST. P1 currently has no distinct
            # PRE_SUBMISSION_FAILED state, so retain the capture reservation for review.
            completed = complete_refund_safely(
                operation_id=operation.operation_id,
                outcome="RECONCILIATION_REQUIRED",
                claim_token=operation.claim_token,
                now=completion_time(),
            )
            return RefundExecutionOutcome(False, "RECONCILIATION_REQUIRED", "UNRESOLVED_CAPTURE_ID_FOR_REFUND", completed)

        payload: Dict[str, Any] = {}
        if operation.amount is not None and operation.currency is not None:
            payload["amount"] = {"currency_code": operation.currency, "value": operation.amount}
        if reason and reason.strip():
            payload["note_to_payer"] = reason.strip()

        try:
            response = self.paypal_client.refund_capture(
                capture_id=operation.capture_id,
                paypal_request_id=operation.paypal_request_id,
                payload=payload,
            )
            refund_id = str(response.get("id") or "").strip() or None
            provider_status = str(response.get("status") or "").strip().upper() or None
            status_map = {
                "COMPLETED": "SUCCEEDED",
                "SUCCEEDED": "SUCCEEDED",
                "FAILED": "FAILED",
                "CANCELLED": "FAILED",
                "PENDING": "PENDING",
            }
            internal_status = status_map.get(provider_status or "")

            if not refund_id or internal_status is None:
                completed = complete_refund_safely(
                    operation_id=operation.operation_id,
                    outcome="RECONCILIATION_REQUIRED",
                    claim_token=operation.claim_token,
                    paypal_refund_id=refund_id,
                    # P1 rejects unknown provider strings. Preserve the ID, reconcile via GET later.
                    now=completion_time(),
                )
                return RefundExecutionOutcome(
                    False, "RECONCILIATION_REQUIRED",
                    "REFUND_RESPONSE_MISSING_REFUND_ID_OR_SUPPORTED_STATUS", completed, refund_id,
                )

            completed = complete_refund_safely(
                operation_id=operation.operation_id,
                outcome=internal_status,
                claim_token=operation.claim_token,
                paypal_refund_id=refund_id,
                provider_status=provider_status,
                now=completion_time(),
            )
            if completed.status == "RECONCILIATION_REQUIRED":
                return RefundExecutionOutcome(
                    False, "RECONCILIATION_REQUIRED", "REFUND_COMPLETION_LEASE_EXPIRED_RECONCILE_FIRST",
                    completed, refund_id,
                )
            allowed = completed.status in ("SUCCEEDED", "PENDING")
            return RefundExecutionOutcome(
                allowed, completed.status, "OUTBOUND_REFUND_PROVIDER_RESULT_RECORDED", completed, refund_id
            )

        except PayPalAuthError as exc:
            # PayPalSandboxClient raises this before transmitting the refund POST.
            # P1 records NOT_SUBMITTED and permits a safe retry under the same logical
            # operation and PayPal request ID; no refund resource is claimed to exist.
            completed = complete_refund_safely(
                operation_id=operation.operation_id,
                outcome="NOT_SUBMITTED",
                claim_token=operation.claim_token,
                provider_submission_confirmed_absent=True,
                now=completion_time(),
            )
            if completed.status == "RECONCILIATION_REQUIRED":
                return RefundExecutionOutcome(
                    False, "RECONCILIATION_REQUIRED", "REFUND_PRE_SUBMISSION_CLAIM_EXPIRED_RECONCILE_FIRST", completed
                )
            return RefundExecutionOutcome(
                False, "NOT_SUBMITTED", sanitize_dashboard_summary(f"PAYPAL_REFUND_OAUTH_ERROR_BEFORE_SUBMISSION:{exc}"), completed
            )
        except PayPalAmbiguousNetworkError as exc:
            completed = complete_refund_safely(
                operation_id=operation.operation_id,
                outcome="RECONCILIATION_REQUIRED",
                claim_token=operation.claim_token,
                now=completion_time(),
            )
            return RefundExecutionOutcome(
                False, "RECONCILIATION_REQUIRED", sanitize_dashboard_summary(f"AMBIGUOUS_REFUND_OUTCOME:{exc}"), completed
            )
        except PayPalAPIError as exc:
            # PayPal's CAPTURE_FULLY_REFUNDED means a refund already exists (possibly from
            # an earlier attempt); locate and verify that exact refund before resolving.
            # Other HTTP 4xx responses are deterministic provider rejections, not ambiguous
            # network outcomes. Mark them REJECTED instead of leaving a permanent
            # RECONCILIATION_REQUIRED operation with no possible refund resource to find.
            issues = {
                str(value).strip().upper()
                for value in (getattr(exc, "issues", None) or [getattr(exc, "issue", None)])
                if value and str(value).strip()
            }
            issue_code = (
                sorted(issues)[0] if issues
                else str(exc.error_name or "PAYPAL_API_REJECTED").strip().upper()
            )
            if "CAPTURE_FULLY_REFUNDED" in issues:
                completed = complete_refund_safely(
                    operation_id=operation.operation_id,
                    outcome="RECONCILIATION_REQUIRED",
                    claim_token=operation.claim_token,
                    now=completion_time(),
                )
                if completed.status == "RECONCILIATION_REQUIRED":
                    try:
                        return self.reconcile_guarded_refund(
                            operation.operation_id, now=completion_time()
                        )
                    except (PayPalError, ValueError) as reconcile_exc:
                        return RefundExecutionOutcome(
                            False, "RECONCILIATION_REQUIRED",
                            sanitize_dashboard_summary(
                                f"CAPTURE_ALREADY_REFUNDED_BUT_LOOKUP_INCOMPLETE:{reconcile_exc}"
                            ),
                            completed,
                        )
                return RefundExecutionOutcome(
                    False, completed.status, "REFUND_ERROR_CLAIM_EXPIRED_RECONCILE_FIRST", completed
                )

            completed = complete_refund_safely(
                operation_id=operation.operation_id,
                outcome="REJECTED",
                claim_token=operation.claim_token,
                provider_error_code=issue_code,
                provider_http_status=int(exc.status_code),
                provider_debug_id=getattr(exc, "debug_id", None),
                now=completion_time(),
            )
            if completed.status == "RECONCILIATION_REQUIRED":
                return RefundExecutionOutcome(
                    False, "RECONCILIATION_REQUIRED",
                    "REFUND_REJECTION_CLAIM_EXPIRED_RECONCILE_FIRST", completed,
                )
            return RefundExecutionOutcome(
                False, "REJECTED",
                sanitize_dashboard_summary(
                    f"PAYPAL_REFUND_REJECTED:{issue_code}:HTTP_{exc.status_code}:DEBUG_{getattr(exc, 'debug_id', None) or 'UNAVAILABLE'}"
                ),
                completed,
            )

    def reconcile_guarded_refund(
        self,
        operation_id: str,
        *,
        now: Optional[float] = None,
    ) -> RefundExecutionOutcome:
        """Resolve a pending/ambiguous refund only after a fresh PayPal refund-resource GET."""
        if self.webhook_mutex is None:
            raise RuntimeError("WebhookRefundMutex is required for refund reconciliation.")
        operation = self.webhook_mutex.get_outbound_operation(operation_id)
        if operation is None:
            raise ValueError(f"Unknown outbound refund operation '{operation_id}'.")
        if operation.status not in ("PENDING", "RECONCILIATION_REQUIRED"):
            return RefundExecutionOutcome(
                False, operation.status, "REFUND_OPERATION_DOES_NOT_REQUIRE_RECONCILIATION",
                operation, operation.paypal_refund_id,
            )

        refund_id = operation.paypal_refund_id
        order_collection_proves_single_capture = False
        if not refund_id:
            # Orders v2 represents refunds at purchase_units[].payments.refunds[],
            # alongside captures[] (not nested under an individual capture). The MVP
            # allows exactly one purchase unit and one full capture per order. Use that
            # constraint to bind the sole refund candidate to this exact capture when the
            # compact refund representation does not carry its own HATEOAS `up` link.
            remote_order = self.paypal_client.get_order(operation.order_id)
            purchase_units = remote_order.get("purchase_units") or []
            if not isinstance(purchase_units, list) or len(purchase_units) != 1:
                return RefundExecutionOutcome(
                    False, "RECONCILIATION_REQUIRED",
                    "REFUND_ORDER_RESOURCE_HAS_UNSUPPORTED_PURCHASE_UNIT_SHAPE",
                    operation, None,
                )

            purchase_unit = purchase_units[0]
            if not isinstance(purchase_unit, dict):
                return RefundExecutionOutcome(
                    False, "RECONCILIATION_REQUIRED",
                    "REFUND_ORDER_RESOURCE_PURCHASE_UNIT_MALFORMED",
                    operation, None,
                )
            payments = purchase_unit.get("payments") or {}
            if not isinstance(payments, dict):
                return RefundExecutionOutcome(
                    False, "RECONCILIATION_REQUIRED",
                    "REFUND_ORDER_RESOURCE_PAYMENTS_MALFORMED",
                    operation, None,
                )
            captures = payments.get("captures") or []
            refunds = payments.get("refunds") or []
            if not isinstance(captures, list) or not isinstance(refunds, list):
                return RefundExecutionOutcome(
                    False, "RECONCILIATION_REQUIRED",
                    "REFUND_ORDER_RESOURCE_PAYMENT_COLLECTION_MALFORMED",
                    operation, None,
                )

            # Do not infer the relationship from `one matching capture` if there are
            # other captures in the same purchase unit. The frozen MVP supports exactly
            # one capture, so the entire remote capture collection must agree.
            matching_captures = [
                capture for capture in captures
                if isinstance(capture, dict)
                and str(capture.get("id") or "").strip() == operation.capture_id
            ]
            refund_candidates = [
                refund for refund in refunds
                if isinstance(refund, dict) and str(refund.get("id") or "").strip()
            ]
            if len(captures) != 1 or len(matching_captures) != 1 or len(refund_candidates) != 1:
                return RefundExecutionOutcome(
                    False, "RECONCILIATION_REQUIRED",
                    "REFUND_ID_NOT_UNAMBIGUOUSLY_PRESENT_IN_ORDER_RESOURCE",
                    operation, None,
                )

            refund_id = str(refund_candidates[0]["id"]).strip()
            order_collection_proves_single_capture = True

        refund_resource = self.paypal_client.get_refund(refund_id)
        response_id = str(refund_resource.get("id") or "").strip()
        provider_status = str(refund_resource.get("status") or "").strip().upper()
        amount_obj = refund_resource.get("amount") or {}
        refund_amount = str(amount_obj.get("value") or "").strip()
        refund_currency = str(amount_obj.get("currency_code") or "").strip().upper()
        links = refund_resource.get("links") or []
        up_relation_seen = False
        up_capture_ids: List[str] = []
        if isinstance(links, list):
            for link in links:
                if not isinstance(link, dict) or str(link.get("rel") or "").lower() != "up":
                    continue
                up_relation_seen = True
                href = str(link.get("href") or "").strip()
                match = re.search(r"/v2/payments/captures/([^/?#]+)(?:[?#].*)?$", href, re.IGNORECASE)
                if match:
                    up_capture_ids.append(match.group(1))

        # When PayPal supplies an `up` link, it is authoritative and must identify the
        # exact capture. Some compact/fake refund representations omit that optional
        # link; in that case, accept the relationship only when the freshly fetched
        # Orders v2 collection proves the MVP's unique purchase-unit/capture/refund
        # structure. Missing link + ambiguous order structure remains fail-closed.
        if up_relation_seen:
            capture_relationship_verified = up_capture_ids == [operation.capture_id]
        else:
            capture_relationship_verified = order_collection_proves_single_capture or bool(
                operation.paypal_refund_id and refund_id == operation.paypal_refund_id
            )
        # Validate the exact refund ID, status, amount and currency before the local
        # operation is allowed to leave reconciliation.
        try:
            normalized_expected = _normalize_amount(
                Decimal(str(operation.amount)), operation.currency
            )
            normalized_actual = _normalize_amount(
                Decimal(refund_amount), refund_currency
            )
        except Exception:
            normalized_expected = None
            normalized_actual = None
        if (
            response_id != refund_id
            or provider_status not in ("COMPLETED", "SUCCEEDED", "FAILED", "CANCELLED", "PENDING")
            or not capture_relationship_verified
            or normalized_expected is None
            or normalized_actual != normalized_expected
            or refund_currency != operation.currency
        ):
            return RefundExecutionOutcome(
                False, "RECONCILIATION_REQUIRED",
                "PAYPAL_REFUND_LOOKUP_RETURNED_INCOMPLETE_OR_MISMATCHED_EVIDENCE",
                operation, refund_id,
            )
        resolved = "SUCCEEDED" if provider_status in ("COMPLETED", "SUCCEEDED") else ("FAILED" if provider_status in ("FAILED", "CANCELLED") else "PENDING")
        completed = self.webhook_mutex.resolve_reconciliation_required_refund(
            operation_id=operation.operation_id,
            resolved_outcome=resolved,
            provider_status=provider_status,
            paypal_refund_id=refund_id,
            now=now if now is not None else time.time(),
        )
        return RefundExecutionOutcome(
            resolved in ("SUCCEEDED", "PENDING"), completed.status,
            "REFUND_RECONCILIATION_CONFIRMED_BY_PAYPAL", completed, refund_id,
        )

