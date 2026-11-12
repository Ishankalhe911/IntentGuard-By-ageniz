"""
Phase 2 (File 1/3): Deterministic Velocity & Identity State Engine
Location: src/pillar1_velocity_engine/state_engine.py

Audited Implementation (All 6 P0 + 6 P1 + Round 2 Hardening):
- P0 #1 (Sticky Hard-Hold Eligibility):
  - Once `OrderRecord.can_auto_capture_if_llm_approves` is `False`, no downstream call
    (`check_and_record_order`, `enrich_order_payer`, `set_order_auto_capture_eligibility`) can
    ever flip it back to `True`.
  - Clean first-order fast path sets `can_auto_capture_if_llm_approves = has_reliable_identity and (not is_hard_hold_category)`.
- P0 #5 (Verified PayPal Authorization Status Required):
  - `validate_order_ready_for_capture()` requires a non-empty `paypal_auth_status` and an
    explicit `paypal_auth_status_verified=True` assertion from the server-side PayPal lookup.
  - Enforces one full capture per authorization; partial captures are disabled by default.
  - Manual capture override is disabled by default (`allow_manual_override=False`).
- P1 #3 (Buyer Identity Integrity):
  - `enrich_order_payer()` populates missing (`None`) identity fields only and raises `ValueError`
    if an incoming strong identity (`payer_id`, `payer_email`, `customer_id`) conflicts with an
    existing value on the `OrderRecord`.
- P1 #4 (Strict Cart Quantity Fingerprint Validation):
  - `compute_cart_fingerprint_details()` rejects invalid/non-positive item quantities by returning
    `(None, False)` (`cart_fingerprint_complete=False`) instead of silently coercing to `1`.
- P1 #5 (Retry Markers Included in Repeat-Order Auto-Capture Eligibility):
  - `check_and_record_order()` includes `(not has_retry_marker_signal)` and
    `(not has_mutation_vs_anchor)` in `can_auto_capture`.
- P1 #6 & Order-Existence Checks:
  - `load_catalog_families()`, `register_sku_family()`, and `register_sku_family_prefix()` reject
    conflicting family mappings with `ValueError`.
  - `register_capture()` and `mark_order_authorized()` verify that `order_id` exists in
    `_orders_by_id` before updating `_capture_to_order_id` or `_auth_to_order_id`.
"""

from __future__ import annotations

import copy
from dataclasses import asdict, dataclass, field
from decimal import Decimal, InvalidOperation
import difflib
import hashlib
import json
import math
import re
import sqlite3
import threading
import time
from typing import Any, Dict, FrozenSet, Iterable, List, Optional, Set, Tuple


DEFAULT_VELOCITY_WINDOW_SECONDS = 900  # 15 minutes
DEFAULT_WEBHOOK_EVENT_TTL_SECONDS = 345600  # 96 hours
DEFAULT_WEBHOOK_INFLIGHT_TIMEOUT_SECONDS = 60  # 60s crash recovery lease
MIN_HUMAN_GAP_SECONDS = 30.0  # < 30s between repeat orders = machine speed
MAX_FUTURE_CLOCK_SKEW_SECONDS = 300.0  # 5 minutes max future clock skew

NON_STACKABLE_CATEGORIES: FrozenSet[str] = frozenset({
    "single_seat_saas",
    "non_stackable_license",
    "digital_license",
    "subscription",
})

STACKABLE_CATEGORIES: FrozenSet[str] = frozenset({
    "physical_good",
    "stackable_good",
    "consumable",
    "apparel",
    "merchandise",
    "standard",
})

VALID_SKU_CATEGORIES: FrozenSet[str] = NON_STACKABLE_CATEGORIES | STACKABLE_CATEGORIES | frozenset({"untagged"})

SKU_CATEGORY_SYNONYMS: Dict[str, str] = {
    "saas": "single_seat_saas",
    "saas_license": "single_seat_saas",
    "saas_seat": "single_seat_saas",
    "single_seat": "single_seat_saas",
    "single_seat_license": "single_seat_saas",
    "non_stackable": "non_stackable_license",
    "nonstackable": "non_stackable_license",
    "nonstackable_license": "non_stackable_license",
    "license": "digital_license",
    "software_license": "digital_license",
    "digital_subscription": "subscription",
    "pro_subscription": "subscription",
    "annual_subscription": "subscription",
    "stackable": "stackable_good",
    "physical": "physical_good",
    "physical_repeatable": "physical_good",
    "repeatable_physical": "physical_good",
    "retail": "stackable_good",
    "general": "standard",
    "default": "untagged",
    "none": "untagged",
}

PAYPAL_SUPPORTED_CURRENCIES: FrozenSet[str] = frozenset({
    "AUD", "BRL", "CAD", "CHF", "CNY", "CZK", "DKK", "EUR", "GBP",
    "HKD", "HUF", "ILS", "JPY", "MXN", "MYR", "NOK", "NZD", "PHP",
    "PLN", "RUB", "SEK", "SGD", "THB", "TWD", "USD",
})

ZERO_DECIMAL_CURRENCIES: FrozenSet[str] = frozenset({"HUF", "JPY", "TWD"})

TERMINAL_ORDER_STATUSES: FrozenSet[str] = frozenset({"CAPTURED", "VOIDED", "PARTIALLY_CAPTURED"})

ALLOWED_STATUS_TRANSITIONS: Dict[str, FrozenSet[str]] = {
    "APPROVED_PENDING_SETTLEMENT": frozenset({
        "APPROVED_PENDING_SETTLEMENT",
        "ANALYZING_HOLD",
        "AUTHORIZED_HOLD",
        "AUTO_CAPTURING",
        "CAPTURED",
        "VOIDED",
        "NEEDS_ATTENTION",
    }),
    "ANALYZING_HOLD": frozenset({
        "ANALYZING_HOLD",
        "AUTHORIZED_HOLD",
        "AUTO_CAPTURING",
        "CAPTURED",
        "VOIDED",
        "NEEDS_ATTENTION",
    }),
    "AUTHORIZED_HOLD": frozenset({
        "AUTHORIZED_HOLD",
        "AUTO_CAPTURING",
        "CAPTURED",
        "VOIDED",
        "NEEDS_ATTENTION",
    }),
    "AUTO_CAPTURING": frozenset({
        "AUTO_CAPTURING",
        "CAPTURED",
        "NEEDS_ATTENTION",
        "AUTHORIZED_HOLD",
    }),
    "NEEDS_ATTENTION": frozenset({
        "NEEDS_ATTENTION",
        "ANALYZING_HOLD",
        "AUTHORIZED_HOLD",
        "AUTO_CAPTURING",
        "CAPTURED",
        "VOIDED",
    }),
    # Legacy partial-capture records are read-only in the one-full-capture MVP.
    "PARTIALLY_CAPTURED": frozenset({"PARTIALLY_CAPTURED"}),
    "CAPTURED": frozenset({"CAPTURED"}),
    "VOIDED": frozenset({"VOIDED"}),
}


def _validated_event_time(now: Optional[float], field_name: str = "now") -> float:
    if now is None:
        return time.time()
    if isinstance(now, bool) or not isinstance(now, (int, float)) or not math.isfinite(float(now)):
        raise ValueError(f"{field_name} must be a finite Unix timestamp.")
    return float(now)


def can_transition_order_status(current_status: str, target_status: str) -> bool:
    if not isinstance(current_status, str) or not current_status.strip():
        return False
    cur = current_status.strip().upper()
    tgt = (target_status or "").strip().upper()
    if cur in TERMINAL_ORDER_STATUSES and tgt != cur:
        return False
    # Fail closed for unknown current states; an unrecognized state must never
    # advance to a financial terminal state by default.
    allowed = ALLOWED_STATUS_TRANSITIONS.get(cur)
    if allowed is None:
        return False
    return tgt in allowed


RETRY_MUTATION_PATTERN = re.compile(
    r"(?<![A-Za-z])(retry|retried|attempt|re-?order|dup|duplicate)(?![A-Za-z])",
    re.IGNORECASE,
)

PROMPT_INJECTION_PATTERN = re.compile(
    r"(ignore\s+(?:(?:all|previous|prior)\s+){0,3}(instructions|rules|prompts)|"
    r"system\s*(prompt|override|:)|"
    r"create_refund|accept_dispute_claim|void_authorization|"
    r"<\s*(system|admin|instruction|override)\b|"
    r"do\s+not\s+hold|auto[_\-\s]*approve|bypass\s+(security|firewall|check))",
    re.IGNORECASE,
)

NUMERIC_OR_VERSION_SUFFIX_RE = re.compile(r"^(v?\d+|#\d+)$", re.IGNORECASE)

_STRENGTH_RANK = {"STRONG": 3, "CONTEXTUAL": 2, "WEAK": 1, "NONE": 0}


def normalize_sku_category(raw_category: Optional[str]) -> str:
    if raw_category is None or not str(raw_category).strip():
        return "untagged"
    cleaned = re.sub(r"[\s\-]+", "_", str(raw_category).strip().lower()).strip("_")
    if not cleaned:
        return "untagged"
    canonical = SKU_CATEGORY_SYNONYMS.get(cleaned, cleaned)
    if canonical in VALID_SKU_CATEGORIES:
        return canonical

    all_known = sorted(VALID_SKU_CATEGORIES | set(SKU_CATEGORY_SYNONYMS.keys()))
    suggestions = difflib.get_close_matches(cleaned, all_known, n=2, cutoff=0.6)
    hint = f" Did you mean '{suggestions[0]}'?" if suggestions else ""
    raise ValueError(
        f"Unknown sku_category '{raw_category}' (normalized: '{cleaned}').{hint} "
        f"Valid categories: {sorted(VALID_SKU_CATEGORIES)}."
    )


def are_sku_categories_compatible(existing_cat: str, incoming_cat: str) -> bool:
    norm_existing = normalize_sku_category(existing_cat)
    norm_incoming = normalize_sku_category(incoming_cat)
    if norm_existing == norm_incoming:
        return True
    if norm_existing == "untagged":
        return True
    if norm_incoming == "untagged":
        return False
    if norm_existing in NON_STACKABLE_CATEGORIES and norm_incoming in NON_STACKABLE_CATEGORIES:
        return True
    if norm_existing in STACKABLE_CATEGORIES and norm_incoming in STACKABLE_CATEGORIES:
        return True
    return False


def validate_financial_amount(
    amount: str | float | int | Decimal,
    currency: str = "USD",
    *,
    allow_zero: bool = False,
    allowed_currencies: Optional[Iterable[str]] = None,
) -> Decimal:
    if isinstance(amount, bool) or amount is None:
        raise ValueError(f"Invalid financial amount: {amount!r}")
    norm_curr = (currency or "").strip().upper()
    valid_set = set(allowed_currencies) if allowed_currencies is not None else PAYPAL_SUPPORTED_CURRENCIES
    if not norm_curr or norm_curr not in valid_set:
        raise ValueError(f"Unsupported or invalid PayPal currency code '{currency}'.")

    raw_str = str(amount).strip()
    if not raw_str:
        raise ValueError("Financial amount cannot be empty.")
    try:
        dec = Decimal(raw_str)
    except InvalidOperation as exc:
        raise ValueError(f"Malformed decimal amount '{amount}'.") from exc

    if not dec.is_finite():
        raise ValueError(f"Non-finite financial amount '{amount}' is not allowed.")
    if allow_zero:
        if dec < Decimal("0"):
            raise ValueError(f"Negative amount '{amount}' is not allowed.")
    else:
        if dec <= Decimal("0"):
            raise ValueError(f"Amount must be strictly positive (got '{amount}').")

    exponent = dec.as_tuple().exponent
    max_decimals = 0 if norm_curr in ZERO_DECIMAL_CURRENCIES else 2
    if isinstance(exponent, int) and (-exponent) > max_decimals:
        if norm_curr in ZERO_DECIMAL_CURRENCIES:
            if dec != dec.to_integral_value():
                raise ValueError(
                    f"Currency '{norm_curr}' does not support decimals (got '{amount}')."
                )
        else:
            raise ValueError(
                f"Currency '{norm_curr}' supports at most 2 decimal places (got '{amount}')."
            )
    return dec


def _normalize_amount(amount: str | float | int | Decimal, currency: str = "USD") -> str:
    norm_curr = (currency or "USD").strip().upper()
    try:
        dec = Decimal(str(amount).strip())
        if norm_curr in ZERO_DECIMAL_CURRENCIES:
            return str(dec.quantize(Decimal("1")))
        return str(dec.quantize(Decimal("0.01")))
    except (InvalidOperation, ValueError, TypeError):
        return str(amount).strip()


def compute_shipping_address_hash(
    shipping_dict: Optional[Dict[str, Any]] = None,
    *,
    recipient_name: Optional[str] = None,
    address_line_1: Optional[str] = None,
    address_line_2: Optional[str] = None,
    admin_area_2: Optional[str] = None,
    admin_area_1: Optional[str] = None,
    postal_code: Optional[str] = None,
    country_code: Optional[str] = None,
    **_kwargs: Any,
) -> Optional[str]:
    if shipping_dict is not None:
        return hash_shipping_address(shipping_dict)
    return hash_shipping_address({
        "name": {"full_name": recipient_name} if recipient_name else {},
        "address": {
            "address_line_1": address_line_1,
            "address_line_2": address_line_2,
            "admin_area_2": admin_area_2,
            "admin_area_1": admin_area_1,
            "postal_code": postal_code,
            "country_code": country_code,
        },
    })


def hash_shipping_address(shipping_dict: Optional[Dict[str, Any]]) -> Optional[str]:
    if not shipping_dict or not isinstance(shipping_dict, dict):
        return None
    address = shipping_dict.get("address")
    if isinstance(address, dict):
        parts = [
            str(address.get("address_line_1") or "").strip().lower(),
            str(address.get("address_line_2") or "").strip().lower(),
            str(address.get("admin_area_2") or "").strip().lower(),
            str(address.get("admin_area_1") or "").strip().lower(),
            str(address.get("postal_code") or "").strip().lower(),
            str(address.get("country_code") or "").strip().lower(),
        ]
    else:
        parts = [
            str(shipping_dict.get("address_line_1") or "").strip().lower(),
            str(shipping_dict.get("postal_code") or "").strip().lower(),
            str(shipping_dict.get("country_code") or "").strip().lower(),
        ]
    joined = "|".join(p for p in parts if p)
    if not joined:
        return None
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()[:16]


def _normalize_catalog_alias(value: Optional[str]) -> str:
    """Normalize a trusted catalogue alias and supplied item text for exact matching only."""
    if value is None:
        return ""
    lowered = str(value).casefold()
    normalized = re.sub(r"[_\W]+", " ", lowered, flags=re.UNICODE)
    return " ".join(normalized.split())


def compute_cart_fingerprint_details(
    sku: Optional[str] = None,
    items: Optional[List[Dict[str, Any]]] = None,
) -> Tuple[Optional[str], bool]:
    """
    P1 #4 Fix: Rejects invalid or non-positive cart quantities (`<= 0`, `bool`, non-numeric)
    by returning `(None, False)` (`cart_fingerprint_complete=False`) instead of silently
    coercing invalid quantities to `1`.
    """
    if items is not None:
        if not isinstance(items, list) or len(items) == 0:
            return None, False
        parts: List[str] = []
        for item in items:
            if not isinstance(item, dict):
                return None, False
            item_sku = str(item.get("sku") or "").strip().upper()
            if not item_sku:
                return None, False
            raw_qty = item.get("quantity", 1)
            if isinstance(raw_qty, bool) or raw_qty is None:
                return None, False
            try:
                qty_str = str(raw_qty).strip()
                if not qty_str:
                    return None, False
                qty = int(qty_str)
            except (ValueError, TypeError):
                return None, False
            if qty <= 0:
                return None, False
            parts.append(f"{item_sku}:{qty}")
        parts.sort()
        return "|".join(parts), True

    if sku and sku.strip():
        return f"{sku.strip().upper()}:1", True
    return None, False


def compute_cart_fingerprint(
    sku: Optional[str] = None,
    items: Optional[List[Dict[str, Any]]] = None,
) -> Optional[str]:
    fp, _ = compute_cart_fingerprint_details(sku=sku, items=items)
    return fp


def _extract_cart_sku_set(cart_fingerprint: Optional[str]) -> Set[str]:
    if not cart_fingerprint:
        return set()
    skus: Set[str] = set()
    for part in cart_fingerprint.split("|"):
        seg = part.strip()
        if not seg:
            continue
        sku_name = seg.rsplit(":", 1)[0].strip().upper()
        if sku_name:
            skus.add(sku_name)
    return skus


def extract_sku_family_and_variant(sku_or_fp: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    if not sku_or_fp:
        return None, None
    clean = sku_or_fp.strip().upper()
    if "|" in clean:
        return None, None
    if ":" in clean:
        clean = clean.rsplit(":", 1)[0].strip()
    tokens = [t for t in re.split(r"[\-_]+", clean) if t]
    if len(tokens) < 2:
        return None, None
    last = tokens[-1]
    if NUMERIC_OR_VERSION_SUFFIX_RE.match(last) or RETRY_MUTATION_PATTERN.search(last):
        return None, None
    family = "-".join(tokens[:-1])
    return family, last


def has_suspicious_sku_or_desc_mutation(
    sku1: str,
    sku2: str,
    desc1: str,
    desc2: str,
) -> bool:
    combined = f"{sku1} {sku2} {desc1} {desc2}"
    if RETRY_MUTATION_PATTERN.search(combined):
        return True
    base1 = re.sub(r"[\-_]?(v?\d+|#\d+)(:\d+)?$", "", sku1.strip().upper(), flags=re.IGNORECASE)
    base2 = re.sub(r"[\-_]?(v?\d+|#\d+)(:\d+)?$", "", sku2.strip().upper(), flags=re.IGNORECASE)
    if base1 and base2 and base1 == base2 and sku1.strip().upper() != sku2.strip().upper():
        return True
    return False


def get_key_strength(key: Optional[str]) -> str:
    return get_identity_key_strength(key)


def get_identity_key_strength(key: Optional[str]) -> str:
    if not key:
        return "NONE"
    if key.startswith(("payer_id:", "email:", "customer_id:")):
        return "STRONG"
    if key.startswith(("custom_id:", "session_id:", "addr_hash:")):
        return "CONTEXTUAL"
    if key.startswith("ip:"):
        return "WEAK"
    return "NONE"


def select_strongest_matched_key(keys: Iterable[str]) -> Tuple[Optional[str], str]:
    best_key: Optional[str] = None
    best_strength = "NONE"
    for k in keys:
        st = get_identity_key_strength(k)
        if _STRENGTH_RANK[st] > _STRENGTH_RANK[best_strength]:
            best_key = k
            best_strength = st
    return best_key, best_strength


def classify_identity_keys(
    payer_id: Optional[str] = None,
    payer_email: Optional[str] = None,
    shipping_address_hash: Optional[str] = None,
    custom_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    session_id: Optional[str] = None,
    client_ip: Optional[str] = None,
) -> Tuple[List[str], bool, str]:
    strong_keys: List[str] = []
    contextual_keys: List[str] = []

    if payer_id and payer_id.strip():
        strong_keys.append(f"payer_id:{payer_id.strip()}")
    if payer_email and payer_email.strip():
        strong_keys.append(f"email:{payer_email.strip().lower()}")
    if customer_id and customer_id.strip():
        strong_keys.append(f"customer_id:{customer_id.strip()}")

    if custom_id and custom_id.strip():
        contextual_keys.append(f"custom_id:{custom_id.strip()}")
    if session_id and session_id.strip():
        contextual_keys.append(f"session_id:{session_id.strip()}")
    if shipping_address_hash and shipping_address_hash.strip():
        contextual_keys.append(f"addr_hash:{shipping_address_hash.strip()}")

    combined = strong_keys + contextual_keys
    if combined:
        overall_strength = "STRONG" if strong_keys else "CONTEXTUAL"
        return combined, False, overall_strength

    if client_ip and client_ip.strip():
        return [f"ip:{client_ip.strip()}"], True, "WEAK"

    return [], False, "NONE"


@dataclass
class WebhookEventClaim:
    event_id: str
    status: str  # "IN_FLIGHT" | "PROCESSED"
    updated_at: float


@dataclass
class OrderRecord:
    order_id: str
    payer_id: Optional[str]
    payer_email: Optional[str]
    shipping_address_hash: Optional[str]
    custom_id: Optional[str]
    sku: Optional[str]
    cart_fingerprint: Optional[str]
    item_name: str
    description: str
    amount: str
    currency: str
    intent: str = "AUTHORIZE"
    timestamp: float = field(default_factory=time.time)
    status_updated_at: float = field(default_factory=time.time)
    captured_at: Optional[float] = None
    customer_id: Optional[str] = None
    session_id: Optional[str] = None
    product_family_id: Optional[str] = None
    cart_family_signature: Optional[str] = None
    cart_fingerprint_complete: bool = False
    note_to_payer: Optional[str] = None
    client_ip: Optional[str] = None
    user_agent: Optional[str] = None
    sku_category: str = "untagged"
    incident_id: Optional[str] = None
    authorization_id: Optional[str] = None
    capture_id: Optional[str] = None
    capture_ids: List[str] = field(default_factory=list)
    resolution_status: str = "APPROVED_PENDING_SETTLEMENT"
    used_ip_fallback: bool = False
    identity_strength: str = "STRONG"
    has_reliable_identity: bool = True
    is_flagged: bool = False
    can_auto_capture_if_llm_approves: bool = True
    pillar2_classification: Optional[str] = None
    deterministic_hold_reason: Optional[str] = None
    manual_override_actor: Optional[str] = None
    manual_override_reason: Optional[str] = None


@dataclass
class VelocityCheckResult:
    is_flagged: bool
    flag_reason: str
    repeat_count: int
    time_delta_seconds: Optional[float]
    matched_identity_key: Optional[str]
    anchor_order: Optional[OrderRecord]
    previous_orders: List[OrderRecord]
    incident_id: Optional[str]
    sku_category: str
    is_hard_hold_category: bool
    address_changed_vs_anchor: bool
    used_ip_fallback: bool
    identity_strength: str
    matched_identity_strength: str
    has_reliable_identity: bool
    can_auto_capture_if_llm_approves: bool
    matched_identity_keys: List[str] = field(default_factory=list)
    variant_match_mode: Optional[str] = None
    # Additive P2 evidence exports. None means the signal was not evaluated by this code path.
    # These fields expose the existing deterministic checks; they do not alter risk decisions.
    has_prompt_injection_signal: Optional[bool] = None
    has_retry_marker_signal: Optional[bool] = None


def validate_order_ready_for_capture(
    order: Optional[OrderRecord],
    decision_allows_capture: bool,
    capture_mode: str = "AUTO",
    paypal_auth_status: Optional[str] = None,
    merchant_actor: Optional[str] = None,
    override_reason: Optional[str] = None,
    *,
    paypal_auth_status_verified: bool = False,
    allow_partial_captures: bool = False,
    allow_manual_override: bool = False,
) -> Tuple[bool, str]:
    """
    MVP capture gate:
    - Requires a caller-attested fresh, server-verified PayPal authorization status.
    - Allows only one full capture per authorization; partial capture mode is explicitly
      rejected in this MVP, even if a caller passes `allow_partial_captures=True`.
    - Manual merchant capture override is disabled by default.
    """
    if order is None:
        return False, "ORDER_NOT_FOUND_IN_LEDGER"
    if allow_partial_captures:
        return False, "PARTIAL_CAPTURES_DISABLED_IN_MVP"
    if (order.intent or "").strip().upper() != "AUTHORIZE":
        return False, f"INVALID_ORDER_INTENT:{order.intent}"
    if not order.authorization_id or not order.authorization_id.strip():
        return False, "MISSING_AUTHORIZATION_ID"

    # P0 #5: Require a fresh, verified PayPal authorization status before any capture
    if paypal_auth_status is None or not str(paypal_auth_status).strip() or paypal_auth_status_verified is not True:
        return False, "MISSING_VERIFIED_PAYPAL_AUTH_STATUS"

    mode = (capture_mode or "AUTO").strip().upper()
    clean_pp_status = str(paypal_auth_status).strip().upper()
    allowed_pp_statuses = ("CREATED",)
    if clean_pp_status not in allowed_pp_statuses:
        return False, f"PAYPAL_AUTHORIZATION_NOT_CAPTURABLE:{clean_pp_status}"

    if order.capture_id or order.capture_ids:
        return False, "ORDER_ALREADY_HAS_CAPTURE_ONE_CAPTURE_PER_AUTH_ONLY"

    if mode == "AUTO":
        if order.resolution_status not in (
            "AUTHORIZED_HOLD",
            "APPROVED_PENDING_SETTLEMENT",
            "ANALYZING_HOLD",
            "AUTO_CAPTURING",
        ):
            return False, f"INVALID_RESOLUTION_STATUS_FOR_AUTO_CAPTURE:{order.resolution_status}"
        if not order.has_reliable_identity or order.identity_strength != "STRONG":
            return False, f"INSUFFICIENT_IDENTITY_STRENGTH_FOR_AUTO_CAPTURE:{order.identity_strength}"
        if not getattr(order, "can_auto_capture_if_llm_approves", True):
            return False, "ORDER_RECORD_HARD_HOLD_FORBIDS_AUTO_CAPTURE"
        if decision_allows_capture is not True:
            return False, "DECISION_FORBIDS_AUTO_CAPTURE"
        return True, "READY_FOR_AUTOMATIC_AUTHORIZATION_CAPTURE"

    if mode == "MANUAL_MERCHANT_OVERRIDE":
        if not allow_manual_override:
            return False, "MANUAL_CAPTURE_OVERRIDE_DISABLED_IN_MVP"
        allowed_res_statuses = ("AUTHORIZED_HOLD", "ANALYZING_HOLD", "NEEDS_ATTENTION")
        if order.resolution_status not in allowed_res_statuses:
            return False, f"INVALID_RESOLUTION_STATUS_FOR_MANUAL_CAPTURE:{order.resolution_status}"
        if not merchant_actor or not merchant_actor.strip():
            return False, "MISSING_MERCHANT_ACTOR_FOR_MANUAL_OVERRIDE"
        if not override_reason or not override_reason.strip():
            return False, "MISSING_OVERRIDE_REASON_FOR_MANUAL_CAPTURE"
        return True, "READY_FOR_MANUAL_MERCHANT_CAPTURE"

    return False, f"UNKNOWN_CAPTURE_MODE:{capture_mode}"


class VelocityStateEngine:
    """
    Deterministic sliding-window velocity & event ledger for Pillar 1.
    """

    def __init__(
        self,
        window_seconds: int = DEFAULT_VELOCITY_WINDOW_SECONDS,
        webhook_ttl_seconds: int = DEFAULT_WEBHOOK_EVENT_TTL_SECONDS,
        min_human_gap_seconds: float = MIN_HUMAN_GAP_SECONDS,
        inflight_webhook_timeout_seconds: int = DEFAULT_WEBHOOK_INFLIGHT_TIMEOUT_SECONDS,
        allow_sku_prefix_heuristic: bool = False,
        webhook_db_path: Optional[str] = None,
        db_path: Optional[str] = None,
        supported_currencies: Optional[Iterable[str]] = None,
    ) -> None:
        self.window_seconds = window_seconds
        self.webhook_ttl_seconds = webhook_ttl_seconds
        self.min_human_gap_seconds = min_human_gap_seconds
        self.inflight_webhook_timeout_seconds = inflight_webhook_timeout_seconds
        self.allow_sku_prefix_heuristic = allow_sku_prefix_heuristic
        self.db_path = db_path or webhook_db_path
        self.webhook_db_path = self.db_path
        self.supported_currencies: FrozenSet[str] = (
            frozenset(c.strip().upper() for c in supported_currencies)
            if supported_currencies is not None
            else PAYPAL_SUPPORTED_CURRENCIES
        )
        self._lock = threading.RLock()

        self._identity_index: Dict[str, List[str]] = {}
        self._order_indexed_keys: Dict[str, Set[str]] = {}
        self._orders_by_id: Dict[str, OrderRecord] = {}
        self._capture_to_order_id: Dict[str, str] = {}
        self._auth_to_order_id: Dict[str, str] = {}
        self._sku_categories: Dict[str, str] = {}
        self._sku_product_families: Dict[str, str] = {}
        self._sku_family_prefixes: Dict[str, str] = {}
        self._webhook_claims: Dict[str, WebhookEventClaim] = {}

        if self.db_path:
            self._init_db()
            self._load_persisted_orders()

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path, timeout=10.0) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS webhook_event_ledger (
                    event_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    updated_at REAL NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS order_records_store (
                    order_id TEXT PRIMARY KEY,
                    record_json TEXT NOT NULL,
                    indexed_keys_json TEXT NOT NULL,
                    timestamp REAL NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS sku_catalog_store (
                    sku TEXT PRIMARY KEY,
                    category TEXT,
                    product_family_id TEXT,
                    updated_at REAL NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS sku_prefix_store (
                    prefix TEXT PRIMARY KEY,
                    product_family_id TEXT NOT NULL,
                    updated_at REAL NOT NULL
                )
                """
            )
            conn.commit()

    def _persist_catalog_sku_locked(self, sku: str) -> None:
        if not self.db_path:
            return
        cat = self._sku_categories.get(sku)
        fam = self._sku_product_families.get(sku)
        with sqlite3.connect(self.db_path, timeout=10.0) as conn:
            conn.execute(
                """
                INSERT INTO sku_catalog_store (sku, category, product_family_id, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(sku) DO UPDATE SET
                    category = COALESCE(excluded.category, sku_catalog_store.category),
                    product_family_id = COALESCE(excluded.product_family_id, sku_catalog_store.product_family_id),
                    updated_at = excluded.updated_at
                """,
                (sku, cat, fam, time.time()),
            )
            conn.commit()

    def _persist_catalog_batch_locked(
        self,
        family_map: Dict[str, str],
        category_map: Dict[str, str],
    ) -> None:
        """Persist one validated catalogue batch in a single SQLite transaction."""
        if not self.db_path:
            return
        all_skus = sorted(set(family_map) | set(category_map))
        now_ts = time.time()
        rows = [
            (
                sku,
                category_map.get(sku, self._sku_categories.get(sku)),
                family_map.get(sku, self._sku_product_families.get(sku)),
                now_ts,
            )
            for sku in all_skus
        ]
        with sqlite3.connect(self.db_path, timeout=10.0) as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.executemany(
                """
                INSERT INTO sku_catalog_store (sku, category, product_family_id, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(sku) DO UPDATE SET
                    category = COALESCE(excluded.category, sku_catalog_store.category),
                    product_family_id = COALESCE(excluded.product_family_id, sku_catalog_store.product_family_id),
                    updated_at = excluded.updated_at
                """,
                rows,
            )
            conn.commit()

    def _persist_catalog_prefix_locked(self, prefix: str, family_id: str) -> None:
        if not self.db_path:
            return
        with sqlite3.connect(self.db_path, timeout=10.0) as conn:
            conn.execute(
                """
                INSERT INTO sku_prefix_store (prefix, product_family_id, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(prefix) DO UPDATE SET
                    product_family_id = excluded.product_family_id,
                    updated_at = excluded.updated_at
                """,
                (prefix, family_id, time.time()),
            )
            conn.commit()

    def _persist_order_locked(
        self,
        record: OrderRecord,
        indexed_keys: Optional[Iterable[str]] = None,
    ) -> None:
        if not self.db_path:
            return
        keys_list = sorted(
            set(indexed_keys)
            if indexed_keys is not None
            else self._order_indexed_keys.get(record.order_id, set())
        )
        with sqlite3.connect(self.db_path, timeout=10.0) as conn:
            conn.execute(
                """
                INSERT INTO order_records_store (order_id, record_json, indexed_keys_json, timestamp)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(order_id) DO UPDATE SET
                    record_json = excluded.record_json,
                    indexed_keys_json = excluded.indexed_keys_json,
                    timestamp = excluded.timestamp
                """,
                (
                    record.order_id,
                    json.dumps(asdict(record)),
                    json.dumps(keys_list),
                    record.timestamp,
                ),
            )
            conn.commit()

    def _delete_persisted_order_locked(self, order_id: str) -> None:
        if not self.db_path:
            return
        with sqlite3.connect(self.db_path, timeout=10.0) as conn:
            conn.execute("DELETE FROM order_records_store WHERE order_id = ?", (order_id,))
            conn.commit()

    def _load_persisted_orders(self) -> None:
        if not self.db_path:
            return
        with self._lock:
            with sqlite3.connect(self.db_path, timeout=10.0) as conn:
                cat_rows = conn.execute(
                    "SELECT sku, category, product_family_id FROM sku_catalog_store"
                ).fetchall()
                prefix_rows = conn.execute(
                    "SELECT prefix, product_family_id FROM sku_prefix_store"
                ).fetchall()
                rows = conn.execute(
                    "SELECT record_json, indexed_keys_json FROM order_records_store ORDER BY timestamp ASC"
                ).fetchall()

            for sku, cat, fam in cat_rows:
                if sku and cat:
                    self._sku_categories[str(sku).strip().upper()] = str(cat).strip()
                if sku and fam:
                    self._sku_product_families[str(sku).strip().upper()] = str(fam).strip().upper()

            for prefix, fam in prefix_rows:
                if prefix and fam:
                    self._sku_family_prefixes[str(prefix).strip().upper()] = str(fam).strip().upper()

            for rec_json, keys_json in rows:
                data = json.loads(rec_json)
                rec = OrderRecord(**data)
                keys = json.loads(keys_json)
                self._replace_order_index(rec, keys, persist=False)
                if rec.authorization_id:
                    self._auth_to_order_id[rec.authorization_id] = rec.order_id
                if rec.capture_id:
                    self._capture_to_order_id[rec.capture_id] = rec.order_id
                for cid in rec.capture_ids:
                    self._capture_to_order_id[cid] = rec.order_id

    def register_sku_category(
        self,
        sku: str,
        category: str,
        product_family_id: Optional[str] = None,
        *,
        allow_downgrade: bool = False,
    ) -> str:
        clean_sku = (sku or "").strip().upper()
        if not clean_sku:
            raise ValueError("sku is required to register a category.")
        norm_cat = normalize_sku_category(category)
        with self._lock:
            existing_cat = self._sku_categories.get(clean_sku)
            if existing_cat and existing_cat != "untagged" and not allow_downgrade:
                if norm_cat == "untagged":
                    norm_cat = existing_cat
                elif existing_cat in NON_STACKABLE_CATEGORIES and norm_cat not in NON_STACKABLE_CATEGORIES:
                    norm_cat = existing_cat

            if product_family_id and product_family_id.strip():
                clean_fam = product_family_id.strip().upper()
                existing_fam = self._sku_product_families.get(clean_sku)
                if existing_fam is not None and existing_fam != clean_fam and not allow_downgrade:
                    raise ValueError(
                        f"Catalog family conflict for SKU '{clean_sku}': existing family "
                        f"'{existing_fam}' != incoming '{clean_fam}'."
                    )
                self._sku_product_families[clean_sku] = clean_fam

            self._sku_categories[clean_sku] = norm_cat
            self._persist_catalog_sku_locked(clean_sku)
            return norm_cat

    def register_sku_family(
        self,
        sku: str,
        product_family_id: str,
        *,
        allow_overwrite: bool = False,
    ) -> str:
        """
        P1 #6 Fix: Rejects conflicting family mappings for an already-registered SKU
        unless `allow_overwrite=True`.
        """
        clean_sku = (sku or "").strip().upper()
        clean_fam = (product_family_id or "").strip().upper()
        if not clean_sku or not clean_fam:
            raise ValueError("Both sku and product_family_id must be non-empty.")
        with self._lock:
            existing_fam = self._sku_product_families.get(clean_sku)
            if existing_fam is not None and existing_fam != clean_fam and not allow_overwrite:
                raise ValueError(
                    f"Catalog family conflict for SKU '{clean_sku}': existing family "
                    f"'{existing_fam}' != incoming '{clean_fam}'."
                )
            self._sku_product_families[clean_sku] = clean_fam
            self._persist_catalog_sku_locked(clean_sku)
            return clean_fam

    def register_sku_family_prefix(
        self,
        prefix: str,
        product_family_id: str,
        *,
        allow_overwrite: bool = False,
    ) -> None:
        """
        P1 #6 Fix: Rejects conflicting prefix-to-family mappings unless `allow_overwrite=True`.
        """
        clean_prefix = (prefix or "").strip().upper()
        clean_family = (product_family_id or "").strip().upper()
        if not clean_prefix or not clean_family:
            raise ValueError("Both prefix and product_family_id must be non-empty.")
        with self._lock:
            existing = self._sku_family_prefixes.get(clean_prefix)
            if existing is not None and existing != clean_family and not allow_overwrite:
                raise ValueError(
                    f"Catalog family prefix conflict for prefix '{clean_prefix}': existing "
                    f"'{existing}' != incoming '{clean_family}'."
                )
            self._sku_family_prefixes[clean_prefix] = clean_family
            self._persist_catalog_prefix_locked(clean_prefix, clean_family)

    def load_catalog_families(
        self,
        family_map: Dict[str, str],
        category_map: Optional[Dict[str, str]] = None,
        *,
        allow_overwrite: bool = False,
    ) -> None:
        """
        Atomically load a trusted merchant catalogue. Conflicting normalized keys or
        existing mappings are rejected unless an explicit administrative overwrite is used.
        """
        validated_families: Dict[str, str] = {}
        for raw_sku, raw_fam in (family_map or {}).items():
            if not isinstance(raw_sku, str) or not raw_sku.strip() or not isinstance(raw_fam, str) or not raw_fam.strip():
                raise ValueError("Every catalogue family entry requires non-empty string SKU and family ID.")
            sku_key, family_value = raw_sku.strip().upper(), raw_fam.strip().upper()
            previous = validated_families.get(sku_key)
            if previous is not None and previous != family_value:
                raise ValueError(f"Conflicting duplicate catalogue family entries for SKU '{sku_key}'.")
            validated_families[sku_key] = family_value

        validated_categories: Dict[str, str] = {}
        for raw_sku, raw_cat in (category_map or {}).items():
            if not isinstance(raw_sku, str) or not raw_sku.strip() or not isinstance(raw_cat, str) or not raw_cat.strip():
                raise ValueError("Every catalogue category entry requires non-empty string SKU and category.")
            sku_key = raw_sku.strip().upper()
            category_value = normalize_sku_category(raw_cat)
            previous = validated_categories.get(sku_key)
            if previous is not None and previous != category_value:
                raise ValueError(f"Conflicting duplicate catalogue category entries for SKU '{sku_key}'.")
            validated_categories[sku_key] = category_value

        with self._lock:
            if not allow_overwrite:
                for sku_key, family_value in validated_families.items():
                    existing_family = self._sku_product_families.get(sku_key)
                    if existing_family is not None and existing_family != family_value:
                        raise ValueError(
                            f"Catalog family conflict for SKU '{sku_key}': existing '{existing_family}' "
                            f"!= incoming '{family_value}'."
                        )
                for sku_key, category_value in validated_categories.items():
                    existing_category = self._sku_categories.get(sku_key)
                    if existing_category and existing_category != "untagged" and not are_sku_categories_compatible(existing_category, category_value):
                        raise ValueError(
                            f"Catalog category conflict for SKU '{sku_key}': existing '{existing_category}' "
                            f"is incompatible with incoming '{category_value}'."
                        )

            # Commit durable state first; only then expose the new mappings in memory.
            self._persist_catalog_batch_locked(validated_families, validated_categories)
            self._sku_product_families.update(validated_families)
            self._sku_categories.update(validated_categories)

    def _resolve_registered_sku_family_locked(self, sku: Optional[str]) -> Optional[str]:
        if not sku or not sku.strip():
            return None
        clean_sku = sku.strip().upper()
        exact = self._sku_product_families.get(clean_sku)
        if exact:
            return exact
        if self._sku_family_prefixes:
            for prefix in sorted(self._sku_family_prefixes.keys(), key=len, reverse=True):
                if clean_sku.startswith(prefix):
                    rem = clean_sku[len(prefix):]
                    if not prefix.endswith(("-", "_")) and not rem.startswith(("-", "_")):
                        continue
                    suffix = rem.lstrip("-_")
                    if (
                        suffix
                        and not NUMERIC_OR_VERSION_SUFFIX_RE.match(suffix)
                        and not RETRY_MUTATION_PATTERN.search(suffix)
                    ):
                        return self._sku_family_prefixes[prefix]
        return None

    def get_sku_category(self, sku: Optional[str]) -> str:
        if not sku or not sku.strip():
            return "untagged"
        with self._lock:
            return self._sku_categories.get(sku.strip().upper(), "untagged")

    def resolve_cart_risk_category(
        self,
        sku: Optional[str] = None,
        items: Optional[List[Dict[str, Any]]] = None,
        item_name: Optional[str] = None,
        description: Optional[str] = None,
    ) -> Tuple[str, bool]:
        """Resolve category by SKU first, then exact registered alias only where SKU is absent.

        Alias fallback is deliberately exact after punctuation/whitespace normalization. It
        never performs fuzzy matching and never marks a cart fingerprint complete.
        """
        with self._lock:
            candidate_categories: List[str] = []

            def add_registered_sku(candidate: Optional[str]) -> None:
                clean = str(candidate or "").strip().upper()
                if clean:
                    candidate_categories.append(self._sku_categories.get(clean, "untagged"))

            alias_index = {
                _normalize_catalog_alias(catalog_key): category
                for catalog_key, category in self._sku_categories.items()
                if _normalize_catalog_alias(catalog_key)
            }

            if items:
                # Some internal callers provide a normalized top-level SKU alongside the
                # expanded item array. Preserve it as a primary catalogue signal too.
                add_registered_sku(sku)
                for item in items:
                    if not isinstance(item, dict):
                        continue
                    item_sku = str(item.get("sku") or "").strip()
                    if item_sku:
                        add_registered_sku(item_sku)
                    else:
                        # SKU-less ad-hoc/catalog item: only a trusted exact alias can add a
                        # category; otherwise it remains untagged.
                        for text_value in (item.get("name"), item.get("description")):
                            key = _normalize_catalog_alias(text_value)
                            if key in alias_index:
                                candidate_categories.append(alias_index[key])
            elif sku and sku.strip():
                add_registered_sku(sku)
            else:
                for text_value in (item_name, description):
                    key = _normalize_catalog_alias(text_value)
                    if key in alias_index:
                        candidate_categories.append(alias_index[key])

            first_non_untagged: Optional[str] = None
            for category in candidate_categories:
                if category in NON_STACKABLE_CATEGORIES:
                    return category, True
                if category != "untagged" and first_non_untagged is None:
                    first_non_untagged = category

            return (first_non_untagged or "untagged"), False

    def get_sku_family(self, sku: Optional[str]) -> Optional[str]:
        with self._lock:
            return self._resolve_registered_sku_family_locked(sku)

    def compute_cart_family_signature(
        self,
        sku: Optional[str] = None,
        product_family_id: Optional[str] = None,
        items: Optional[List[Dict[str, Any]]] = None,
    ) -> Optional[str]:
        with self._lock:
            if items:
                fam_totals: Dict[str, int] = {}
                for item in items:
                    if not isinstance(item, dict):
                        return None
                    item_sku = str(item.get("sku") or "").strip().upper()
                    item_fam = (
                        str(item.get("product_family_id") or "").strip().upper()
                        or (self._resolve_registered_sku_family_locked(item_sku) if item_sku else None)
                        or (
                            product_family_id.strip().upper()
                            if len(items) == 1 and product_family_id and product_family_id.strip()
                            else None
                        )
                    )
                    if not item_fam:
                        return None
                    raw_qty = item.get("quantity", 1)
                    if isinstance(raw_qty, bool) or raw_qty is None:
                        return None
                    try:
                        qty = int(str(raw_qty).strip())
                    except (ValueError, TypeError):
                        return None
                    if qty <= 0:
                        return None
                    fam_totals[item_fam] = fam_totals.get(item_fam, 0) + qty
                parts = [f"{fam}:{fam_totals[fam]}" for fam in sorted(fam_totals.keys())]
                return "|".join(parts)

            if product_family_id and product_family_id.strip():
                return f"{product_family_id.strip().upper()}:1"
            if sku and sku.strip():
                mapped = self._resolve_registered_sku_family_locked(sku)
                if mapped:
                    return f"{mapped}:1"
            return None

    # ------------------------------------------------------------------
    # Atomic Webhook Event Claim & Crash-Recoverable Lease
    # ------------------------------------------------------------------
    def claim_webhook_event(self, event_id: str, now: Optional[float] = None) -> bool:
        if not event_id or not event_id.strip():
            return False
        current_time = _validated_event_time(now)
        clean_id = event_id.strip()

        with self._lock:
            if self.db_path:
                conn = sqlite3.connect(self.db_path, timeout=10.0, isolation_level=None)
                try:
                    conn.execute("BEGIN IMMEDIATE")
                    conn.execute(
                        "DELETE FROM webhook_event_ledger WHERE updated_at < ?",
                        (current_time - self.webhook_ttl_seconds,),
                    )
                    row = conn.execute(
                        "SELECT status, updated_at FROM webhook_event_ledger WHERE event_id = ?",
                        (clean_id,),
                    ).fetchone()
                    if row is not None:
                        status, updated_at = row[0], float(row[1])
                        if status == "PROCESSED":
                            conn.execute("COMMIT")
                            return False
                        if (
                            status == "IN_FLIGHT"
                            and (current_time - updated_at) < self.inflight_webhook_timeout_seconds
                        ):
                            conn.execute("COMMIT")
                            return False
                        conn.execute(
                            "UPDATE webhook_event_ledger SET status = 'IN_FLIGHT', updated_at = ? WHERE event_id = ?",
                            (current_time, clean_id),
                        )
                    else:
                        conn.execute(
                            "INSERT INTO webhook_event_ledger (event_id, status, updated_at) VALUES (?, 'IN_FLIGHT', ?)",
                            (clean_id, current_time),
                        )
                    conn.execute("COMMIT")
                except Exception:
                    conn.execute("ROLLBACK")
                    raise
                finally:
                    conn.close()

            self._prune_expired_webhooks(current_time)
            existing = self._webhook_claims.get(clean_id)
            if existing is not None and not self.db_path:
                if existing.status == "PROCESSED":
                    return False
                if (
                    existing.status == "IN_FLIGHT"
                    and (current_time - existing.updated_at) < self.inflight_webhook_timeout_seconds
                ):
                    return False

            self._webhook_claims[clean_id] = WebhookEventClaim(
                event_id=clean_id,
                status="IN_FLIGHT",
                updated_at=current_time,
            )
            return True

    def is_duplicate_webhook(self, event_id: str, now: Optional[float] = None) -> bool:
        if not event_id or not event_id.strip():
            return False
        current_time = _validated_event_time(now)
        clean_id = event_id.strip()
        with self._lock:
            if self.db_path:
                with sqlite3.connect(self.db_path, timeout=10.0) as conn:
                    row = conn.execute(
                        "SELECT status, updated_at FROM webhook_event_ledger WHERE event_id = ?",
                        (clean_id,),
                    ).fetchone()
                    if row is not None:
                        status, updated_at = row[0], float(row[1])
                        if status == "PROCESSED":
                            return True
                        return (current_time - updated_at) < self.inflight_webhook_timeout_seconds

            self._prune_expired_webhooks(current_time)
            existing = self._webhook_claims.get(clean_id)
            if existing is None:
                return False
            if existing.status == "PROCESSED":
                return True
            return (current_time - existing.updated_at) < self.inflight_webhook_timeout_seconds

    def mark_webhook_processed(self, event_id: str, now: Optional[float] = None) -> None:
        if not event_id or not event_id.strip():
            return
        current_time = _validated_event_time(now)
        clean_id = event_id.strip()
        with self._lock:
            if self.db_path:
                with sqlite3.connect(self.db_path, timeout=10.0) as conn:
                    conn.execute(
                        """
                        INSERT INTO webhook_event_ledger (event_id, status, updated_at)
                        VALUES (?, 'PROCESSED', ?)
                        ON CONFLICT(event_id) DO UPDATE SET status = 'PROCESSED', updated_at = excluded.updated_at
                        """,
                        (clean_id, current_time),
                    )
                    conn.commit()
            self._prune_expired_webhooks(current_time)
            self._webhook_claims[clean_id] = WebhookEventClaim(
                event_id=clean_id,
                status="PROCESSED",
                updated_at=current_time,
            )

    def unmark_webhook_event(self, event_id: str) -> None:
        if not event_id or not event_id.strip():
            return
        clean_id = event_id.strip()
        with self._lock:
            if self.db_path:
                with sqlite3.connect(self.db_path, timeout=10.0) as conn:
                    conn.execute(
                        "DELETE FROM webhook_event_ledger WHERE event_id = ? AND status = 'IN_FLIGHT'",
                        (clean_id,),
                    )
                    conn.commit()
            self._webhook_claims.pop(clean_id, None)

    def _prune_expired_webhooks(self, current_time: float) -> None:
        cutoff = current_time - self.webhook_ttl_seconds
        expired = [
            eid
            for eid, claim in self._webhook_claims.items()
            if claim.updated_at < cutoff
        ]
        for eid in expired:
            del self._webhook_claims[eid]
        if self.db_path:
            with sqlite3.connect(self.db_path, timeout=10.0) as conn:
                conn.execute(
                    "DELETE FROM webhook_event_ledger WHERE updated_at < ?",
                    (cutoff,),
                )
                conn.commit()

    # ------------------------------------------------------------------
    # Memory Pruning & Hold Resolution Tracking
    # ------------------------------------------------------------------
    def _prune_expired_orders(self, current_time: float) -> None:
        cutoff = current_time - self.window_seconds
        active_order_ids: Set[str] = set()

        for key in list(self._identity_index.keys()):
            valid_ids = [
                oid
                for oid in self._identity_index[key]
                if oid in self._orders_by_id
                and self._orders_by_id[oid].timestamp >= cutoff
            ]
            if valid_ids:
                self._identity_index[key] = valid_ids
                active_order_ids.update(valid_ids)
            else:
                del self._identity_index[key]

        protected_states = (
            "APPROVED_PENDING_SETTLEMENT",
            "AUTHORIZED_HOLD",
            "ANALYZING_HOLD",
            "AUTO_CAPTURING",
            "NEEDS_ATTENTION",
            "PARTIALLY_CAPTURED",
        )
        capture_retention_cutoff = current_time - max(3600, self.webhook_ttl_seconds)
        for oid in list(self._orders_by_id.keys()):
            rec = self._orders_by_id[oid]
            if oid in active_order_ids:
                continue
            if rec.resolution_status in protected_states:
                continue
            capture_ts = rec.captured_at if rec.captured_at is not None else rec.timestamp
            if (rec.capture_id or rec.capture_ids) and capture_ts >= capture_retention_cutoff:
                continue
            if rec.timestamp < cutoff:
                if rec.capture_id:
                    self._capture_to_order_id.pop(rec.capture_id, None)
                for cid in rec.capture_ids:
                    self._capture_to_order_id.pop(cid, None)
                if rec.authorization_id:
                    self._auth_to_order_id.pop(rec.authorization_id, None)
                self._order_indexed_keys.pop(oid, None)
                del self._orders_by_id[oid]
                self._delete_persisted_order_locked(oid)

    @staticmethod
    def _resolve_distinct_variant_match_mode(
        current_fp: Optional[str],
        prev_fp: Optional[str],
        current_desc: str,
        prev_desc: str,
        current_family: Optional[str] = None,
        prev_family: Optional[str] = None,
        allow_sku_prefix_heuristic: bool = False,
        current_fp_complete: bool = True,
        prev_fp_complete: bool = True,
    ) -> Optional[str]:
        if not current_fp_complete or not prev_fp_complete:
            return None
        if not current_fp or not prev_fp:
            return None

        s1 = current_fp.strip().upper()
        s2 = prev_fp.strip().upper()
        if not s1 or not s2 or s1 == s2:
            return None

        if RETRY_MUTATION_PATTERN.search(s1) or RETRY_MUTATION_PATTERN.search(s2):
            return None

        if RETRY_MUTATION_PATTERN.search(current_desc) or RETRY_MUTATION_PATTERN.search(prev_desc):
            return None

        if current_family or prev_family:
            if (
                current_family
                and prev_family
                and current_family.strip().upper() == prev_family.strip().upper()
            ):
                return "EXPLICIT_FAMILY"
            return None

        if allow_sku_prefix_heuristic:
            fam1, var1 = extract_sku_family_and_variant(s1)
            fam2, var2 = extract_sku_family_and_variant(s2)
            if fam1 and fam2 and fam1 == fam2 and var1 != var2:
                return "HEURISTIC_STEM"

        return None

    @staticmethod
    def _is_distinct_clean_variant_sku(
        current_fp: Optional[str],
        prev_fp: Optional[str],
        current_desc: str,
        prev_desc: str,
        current_family: Optional[str] = None,
        prev_family: Optional[str] = None,
        allow_sku_prefix_heuristic: bool = False,
        current_fp_complete: bool = True,
        prev_fp_complete: bool = True,
    ) -> bool:
        return (
            VelocityStateEngine._resolve_distinct_variant_match_mode(
                current_fp=current_fp,
                prev_fp=prev_fp,
                current_desc=current_desc,
                prev_desc=prev_desc,
                current_family=current_family,
                prev_family=prev_family,
                allow_sku_prefix_heuristic=allow_sku_prefix_heuristic,
                current_fp_complete=current_fp_complete,
                prev_fp_complete=prev_fp_complete,
            )
            is not None
        )

    @staticmethod
    def _is_clearly_unrelated_product_sku(
        current_fp: Optional[str],
        prev_fp: Optional[str],
        current_desc: str,
        prev_desc: str,
        current_family: Optional[str] = None,
        prev_family: Optional[str] = None,
        current_fp_complete: bool = True,
        prev_fp_complete: bool = True,
    ) -> bool:
        if not current_fp_complete or not prev_fp_complete:
            return False
        if not current_fp or not prev_fp:
            return False
        s1 = current_fp.strip().upper()
        s2 = prev_fp.strip().upper()
        if not s1 or not s2 or s1 == s2:
            return False
        if has_suspicious_sku_or_desc_mutation(s1, s2, current_desc, prev_desc):
            return False
        # Explicit catalogue metadata takes precedence over SKU-stem inference.
        # If only one side has a family mapping, relationship is unknown, not unrelated.
        if current_family or prev_family:
            if not current_family or not prev_family:
                return False
            return current_family.strip().upper() != prev_family.strip().upper()
        fam1, _ = extract_sku_family_and_variant(s1)
        fam2, _ = extract_sku_family_and_variant(s2)
        if fam1 and fam2 and fam1 != fam2:
            return True
        return False

    def check_and_record_order(
        self,
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
    ) -> VelocityCheckResult:
        current_time = _validated_event_time(now)
        clean_order_id = (order_id or "").strip()
        if not clean_order_id:
            raise ValueError("order_id is required.")
        intent = (intent or "").strip().upper()
        if intent != "AUTHORIZE":
            raise ValueError("Pillar 1 MVP supports only PayPal AUTHORIZE orders.")
        norm_currency = (currency or "USD").strip().upper()
        validate_financial_amount(
            amount,
            norm_currency,
            allow_zero=False,
            allowed_currencies=self.supported_currencies,
        )
        norm_amount = _normalize_amount(amount, norm_currency)
        if items is not None and (
            not isinstance(items, list) or any(not isinstance(item, dict) for item in items)
        ):
            raise ValueError("items must be a list of item dictionaries when supplied.")
        sku_clean = sku.strip() if sku and sku.strip() else None
        cart_fp, fp_complete = compute_cart_fingerprint_details(sku=sku_clean, items=items)
        sku_category, is_hard_hold_category = self.resolve_cart_risk_category(
            sku=sku_clean,
            items=items,
            item_name=item_name,
            description=description,
        )
        # Export the already-existing deterministic marker checks to P2 as evidence only.
        # P1's matching patterns and eligibility logic remain unchanged.
        cur_full_untrusted_text = f"{sku_clean or ''} {item_name} {description} {note_to_payer or ''}"
        has_prompt_injection_signal = bool(PROMPT_INJECTION_PATTERN.search(cur_full_untrusted_text))
        has_retry_marker_signal = bool(RETRY_MUTATION_PATTERN.search(cur_full_untrusted_text))
        cart_family_sig = self.compute_cart_family_signature(
            sku=sku_clean,
            product_family_id=product_family_id,
            items=items,
        )

        identity_keys, used_ip_fallback, identity_strength = classify_identity_keys(
            payer_id=payer_id,
            payer_email=payer_email,
            shipping_address_hash=shipping_address_hash,
            custom_id=custom_id,
            customer_id=customer_id,
            session_id=session_id,
            client_ip=client_ip,
        )
        has_reliable_identity = identity_strength == "STRONG"

        with self._lock:
            self._prune_expired_orders(current_time)

            existing_rec = self._orders_by_id.get(clean_order_id)
            if existing_rec is not None:
                # A repeated event for one PayPal order ID must not rewrite its financial
                # identity or cart. Treat contradictory payloads as integrity conflicts.
                if existing_rec.amount != norm_amount or existing_rec.currency != norm_currency:
                    raise ValueError(
                        f"Conflicting repeat for order_id '{clean_order_id}': financial amount/currency changed."
                    )
                if existing_rec.intent.strip().upper() != intent:
                    raise ValueError(
                        f"Conflicting repeat for order_id '{clean_order_id}': intent changed."
                    )
                if (
                    existing_rec.cart_fingerprint_complete
                    and fp_complete
                    and existing_rec.cart_fingerprint
                    and cart_fp
                    and existing_rec.cart_fingerprint != cart_fp
                ):
                    raise ValueError(
                        f"Conflicting repeat for order_id '{clean_order_id}': complete cart fingerprint changed."
                    )

            if not identity_keys or identity_strength == "NONE":
                raw_inc = f"anon_missing_id|{clean_order_id}"
                incident_id = f"inc_{hashlib.sha256(raw_inc.encode('utf-8')).hexdigest()[:12]}"
                if existing_rec is None:
                    new_record = OrderRecord(
                        order_id=clean_order_id,
                        payer_id=None,
                        payer_email=None,
                        shipping_address_hash=None,
                        custom_id=None,
                        customer_id=None,
                        session_id=None,
                        product_family_id=product_family_id,
                        cart_family_signature=cart_family_sig,
                        cart_fingerprint_complete=fp_complete,
                        sku=sku_clean,
                        cart_fingerprint=cart_fp,
                        item_name=item_name,
                        description=description,
                        amount=norm_amount,
                        currency=norm_currency,
                        intent=intent,
                        timestamp=current_time,
                        status_updated_at=current_time,
                        note_to_payer=note_to_payer,
                        client_ip=None,
                        user_agent=user_agent,
                        sku_category=sku_category,
                        incident_id=incident_id,
                        used_ip_fallback=False,
                        identity_strength="NONE",
                        has_reliable_identity=False,
                        is_flagged=True,
                        can_auto_capture_if_llm_approves=False,
                    )
                    self._replace_order_index(new_record, [])
                else:
                    candidate = copy.deepcopy(existing_rec)
                    candidate.is_flagged = True
                    candidate.can_auto_capture_if_llm_approves = False
                    self._persist_order_locked(
                        candidate, self._order_indexed_keys.get(clean_order_id, set())
                    )
                    self._orders_by_id[clean_order_id] = candidate
                    existing_rec = candidate
                return VelocityCheckResult(
                    is_flagged=True,
                    flag_reason="MISSING_BUYER_IDENTITY_HOLD",
                    repeat_count=0,
                    time_delta_seconds=None,
                    matched_identity_key=None,
                    anchor_order=None,
                    previous_orders=[],
                    incident_id=incident_id,
                    sku_category=sku_category,
                    is_hard_hold_category=is_hard_hold_category,
                    address_changed_vs_anchor=False,
                    used_ip_fallback=False,
                    identity_strength="NONE",
                    matched_identity_strength="NONE",
                    has_reliable_identity=False,
                    can_auto_capture_if_llm_approves=False,
                    matched_identity_keys=[],
                    has_prompt_injection_signal=has_prompt_injection_signal,
                    has_retry_marker_signal=has_retry_marker_signal,
                )

            keys_by_order_id: Dict[str, List[str]] = {}
            for key in identity_keys:
                prior_ids = self._identity_index.get(key, [])
                for oid in prior_ids:
                    if oid != clean_order_id:
                        keys_by_order_id.setdefault(oid, []).append(key)

            ref_timestamp = existing_rec.timestamp if existing_rec else current_time
            prior_orders: List[OrderRecord] = sorted(
                (
                    self._orders_by_id[oid]
                    for oid in keys_by_order_id.keys()
                    if oid in self._orders_by_id
                    and oid != clean_order_id
                    and self._orders_by_id[oid].timestamp <= ref_timestamp
                ),
                key=lambda r: r.timestamp,
            )

            correlated_orders: List[OrderRecord] = []
            saw_distinct_variant_swap = False
            variant_match_mode: Optional[str] = None
            saw_different_product_sku = False
            cur_text = f"{item_name} {description}"
            cur_sku_set = _extract_cart_sku_set(cart_fp)

            for prev in prior_orders:
                if prev.currency != norm_currency:
                    continue

                prev_text = f"{prev.item_name} {prev.description}"
                delta_vs_prev = max(0.0, ref_timestamp - prev.timestamp)

                match_mode = self._resolve_distinct_variant_match_mode(
                    cart_fp,
                    prev.cart_fingerprint,
                    cur_text,
                    prev_text,
                    current_family=cart_family_sig,
                    prev_family=prev.cart_family_signature,
                    allow_sku_prefix_heuristic=self.allow_sku_prefix_heuristic,
                    current_fp_complete=fp_complete,
                    prev_fp_complete=prev.cart_fingerprint_complete,
                )
                if match_mode is not None:
                    saw_distinct_variant_swap = True
                    variant_match_mode = match_mode
                    continue

                if (
                    fp_complete
                    and prev.cart_fingerprint_complete
                    and cart_fp
                    and prev.cart_fingerprint
                    and cart_fp == prev.cart_fingerprint
                ):
                    correlated_orders.append(prev)
                    continue

                prev_sku_set = _extract_cart_sku_set(prev.cart_fingerprint)
                if cur_sku_set and prev_sku_set and cur_sku_set == prev_sku_set:
                    correlated_orders.append(prev)
                    continue

                if self._is_clearly_unrelated_product_sku(
                    cart_fp,
                    prev.cart_fingerprint,
                    cur_text,
                    prev_text,
                    current_family=cart_family_sig,
                    prev_family=prev.cart_family_signature,
                    current_fp_complete=fp_complete,
                    prev_fp_complete=prev.cart_fingerprint_complete,
                ):
                    if delta_vs_prev < self.min_human_gap_seconds:
                        correlated_orders.append(prev)
                        continue
                    saw_different_product_sku = True
                    continue

                if prev.amount == norm_amount:
                    correlated_orders.append(prev)

            if not correlated_orders:
                if has_prompt_injection_signal or has_retry_marker_signal:
                    primary_key, primary_strength = select_strongest_matched_key(identity_keys)
                    tag = "prompt_injection" if has_prompt_injection_signal else "first_order_retry"
                    raw_inc = f"{tag}|{primary_key or 'anon'}|{clean_order_id}"
                    incident_id = f"inc_{hashlib.sha256(raw_inc.encode('utf-8')).hexdigest()[:12]}"
                    flag_reason = (
                        "UNTRUSTED_TEXT_PROMPT_INJECTION_SUSPECTED"
                        if has_prompt_injection_signal
                        else "FIRST_ORDER_RETRY_MUTATION_MARKER_DETECTED"
                    )
                    if existing_rec is None:
                        new_record = OrderRecord(
                            order_id=clean_order_id,
                            payer_id=payer_id,
                            payer_email=payer_email,
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
                            amount=norm_amount,
                            currency=norm_currency,
                            intent=intent,
                            timestamp=current_time,
                            status_updated_at=current_time,
                            note_to_payer=note_to_payer,
                            client_ip=client_ip,
                            user_agent=user_agent,
                            sku_category=sku_category,
                            incident_id=incident_id,
                            used_ip_fallback=used_ip_fallback,
                            identity_strength=identity_strength,
                            has_reliable_identity=has_reliable_identity,
                            is_flagged=True,
                            can_auto_capture_if_llm_approves=False,
                        )
                        self._replace_order_index(new_record, identity_keys)
                    else:
                        candidate, candidate_keys = self._candidate_with_payer_enrichment(
                            existing_rec,
                            payer_id=payer_id,
                            payer_email=payer_email,
                            shipping_address_hash=shipping_address_hash,
                            custom_id=custom_id,
                            customer_id=customer_id,
                            session_id=session_id,
                        )
                        candidate.incident_id = candidate.incident_id or incident_id
                        candidate.is_flagged = True
                        candidate.can_auto_capture_if_llm_approves = False
                        self._replace_order_index(candidate, candidate_keys)
                        existing_rec = candidate
                    return VelocityCheckResult(
                        is_flagged=True,
                        flag_reason=flag_reason,
                        repeat_count=0,
                        time_delta_seconds=None,
                        matched_identity_key=primary_key,
                        anchor_order=None,
                        previous_orders=[],
                        incident_id=incident_id,
                        sku_category=sku_category,
                        is_hard_hold_category=is_hard_hold_category,
                        address_changed_vs_anchor=False,
                        used_ip_fallback=used_ip_fallback,
                        identity_strength=identity_strength,
                        matched_identity_strength=primary_strength,
                        has_reliable_identity=has_reliable_identity,
                        can_auto_capture_if_llm_approves=False,
                        matched_identity_keys=list(identity_keys),
                        variant_match_mode=None,
                        has_prompt_injection_signal=has_prompt_injection_signal,
                        has_retry_marker_signal=has_retry_marker_signal,
                    )

                if saw_distinct_variant_swap:
                    flag_reason = "DISTINCT_VARIANT_SKU_FAST_PATH"
                elif saw_different_product_sku:
                    flag_reason = "DIFFERENT_PRODUCT_SKU_FAST_PATH"
                else:
                    flag_reason = "FIRST_ORDER_IN_WINDOW_FAST_PATH"

                # P0 #1: Clean first-order auto-capture eligibility requires reliable identity,
                # and if existing_rec was previously hard-held (can_auto_capture_if_llm_approves=False),
                # never restore it to True!
                fast_path_eligible = (
                    has_reliable_identity
                    and not is_hard_hold_category
                    and (
                        True
                        if existing_rec is None
                        else existing_rec.can_auto_capture_if_llm_approves
                    )
                )
                if existing_rec is None:
                    new_record = OrderRecord(
                        order_id=clean_order_id,
                        payer_id=payer_id,
                        payer_email=payer_email,
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
                        amount=norm_amount,
                        currency=norm_currency,
                        intent=intent,
                        timestamp=current_time,
                        status_updated_at=current_time,
                        note_to_payer=note_to_payer,
                        client_ip=client_ip,
                        user_agent=user_agent,
                        sku_category=sku_category,
                        incident_id=None,
                        used_ip_fallback=used_ip_fallback,
                        identity_strength=identity_strength,
                        has_reliable_identity=has_reliable_identity,
                        is_flagged=False,
                        can_auto_capture_if_llm_approves=fast_path_eligible,
                    )
                    self._replace_order_index(new_record, identity_keys)
                else:
                    # P0 #1: Never clear an existing hard-hold flag or restore eligibility.
                    candidate, candidate_keys = self._candidate_with_payer_enrichment(
                        existing_rec,
                        payer_id=payer_id,
                        payer_email=payer_email,
                        shipping_address_hash=shipping_address_hash,
                        custom_id=custom_id,
                        customer_id=customer_id,
                        session_id=session_id,
                    )
                    candidate.can_auto_capture_if_llm_approves = (
                        candidate.can_auto_capture_if_llm_approves and fast_path_eligible
                    )
                    self._replace_order_index(candidate, candidate_keys)
                    existing_rec = candidate
                return VelocityCheckResult(
                    is_flagged=bool(existing_rec.is_flagged) if existing_rec else False,
                    flag_reason=flag_reason,
                    repeat_count=0,
                    time_delta_seconds=None,
                    matched_identity_key=None,
                    anchor_order=None,
                    previous_orders=[],
                    incident_id=existing_rec.incident_id if existing_rec else None,
                    sku_category=sku_category,
                    is_hard_hold_category=is_hard_hold_category,
                    address_changed_vs_anchor=False,
                    used_ip_fallback=used_ip_fallback,
                    identity_strength=identity_strength,
                    matched_identity_strength="NONE",
                    has_reliable_identity=has_reliable_identity,
                    can_auto_capture_if_llm_approves=fast_path_eligible,
                    matched_identity_keys=[],
                    variant_match_mode=variant_match_mode if saw_distinct_variant_swap else None,
                    has_prompt_injection_signal=has_prompt_injection_signal,
                    has_retry_marker_signal=has_retry_marker_signal,
                )

            correlated_matched_keys: List[str] = []
            for corr_ord in correlated_orders:
                for k in keys_by_order_id.get(corr_ord.order_id, []):
                    if k not in correlated_matched_keys:
                        correlated_matched_keys.append(k)
            matched_key, matched_key_strength = select_strongest_matched_key(correlated_matched_keys)

            anchor_order = correlated_orders[0]
            most_recent_order = correlated_orders[-1]
            fulfilled_prior_orders = [
                o for o in correlated_orders
                if o.resolution_status not in ("AUTHORIZED_HOLD", "VOIDED", "NEEDS_ATTENTION")
                and o.can_auto_capture_if_llm_approves
            ]
            repeat_count = len(fulfilled_prior_orders) if fulfilled_prior_orders else len(correlated_orders)
            time_delta = max(0.0, ref_timestamp - most_recent_order.timestamp)

            incident_id = anchor_order.incident_id
            if not incident_id:
                raw_inc = f"{matched_key or 'anon'}|{anchor_order.order_id}"
                incident_id = f"inc_{hashlib.sha256(raw_inc.encode('utf-8')).hexdigest()[:12]}"
                anchor_candidate = copy.deepcopy(anchor_order)
                anchor_candidate.incident_id = incident_id
                self._persist_order_locked(
                    anchor_candidate,
                    self._order_indexed_keys.get(anchor_order.order_id, set()),
                )
                self._orders_by_id[anchor_order.order_id] = anchor_candidate
                anchor_order = anchor_candidate
                correlated_orders[0] = anchor_candidate

            if (
                fp_complete
                and anchor_order.cart_fingerprint_complete
                and cart_fp
                and anchor_order.cart_fingerprint
                and cart_fp == anchor_order.cart_fingerprint
            ):
                flag_reason = "EXACT_SKU_REPEAT_IN_15M_WINDOW"
            else:
                flag_reason = "SAME_AMOUNT_MUTATED_OR_MISSING_SKU_IN_15M_WINDOW"

            address_changed_vs_anchor = bool(
                shipping_address_hash
                and anchor_order.shipping_address_hash
                and shipping_address_hash != anchor_order.shipping_address_hash
            )
            is_human_speed = time_delta >= self.min_human_gap_seconds
            anchor_text = f"{anchor_order.item_name} {anchor_order.description}"
            has_mutation_vs_anchor = has_suspicious_sku_or_desc_mutation(
                cart_fp or (sku_clean or ""),
                anchor_order.cart_fingerprint or (anchor_order.sku or ""),
                cur_text,
                anchor_text,
            )

            # P1 #5: Include retry marker signals and suspicious SKU/desc mutations in final eligibility
            can_auto_capture = (
                has_reliable_identity
                and (matched_key_strength == "STRONG")
                and (repeat_count == 1)
                and (not is_hard_hold_category)
                and is_human_speed
                and (not address_changed_vs_anchor)
                and (not has_prompt_injection_signal)
                and (not has_retry_marker_signal)
                and (not has_mutation_vs_anchor)
            )
            if existing_rec is not None and not existing_rec.can_auto_capture_if_llm_approves:
                can_auto_capture = False

            if existing_rec is None:
                new_record = OrderRecord(
                    order_id=clean_order_id,
                    payer_id=payer_id,
                    payer_email=payer_email,
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
                    amount=norm_amount,
                    currency=norm_currency,
                    intent=intent,
                    timestamp=current_time,
                    status_updated_at=current_time,
                    note_to_payer=note_to_payer,
                    client_ip=client_ip,
                    user_agent=user_agent,
                    sku_category=sku_category,
                    incident_id=incident_id,
                    used_ip_fallback=used_ip_fallback,
                    identity_strength=identity_strength,
                    has_reliable_identity=has_reliable_identity,
                    is_flagged=True,
                    can_auto_capture_if_llm_approves=can_auto_capture,
                )
                self._replace_order_index(new_record, identity_keys)
            else:
                candidate, candidate_keys = self._candidate_with_payer_enrichment(
                    existing_rec,
                    payer_id=payer_id,
                    payer_email=payer_email,
                    shipping_address_hash=shipping_address_hash,
                    custom_id=custom_id,
                    customer_id=customer_id,
                    session_id=session_id,
                )
                candidate.incident_id = candidate.incident_id or incident_id
                candidate.is_flagged = True
                candidate.can_auto_capture_if_llm_approves = (
                    candidate.can_auto_capture_if_llm_approves and can_auto_capture
                )
                self._replace_order_index(candidate, candidate_keys)
                existing_rec = candidate

            return VelocityCheckResult(
                is_flagged=True,
                flag_reason=flag_reason,
                repeat_count=repeat_count,
                time_delta_seconds=round(time_delta, 3),
                matched_identity_key=matched_key,
                anchor_order=copy.deepcopy(anchor_order),
                previous_orders=[copy.deepcopy(o) for o in correlated_orders],
                incident_id=incident_id,
                sku_category=sku_category,
                is_hard_hold_category=is_hard_hold_category,
                address_changed_vs_anchor=address_changed_vs_anchor,
                used_ip_fallback=used_ip_fallback,
                identity_strength=identity_strength,
                matched_identity_strength=matched_key_strength,
                has_reliable_identity=has_reliable_identity,
                can_auto_capture_if_llm_approves=can_auto_capture,
                matched_identity_keys=correlated_matched_keys,
                variant_match_mode=variant_match_mode,
                has_prompt_injection_signal=has_prompt_injection_signal,
                has_retry_marker_signal=has_retry_marker_signal,
            )

    def _replace_order_index(
        self,
        record: OrderRecord,
        new_identity_keys: List[str],
        persist: bool = True,
    ) -> None:
        """Persist the candidate record before publishing it to in-memory indexes."""
        oid = record.order_id
        new_key_set = set(new_identity_keys)
        if persist:
            self._persist_order_locked(record, new_key_set)

        old_keys = self._order_indexed_keys.get(oid, set())
        for stale_key in old_keys - new_key_set:
            bucket = self._identity_index.get(stale_key)
            if bucket is not None:
                self._identity_index[stale_key] = [x for x in bucket if x != oid]
                if not self._identity_index[stale_key]:
                    del self._identity_index[stale_key]

        for key in new_identity_keys:
            bucket = self._identity_index.setdefault(key, [])
            if oid not in bucket:
                bucket.append(oid)

        self._orders_by_id[oid] = record
        self._order_indexed_keys[oid] = new_key_set

    def _candidate_with_payer_enrichment(
        self,
        record: OrderRecord,
        *,
        payer_id: Optional[str] = None,
        payer_email: Optional[str] = None,
        shipping_address_hash: Optional[str] = None,
        custom_id: Optional[str] = None,
        customer_id: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> Tuple[OrderRecord, List[str]]:
        """Return an enriched copy after validating all strong identities; do not mutate live state."""
        candidate = copy.deepcopy(record)
        incoming_pid = payer_id.strip() if payer_id and payer_id.strip() else None
        incoming_email = payer_email.strip().lower() if payer_email and payer_email.strip() else None
        incoming_cid = customer_id.strip() if customer_id and customer_id.strip() else None

        if candidate.payer_id and incoming_pid and candidate.payer_id != incoming_pid:
            raise ValueError(
                f"Conflicting strong identity payer_id on order '{candidate.order_id}': "
                f"existing='{candidate.payer_id}' vs incoming='{incoming_pid}'."
            )
        if candidate.payer_email and incoming_email and candidate.payer_email.lower() != incoming_email:
            raise ValueError(
                f"Conflicting strong identity payer_email on order '{candidate.order_id}': "
                f"existing='{candidate.payer_email}' vs incoming='{incoming_email}'."
            )
        if candidate.customer_id and incoming_cid and candidate.customer_id != incoming_cid:
            raise ValueError(
                f"Conflicting strong identity customer_id on order '{candidate.order_id}': "
                f"existing='{candidate.customer_id}' vs incoming='{incoming_cid}'."
            )

        if incoming_pid and not candidate.payer_id:
            candidate.payer_id = incoming_pid
        if incoming_email and not candidate.payer_email:
            candidate.payer_email = incoming_email
        if incoming_cid and not candidate.customer_id:
            candidate.customer_id = incoming_cid
        if shipping_address_hash and shipping_address_hash.strip() and not candidate.shipping_address_hash:
            candidate.shipping_address_hash = shipping_address_hash.strip()
        if custom_id and custom_id.strip() and not candidate.custom_id:
            candidate.custom_id = custom_id.strip()
        if session_id and session_id.strip() and not candidate.session_id:
            candidate.session_id = session_id.strip()

        keys, used_ip, strength = classify_identity_keys(
            payer_id=candidate.payer_id,
            payer_email=candidate.payer_email,
            shipping_address_hash=candidate.shipping_address_hash,
            custom_id=candidate.custom_id,
            customer_id=candidate.customer_id,
            session_id=candidate.session_id,
            client_ip=candidate.client_ip,
        )
        candidate.used_ip_fallback = used_ip
        candidate.identity_strength = strength
        candidate.has_reliable_identity = strength == "STRONG"
        return candidate, keys

    # ------------------------------------------------------------------
    # Ledger Enrichment & Reconciliation Sweep Helpers
    # ------------------------------------------------------------------
    def enrich_order_payer(
        self,
        order_id: str,
        payer_id: Optional[str] = None,
        payer_email: Optional[str] = None,
        shipping_address_hash: Optional[str] = None,
        custom_id: Optional[str] = None,
        customer_id: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> Optional[OrderRecord]:
        """Enrich missing identity fields only, persisting the validated copy before publishing it."""
        with self._lock:
            rec = self._orders_by_id.get((order_id or "").strip())
            if rec is None:
                return None
            candidate, new_keys = self._candidate_with_payer_enrichment(
                rec,
                payer_id=payer_id,
                payer_email=payer_email,
                shipping_address_hash=shipping_address_hash,
                custom_id=custom_id,
                customer_id=customer_id,
                session_id=session_id,
            )
            self._replace_order_index(candidate, new_keys)
            return copy.deepcopy(candidate)

    def register_capture(
        self,
        order_id: str,
        capture_id: str,
        authorization_id: Optional[str] = None,
        payer_id: Optional[str] = None,
        payer_email: Optional[str] = None,
        shipping_address_hash: Optional[str] = None,
        manual_override_actor: Optional[str] = None,
        manual_override_reason: Optional[str] = None,
        resolution_status: str = "CAPTURED",
        now: Optional[float] = None,
    ) -> None:
        """Register the sole full capture supported by the MVP.

        Repeated registration of the same capture is idempotent; a different capture for
        the same order is rejected. The candidate order is committed before any in-memory
        capture/auth mapping is published.
        """
        current_time = _validated_event_time(now)
        clean_cap = (capture_id or "").strip()
        clean_oid = (order_id or "").strip()
        clean_auth = authorization_id.strip() if authorization_id and authorization_id.strip() else None
        if not clean_cap or not clean_oid:
            raise ValueError("order_id and capture_id are required.")

        with self._lock:
            rec = self._orders_by_id.get(clean_oid)
            if rec is None:
                raise ValueError(f"Cannot register capture '{clean_cap}' for unknown order_id '{clean_oid}'.")
            if rec.intent.strip().upper() != "AUTHORIZE":
                raise ValueError(f"Cannot register an authorization capture for non-AUTHORIZE order '{clean_oid}'.")
            if not (rec.authorization_id or clean_auth):
                raise ValueError(
                    f"Cannot register capture '{clean_cap}' before a verified authorization_id is recorded for order '{clean_oid}'."
                )

            existing_oid = self._capture_to_order_id.get(clean_cap)
            if existing_oid is not None and existing_oid != clean_oid:
                raise ValueError(
                    f"Conflicting capture-to-order mapping: capture_id '{clean_cap}' is already "
                    f"mapped to order '{existing_oid}', cannot remap to '{clean_oid}'."
                )

            known_capture_ids = set(rec.capture_ids or [])
            if rec.capture_id:
                known_capture_ids.add(rec.capture_id)
            if known_capture_ids and clean_cap not in known_capture_ids:
                raise ValueError(
                    f"MVP supports one capture per order; order '{clean_oid}' already has "
                    f"capture(s) {sorted(known_capture_ids)}."
                )

            if rec.authorization_id and clean_auth and rec.authorization_id != clean_auth:
                raise ValueError(
                    f"Order '{clean_oid}' is already bound to authorization '{rec.authorization_id}', "
                    f"cannot register capture under '{clean_auth}'."
                )
            if clean_auth:
                mapped_auth_oid = self._auth_to_order_id.get(clean_auth)
                if mapped_auth_oid is not None and mapped_auth_oid != clean_oid:
                    raise ValueError(
                        f"Conflicting auth-to-order mapping: authorization_id '{clean_auth}' is already "
                        f"mapped to order '{mapped_auth_oid}', cannot remap to '{clean_oid}'."
                    )

            target_status = (resolution_status or "").strip().upper()
            if not target_status or not can_transition_order_status(rec.resolution_status, target_status):
                raise ValueError(
                    f"Invalid capture state transition for order '{clean_oid}': "
                    f"{rec.resolution_status} -> {resolution_status}."
                )

            candidate, new_keys = self._candidate_with_payer_enrichment(
                rec,
                payer_id=payer_id,
                payer_email=payer_email,
                shipping_address_hash=shipping_address_hash,
            )
            if clean_auth:
                candidate.authorization_id = clean_auth
            candidate.capture_id = clean_cap
            if clean_cap not in candidate.capture_ids:
                candidate.capture_ids.append(clean_cap)
            candidate.captured_at = current_time
            candidate.status_updated_at = current_time
            if manual_override_actor and manual_override_actor.strip():
                candidate.manual_override_actor = manual_override_actor.strip()
            if manual_override_reason and manual_override_reason.strip():
                candidate.manual_override_reason = manual_override_reason.strip()
            candidate.resolution_status = target_status

            # Durable candidate first; only then publish the order and provider-ID indexes.
            self._replace_order_index(candidate, new_keys)
            self._capture_to_order_id[clean_cap] = clean_oid
            if clean_auth:
                self._auth_to_order_id[clean_auth] = clean_oid

    def mark_order_authorized(
        self,
        order_id: str,
        authorization_id: Optional[str] = None,
        status: str = "AUTHORIZED_HOLD",
        payer_id: Optional[str] = None,
        payer_email: Optional[str] = None,
        shipping_address_hash: Optional[str] = None,
        now: Optional[float] = None,
    ) -> bool:
        current_time = _validated_event_time(now)
        clean_oid = (order_id or "").strip()
        clean_auth = authorization_id.strip() if authorization_id and authorization_id.strip() else None
        if not clean_oid:
            return False
        if not clean_auth:
            raise ValueError("authorization_id is required to mark an order authorized.")
        with self._lock:
            rec = self._orders_by_id.get(clean_oid)
            if rec is None:
                return False
            if (rec.intent or "").strip().upper() != "AUTHORIZE":
                raise ValueError(
                    f"Cannot mark non-AUTHORIZE order '{clean_oid}' as authorized (intent={rec.intent!r})."
                )

            target_status = (status or "").strip().upper()
            if not target_status or not can_transition_order_status(rec.resolution_status, target_status):
                return False
            if rec.authorization_id and rec.authorization_id != clean_auth:
                raise ValueError(
                    f"Order '{clean_oid}' is already bound to authorization '{rec.authorization_id}', "
                    f"cannot replace it with '{clean_auth}'."
                )
            existing_auth_oid = self._auth_to_order_id.get(clean_auth)
            if existing_auth_oid is not None and existing_auth_oid != clean_oid:
                raise ValueError(
                    f"Conflicting auth-to-order mapping: authorization_id '{clean_auth}' is already "
                    f"mapped to order '{existing_auth_oid}', cannot remap to '{clean_oid}'."
                )

            candidate, new_keys = self._candidate_with_payer_enrichment(
                rec,
                payer_id=payer_id,
                payer_email=payer_email,
                shipping_address_hash=shipping_address_hash,
            )
            candidate.authorization_id = clean_auth
            candidate.intent = "AUTHORIZE"
            candidate.resolution_status = target_status
            candidate.status_updated_at = current_time

            self._replace_order_index(candidate, new_keys)
            self._auth_to_order_id[clean_auth] = clean_oid
            return True

    def assign_order_incident_id(
        self,
        order_id: str,
        incident_id: str,
        *,
        replace_existing: bool = False,
    ) -> bool:
        clean_order_id = (order_id or "").strip()
        clean_incident_id = (incident_id or "").strip()
        if not clean_order_id:
            raise ValueError("order_id is required.")
        if not clean_incident_id:
            raise ValueError("incident_id is required.")
        with self._lock:
            record = self._orders_by_id.get(clean_order_id)
            if record is None:
                return False
            if record.incident_id and record.incident_id != clean_incident_id and not replace_existing:
                # By default preserve the first association. The combined checkout evaluator
                # may explicitly merge independently-derived IDs after P1 proves one
                # refund/rebuy correlation, because OrderRecord stores a single incident ID.
                return False
            if record.incident_id != clean_incident_id:
                candidate = copy.deepcopy(record)
                candidate.incident_id = clean_incident_id
                self._persist_order_locked(
                    candidate, self._order_indexed_keys.get(clean_order_id, set())
                )
                self._orders_by_id[clean_order_id] = candidate
            return True

    def set_order_auto_capture_eligibility(
        self,
        order_id: str,
        can_auto_capture: bool,
        is_flagged: Optional[bool] = None,
    ) -> bool:
        """Persist combined eligibility with a durable one-way hard-hold latch."""
        clean_oid = (order_id or "").strip()
        if not clean_oid:
            raise ValueError("order_id is required.")
        if not isinstance(can_auto_capture, bool):
            raise TypeError("can_auto_capture must be a bool.")
        if is_flagged is not None and not isinstance(is_flagged, bool):
            raise TypeError("is_flagged must be bool or None.")
        with self._lock:
            rec = self._orders_by_id.get(clean_oid)
            if rec is None:
                return False
            candidate = copy.deepcopy(rec)
            candidate.can_auto_capture_if_llm_approves = (
                candidate.can_auto_capture_if_llm_approves and can_auto_capture
            )
            if is_flagged is not None:
                candidate.is_flagged = candidate.is_flagged or is_flagged
            if candidate != rec:
                self._persist_order_locked(
                    candidate, self._order_indexed_keys.get(clean_oid, set())
                )
                self._orders_by_id[clean_oid] = candidate
            return True

    def update_order_resolution(
        self,
        order_id: str,
        resolution_status: str,
        now: Optional[float] = None,
        pillar2_classification: Optional[str] = None,
        deterministic_hold_reason: Optional[str] = None,
        manual_override_actor: Optional[str] = None,
        manual_override_reason: Optional[str] = None,
    ) -> bool:
        current_time = _validated_event_time(now)
        clean_oid = (order_id or "").strip()
        with self._lock:
            rec = self._orders_by_id.get(clean_oid)
            if rec is None:
                return False
            if not can_transition_order_status(rec.resolution_status, resolution_status):
                return False
            candidate = copy.deepcopy(rec)
            candidate.resolution_status = resolution_status.strip().upper()
            candidate.status_updated_at = current_time
            if pillar2_classification is not None and pillar2_classification.strip():
                candidate.pillar2_classification = pillar2_classification.strip().upper()
            if deterministic_hold_reason is not None and deterministic_hold_reason.strip():
                candidate.deterministic_hold_reason = deterministic_hold_reason.strip().upper()
            if manual_override_actor is not None and manual_override_actor.strip():
                candidate.manual_override_actor = manual_override_actor.strip()
            if manual_override_reason is not None and manual_override_reason.strip():
                candidate.manual_override_reason = manual_override_reason.strip()
            self._persist_order_locked(
                candidate, self._order_indexed_keys.get(clean_oid, set())
            )
            self._orders_by_id[clean_oid] = candidate
            return True

    def get_unresolved_holds(
        self,
        older_than_seconds: float = 60.0,
        now: Optional[float] = None,
    ) -> List[OrderRecord]:
        current_time = _validated_event_time(now)
        with self._lock:
            return [
                copy.deepcopy(rec)
                for rec in self._orders_by_id.values()
                if rec.resolution_status in ("APPROVED_PENDING_SETTLEMENT", "ANALYZING_HOLD", "AUTO_CAPTURING")
                and (current_time - rec.status_updated_at) >= older_than_seconds
            ]

    def get_active_holds(
        self,
        incident_id: Optional[str] = None,
        voidable_only: bool = True,
    ) -> List[OrderRecord]:
        allowed_statuses = (
            ("AUTHORIZED_HOLD",)
            if voidable_only
            else ("AUTHORIZED_HOLD", "ANALYZING_HOLD", "NEEDS_ATTENTION")
        )
        with self._lock:
            return [
                copy.deepcopy(rec)
                for rec in self._orders_by_id.values()
                if rec.resolution_status in allowed_statuses
                and (
                    not voidable_only
                    or rec.pillar2_classification != "LEGITIMATE_REPEAT_BUYER"
                )
                and (incident_id is None or rec.incident_id == incident_id)
            ]

    def get_order(self, order_id: str) -> Optional[OrderRecord]:
        with self._lock:
            rec = self._orders_by_id.get(order_id.strip())
            return copy.deepcopy(rec) if rec is not None else None

    def get_order_by_capture_id(self, capture_id: str) -> Optional[OrderRecord]:
        with self._lock:
            oid = self._capture_to_order_id.get(capture_id.strip())
            rec = self._orders_by_id.get(oid) if oid else None
            return copy.deepcopy(rec) if rec is not None else None

    def get_order_by_auth_id(self, authorization_id: str) -> Optional[OrderRecord]:
        with self._lock:
            oid = self._auth_to_order_id.get(authorization_id.strip())
            rec = self._orders_by_id.get(oid) if oid else None
            return copy.deepcopy(rec) if rec is not None else None