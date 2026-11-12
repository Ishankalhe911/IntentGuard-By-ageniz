"""
Phase 3 (File 2/3): Pre-Creation Checkout Shield & `CAPTURE` -> `AUTHORIZE` Rewriter
Location: src/pillar3_capture_shield/intent_rewriter.py

Locked Architectural Safeguards (Section A + Round 2 Audited):
1. Unconditional `intent: "AUTHORIZE"` Enforcement at Creation:
   - Empirically verified on live PayPal Sandbox (`Order ID: 55W24923R2615592P`, `HTTP 422`,
     `issue: "CANNOT_MODIFY_INTENT"` — see `SANDBOX_PATCH_INTENT_VERIFICATION_EVIDENCE` below):
     PayPal blocks `PATCH /intent` after order creation, and `payer_id` is only revealed after
     buyer approval. Every incoming checkout creation payload is rewritten to `"intent": "AUTHORIZE"`
     before calling `POST /v2/checkout/orders`.
   - Unapproved orders are NOT recorded into Pillar 1's 15-minute velocity window.
2. Safe Per-Checkout Idempotency Key Derivation (`derive_create_order_request_id` — Must-Fix #1):
   - Derives `PayPal-Request-Id` ONLY from an explicit `paypal_request_id`, a per-checkout
     `checkout_attempt_id` (or `checkout_session_id`), or `purchase_units[0].invoice_id`.
   - NEVER derives `PayPal-Request-Id` from `custom_id`, `reference_id` (often `"default"`),
     or a payload hash, preventing PayPal from collapsing legitimate repeat purchases or hiding
     agent retry loops. Caps derived keys at `<= 100` characters.
3. Non-Blocking Catalog Registration & Downgrade Protection (Should-Fix #3a):
   - Canonicalizes `sku_category` via `normalize_sku_category()` (handling `-` vs `_`, mapping
     synonyms, and rejecting unknown/misspelled category names with a `difflib` suggestion).
   - If a trusted checkout payload supplies a category or family that conflicts with an
     already-registered SKU in `state_engine` (such as `"default"` / `"untagged"` or a stackable
     category for a `single_seat_saas` SKU), preserves the existing catalog registration and
     records a warning in `catalog_conflict_warnings` instead of crashing the customer's checkout.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from decimal import Decimal
import hashlib
import importlib.util
import logging
from pathlib import Path
import sys
from typing import Any, Dict, FrozenSet, List, Optional, Tuple


logger = logging.getLogger(__name__)

MAX_PAYPAL_REQUEST_ID_LENGTH = 100

# Live PayPal Sandbox verification artifact (Minor #9)
SANDBOX_PATCH_INTENT_VERIFICATION_EVIDENCE: Dict[str, Any] = {
    "verified_on": "2026-11-05",
    "endpoint": "PATCH https://api-m.sandbox.paypal.com/v2/checkout/orders/55W24923R2615592P",
    "order_id": "55W24923R2615592P",
    "authorize_capture_test_order_id": "5L844379A19170604",
    "authorize_capture_test_auth_id": "1JN73101EA366674P",
    "authorize_capture_test_capture_id": "9T298980B5559222S",
    "request_body": [{"op": "replace", "path": "/intent", "value": "AUTHORIZE"}],
    "http_status": 422,
    "response_body": {
        "name": "UNPROCESSABLE_ENTITY",
        "details": [
            {
                "field": "/intent",
                "value": "AUTHORIZE",
                "location": "body",
                "issue": "CANNOT_MODIFY_INTENT",
                "description": "The 'intent' field cannot be modified after the order is created.",
            }
        ],
        "message": "The requested action could not be performed, semantically incorrect, or failed business validation.",
    },
}


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
    from ..pillar1_velocity_engine.state_engine import (
        NON_STACKABLE_CATEGORIES,
        PAYPAL_SUPPORTED_CURRENCIES,
        VelocityStateEngine,
        _normalize_amount,
        are_sku_categories_compatible,
        normalize_sku_category,
        validate_financial_amount,
    )
    from ..config.paypal_client import PayPalSandboxClient
except ImportError:
    _se_mod = _load_sibling_module(
        "state_engine",
        "src.pillar1_velocity_engine.state_engine",
        ("pillar1_velocity_engine",),
    )
    _pp_mod = _load_sibling_module(
        "paypal_client",
        "src.config.paypal_client",
        ("config",),
    )
    NON_STACKABLE_CATEGORIES = _se_mod.NON_STACKABLE_CATEGORIES
    PAYPAL_SUPPORTED_CURRENCIES = _se_mod.PAYPAL_SUPPORTED_CURRENCIES
    VelocityStateEngine = _se_mod.VelocityStateEngine
    _normalize_amount = _se_mod._normalize_amount
    are_sku_categories_compatible = _se_mod.are_sku_categories_compatible
    normalize_sku_category = _se_mod.normalize_sku_category
    validate_financial_amount = _se_mod.validate_financial_amount
    PayPalSandboxClient = _pp_mod.PayPalSandboxClient


PAYPAL_SUPPORTED_ITEM_FIELDS: FrozenSet[str] = frozenset({
    "name",
    "unit_amount",
    "tax",
    "quantity",
    "description",
    "sku",
    "url",
    "category",
    "image_url",
    "upc",
})

PAYPAL_ALLOWED_ITEM_CATEGORIES: FrozenSet[str] = frozenset({
    "DIGITAL_GOODS",
    "PHYSICAL_GOODS",
    "DONATION",
})

INTERNAL_ONLY_ITEM_FIELDS: FrozenSet[str] = frozenset({
    "product_family_id",
    "sku_category",
})


@dataclass
class ExtractedItemMetadata:
    sku: Optional[str]
    name: str
    quantity: int
    product_family_id: Optional[str] = None
    sku_category: Optional[str] = None
    registered_in_catalog: bool = False


@dataclass
class RewrittenOrderPayload:
    paypal_payload: Dict[str, Any]
    original_intent: str
    effective_intent: str
    was_intent_rewritten: bool
    currency: str
    normalized_amount: str
    extracted_items: List[ExtractedItemMetadata] = field(default_factory=list)
    trusted_metadata_registered: bool = False
    catalog_conflict_warnings: List[str] = field(default_factory=list)


def _bound_request_id(prefix: str, raw_key: str, max_length: int = MAX_PAYPAL_REQUEST_ID_LENGTH) -> str:
    candidate = f"{prefix}{raw_key}" if prefix else raw_key
    if len(candidate) <= max_length:
        return candidate
    digest = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()[:24]
    head_len = max(1, max_length - len(prefix) - 25)
    return f"{prefix}{raw_key[:head_len]}-{digest}"


def derive_create_order_request_id(
    paypal_payload: Dict[str, Any],
    *,
    paypal_request_id: Optional[str] = None,
    checkout_attempt_id: Optional[str] = None,
    checkout_session_id: Optional[str] = None,
) -> Optional[str]:
    """
    Derives a deterministic `PayPal-Request-Id` for `POST /v2/checkout/orders` ONLY from
    per-checkout unique identifiers (Must-Fix #1):
    1. Explicit `paypal_request_id`
    2. Explicit per-checkout `checkout_attempt_id` (or `checkout_session_id` alias)
    3. `purchase_units[0].invoice_id` (unique per order in PayPal)

    Never derives a key from `custom_id`, `reference_id`, or a hash of `paypal_payload`,
    returning `None` when no per-checkout unique key is provided so genuine repeat purchases
    are never collapsed by PayPal's idempotency layer. Caps keys at `<= 100` chars.
    """
    if paypal_request_id and paypal_request_id.strip():
        return _bound_request_id("", paypal_request_id.strip())

    per_checkout_id = checkout_attempt_id or checkout_session_id
    if per_checkout_id and per_checkout_id.strip():
        return _bound_request_id("create-chk-", per_checkout_id.strip())

    pu_list = paypal_payload.get("purchase_units") or []
    pu0 = pu_list[0] if (pu_list and isinstance(pu_list[0], dict)) else {}
    inv_id = pu0.get("invoice_id")
    if inv_id and str(inv_id).strip():
        return _bound_request_id("create-inv-", str(inv_id).strip())

    return None


def rewrite_order_payload(
    order_payload: Dict[str, Any],
    state_engine: Optional[VelocityStateEngine] = None,
    *,
    trusted_merchant_metadata: bool = False,
    reject_untrusted_internal_metadata: bool = False,
) -> RewrittenOrderPayload:
    """
    Validates, sanitizes, and rewrites an incoming checkout creation payload to
    `"intent": "AUTHORIZE"` without mutating `order_payload` in place.
    """
    if not isinstance(order_payload, dict):
        raise ValueError("order_payload must be a dictionary.")

    sanitized = copy.deepcopy(order_payload)
    raw_intent = str(sanitized.get("intent") or "CAPTURE").strip().upper()
    if raw_intent not in ("CAPTURE", "AUTHORIZE"):
        raise ValueError(f"Unsupported PayPal order intent '{raw_intent}'. Expected 'CAPTURE' or 'AUTHORIZE'.")

    was_rewritten = raw_intent != "AUTHORIZE"
    sanitized["intent"] = "AUTHORIZE"

    pu_list = sanitized.get("purchase_units")
    if not isinstance(pu_list, list) or len(pu_list) == 0:
        raise ValueError("PayPal order payload must contain a non-empty 'purchase_units' list.")

    if len(pu_list) != 1:
        raise ValueError(
            f"UNSUPPORTED_INTENT: PayPal orders with intent='AUTHORIZE' support exactly 1 "
            f"purchase_unit (got {len(pu_list)}). Use purchase_units[0].items[] for multi-item carts."
        )

    pu0 = pu_list[0]
    if not isinstance(pu0, dict):
        raise ValueError("purchase_units[0] must be a dictionary.")

    # MVP is one merchant/payee per order. Do not silently pass platform-fee splits,
    # delayed disbursement instructions, or caller-selected payee routing to PayPal.
    if "payment_instruction" in pu0:
        raise ValueError("Marketplace payment instructions, including platform-fee splits and delayed disbursement, are disabled in the MVP.")
    if "payee" in pu0:
        raise ValueError("CALLER_SELECTED_PAYEE_DISABLED_IN_MVP: merchant payee must be bound by trusted server configuration.")

    amount_obj = pu0.get("amount")
    if not isinstance(amount_obj, dict):
        raise ValueError("purchase_units[0].amount is required and must be a dictionary.")

    allowed_currencies = (
        state_engine.supported_currencies
        if state_engine is not None
        else PAYPAL_SUPPORTED_CURRENCIES
    )
    raw_currency = str(amount_obj.get("currency_code") or "").strip().upper()
    raw_value = amount_obj.get("value")
    total_dec = validate_financial_amount(
        raw_value,
        raw_currency,
        allow_zero=False,
        allowed_currencies=allowed_currencies,
    )
    norm_total_str = _normalize_amount(total_dec, raw_currency)
    amount_obj["currency_code"] = raw_currency
    amount_obj["value"] = norm_total_str

    items_key_present = "items" in pu0
    raw_items = pu0.get("items")
    extracted_metadata: List[ExtractedItemMetadata] = []
    pending_registrations: List[ExtractedItemMetadata] = []
    catalog_warnings: List[str] = []

    if items_key_present:
        if not isinstance(raw_items, list) or len(raw_items) == 0:
            raise ValueError(
                "INVALID_ARRAY_MIN_ITEMS: purchase_units[0].items must be a non-empty list when provided."
            )
    else:
        description_signal = str(pu0.get("description") or "").strip()
        custom_id_signal = str(pu0.get("custom_id") or "").strip()
        if not description_signal and not custom_id_signal:
            raise ValueError(
                "ORDER_PRODUCT_SIGNAL_REQUIRED: when items is omitted, purchase_units[0] "
                "must contain a non-empty description or custom_id."
            )

    if items_key_present:

        sanitized_items: List[Dict[str, Any]] = []
        computed_items_total = Decimal("0.00")
        all_items_have_unit_amount = True

        for idx, item in enumerate(raw_items):
            if not isinstance(item, dict):
                raise ValueError(f"purchase_units[0].items[{idx}] must be a dictionary.")

            item_name = str(item.get("name") or "").strip()
            if not item_name:
                raise ValueError(f"purchase_units[0].items[{idx}].name is required by PayPal Orders v2.")

            raw_qty = item.get("quantity", "1")
            if isinstance(raw_qty, bool):
                raise ValueError(f"purchase_units[0].items[{idx}].quantity is invalid.")
            try:
                qty_int = int(str(raw_qty).strip())
            except (ValueError, TypeError) as exc:
                raise ValueError(
                    f"purchase_units[0].items[{idx}].quantity must be a positive integer (got '{raw_qty}')."
                ) from exc
            if qty_int <= 0:
                raise ValueError(
                    f"purchase_units[0].items[{idx}].quantity must be >= 1 (got {qty_int})."
                )

            raw_sku = item.get("sku")
            clean_sku = str(raw_sku).strip().upper() if raw_sku and str(raw_sku).strip() else None

            raw_fam = item.get("product_family_id")
            clean_fam = str(raw_fam).strip().upper() if raw_fam and str(raw_fam).strip() else None

            raw_cat = item.get("sku_category")
            has_raw_cat = raw_cat is not None and bool(str(raw_cat).strip())
            clean_cat: Optional[str] = None

            if (clean_fam is not None or has_raw_cat) and not trusted_merchant_metadata:
                if reject_untrusted_internal_metadata:
                    raise PermissionError(
                        f"Untrusted checkout payload attempted to supply internal catalog metadata "
                        f"on items[{idx}] (product_family_id={clean_fam}, sku_category={raw_cat})."
                    )

            if trusted_merchant_metadata and has_raw_cat:
                clean_cat = normalize_sku_category(str(raw_cat))

            if trusted_merchant_metadata and (clean_fam is not None or clean_cat is not None):
                if not clean_sku:
                    raise ValueError(
                        f"purchase_units[0].items[{idx}] provides trusted internal metadata "
                        f"(product_family_id/sku_category) but is missing a valid 'sku'."
                    )
                if state_engine is not None:
                    existing_fam = state_engine.get_sku_family(clean_sku)
                    if existing_fam is not None and clean_fam is not None and existing_fam != clean_fam:
                        warn_msg = (
                            f"Catalog family conflict for SKU '{clean_sku}': keeping existing "
                            f"'{existing_fam}', ignoring incoming '{clean_fam}'."
                        )
                        logger.warning(warn_msg)
                        catalog_warnings.append(warn_msg)
                        clean_fam = existing_fam

                    existing_cat = state_engine.get_sku_category(clean_sku)
                    if (
                        existing_cat != "untagged"
                        and clean_cat is not None
                        and not are_sku_categories_compatible(existing_cat, clean_cat)
                    ):
                        warn_msg = (
                            f"Catalog category conflict for SKU '{clean_sku}': keeping existing "
                            f"'{existing_cat}', ignoring incompatible incoming '{clean_cat}'."
                        )
                        logger.warning(warn_msg)
                        catalog_warnings.append(warn_msg)
                        clean_cat = existing_cat

            if "category" in item and item["category"] is not None:
                pp_cat = str(item["category"]).strip().upper()
                if pp_cat not in PAYPAL_ALLOWED_ITEM_CATEGORIES:
                    raise ValueError(
                        f"Invalid PayPal item category '{item['category']}' on items[{idx}]. "
                        f"PayPal allows only {sorted(PAYPAL_ALLOWED_ITEM_CATEGORIES)}. "
                        "Keep internal risk categories in 'sku_category'."
                    )

            unit_amt_obj = item.get("unit_amount")
            if unit_amt_obj is not None:
                if not isinstance(unit_amt_obj, dict):
                    raise ValueError(f"purchase_units[0].items[{idx}].unit_amount must be a dict.")
                u_curr = str(unit_amt_obj.get("currency_code") or "").strip().upper()
                if u_curr != raw_currency:
                    raise ValueError(
                        f"Currency mismatch on items[{idx}].unit_amount: expected '{raw_currency}', got '{u_curr}'."
                    )
                u_dec = validate_financial_amount(
                    unit_amt_obj.get("value"),
                    u_curr,
                    allow_zero=False,
                    allowed_currencies=allowed_currencies,
                )
                unit_amt_obj["currency_code"] = u_curr
                unit_amt_obj["value"] = _normalize_amount(u_dec, u_curr)
                computed_items_total += u_dec * Decimal(qty_int)
            else:
                all_items_have_unit_amount = False

            paypal_item: Dict[str, Any] = {
                k: v
                for k, v in item.items()
                if k in PAYPAL_SUPPORTED_ITEM_FIELDS
            }
            paypal_item["name"] = item_name
            paypal_item["quantity"] = str(qty_int)
            if "category" in paypal_item and paypal_item["category"] is not None:
                paypal_item["category"] = str(paypal_item["category"]).strip().upper()
            sanitized_items.append(paypal_item)

            meta = ExtractedItemMetadata(
                sku=clean_sku,
                name=item_name,
                quantity=qty_int,
                product_family_id=clean_fam if trusted_merchant_metadata else None,
                sku_category=clean_cat if trusted_merchant_metadata else None,
                registered_in_catalog=False,
            )
            extracted_metadata.append(meta)
            if trusted_merchant_metadata and (clean_fam is not None or clean_cat is not None):
                pending_registrations.append(meta)

        breakdown = amount_obj.get("breakdown")
        if breakdown is not None and not isinstance(breakdown, dict):
            raise ValueError("purchase_units[0].amount.breakdown must be a dictionary when provided.")

        # Sum optional PayPal v2 breakdown adjustments (+ tax/shipping/handling/insurance, - discounts)
        net_breakdown_adjustment = Decimal("0.00")
        has_other_breakdown_fields = False
        if isinstance(breakdown, dict):
            for add_key in ("tax_total", "shipping", "handling", "insurance"):
                if isinstance(breakdown.get(add_key), dict):
                    has_other_breakdown_fields = True
                    bd_obj = breakdown[add_key]
                    bd_curr = str(bd_obj.get("currency_code") or "").strip().upper()
                    if bd_curr != raw_currency:
                        raise ValueError(
                            f"amount.breakdown.{add_key} currency '{bd_curr}' does not match '{raw_currency}'."
                        )
                    bd_dec = validate_financial_amount(
                        bd_obj.get("value"),
                        bd_curr,
                        allow_zero=True,
                        allowed_currencies=allowed_currencies,
                    )
                    bd_obj["currency_code"] = raw_currency
                    bd_obj["value"] = _normalize_amount(bd_dec, raw_currency)
                    net_breakdown_adjustment += bd_dec

            for sub_key in ("shipping_discount", "discount"):
                if isinstance(breakdown.get(sub_key), dict):
                    has_other_breakdown_fields = True
                    bd_obj = breakdown[sub_key]
                    bd_curr = str(bd_obj.get("currency_code") or "").strip().upper()
                    if bd_curr != raw_currency:
                        raise ValueError(
                            f"amount.breakdown.{sub_key} currency '{bd_curr}' does not match '{raw_currency}'."
                        )
                    bd_dec = validate_financial_amount(
                        bd_obj.get("value"),
                        bd_curr,
                        allow_zero=True,
                        allowed_currencies=allowed_currencies,
                    )
                    bd_obj["currency_code"] = raw_currency
                    bd_obj["value"] = _normalize_amount(bd_dec, raw_currency)
                    net_breakdown_adjustment -= bd_dec

        if isinstance(breakdown, dict) and isinstance(breakdown.get("item_total"), dict):
            it_obj = breakdown["item_total"]
            it_curr = str(it_obj.get("currency_code") or "").strip().upper()
            if it_curr != raw_currency:
                raise ValueError(
                    f"amount.breakdown.item_total currency '{it_curr}' does not match '{raw_currency}'."
                )
            it_dec = validate_financial_amount(
                it_obj.get("value"),
                it_curr,
                allow_zero=False,
                allowed_currencies=allowed_currencies,
            )
            if all_items_have_unit_amount and computed_items_total != it_dec:
                raise ValueError(
                    f"ITEM_TOTAL_MISMATCH: sum(unit_amount * quantity) = {_normalize_amount(computed_items_total, raw_currency)} "
                    f"does not match amount.breakdown.item_total = {_normalize_amount(it_dec, raw_currency)}."
                )
            expected_total_dec = it_dec + net_breakdown_adjustment
            if expected_total_dec != total_dec:
                raise ValueError(
                    f"AMOUNT_MISMATCH: amount.breakdown net total = {_normalize_amount(expected_total_dec, raw_currency)} "
                    f"does not match purchase_units[0].amount.value = {norm_total_str}."
                )
            it_obj["currency_code"] = raw_currency
            it_obj["value"] = _normalize_amount(it_dec, raw_currency)
        elif all_items_have_unit_amount:
            expected_total_dec = computed_items_total + net_breakdown_adjustment
            if expected_total_dec != total_dec:
                if has_other_breakdown_fields:
                    raise ValueError(
                        f"AMOUNT_MISMATCH: sum(unit_amount * quantity) + breakdown adjustments = "
                        f"{_normalize_amount(expected_total_dec, raw_currency)} "
                        f"does not match purchase_units[0].amount.value = {norm_total_str}."
                    )
                raise ValueError(
                    f"ITEM_TOTAL_MISMATCH: sum(unit_amount * quantity) = {_normalize_amount(computed_items_total, raw_currency)} "
                    f"does not match purchase_units[0].amount.value = {norm_total_str}."
                )
            # PayPal Orders v2 requires amount.breakdown.item_total whenever items[].unit_amount & quantity are present
            if not isinstance(breakdown, dict):
                breakdown = {}
                amount_obj["breakdown"] = breakdown
            breakdown["item_total"] = {
                "currency_code": raw_currency,
                "value": _normalize_amount(computed_items_total, raw_currency),
            }

        pu0["items"] = sanitized_items

    # Resolve within-batch conflicts without crashing checkout (keep first family & stricter category)
    batch_families: Dict[str, str] = {}
    batch_categories: Dict[str, str] = {}
    for meta in pending_registrations:
        if not meta.sku:
            raise ValueError("Internal metadata registration requires a non-empty SKU.")
        if meta.product_family_id:
            prev_f = batch_families.get(meta.sku)
            if prev_f and prev_f != meta.product_family_id:
                warn_msg = (
                    f"Conflicting product_family_id values for SKU '{meta.sku}' within same request: "
                    f"keeping '{prev_f}', ignoring '{meta.product_family_id}'."
                )
                logger.warning(warn_msg)
                catalog_warnings.append(warn_msg)
                meta.product_family_id = prev_f
            else:
                batch_families[meta.sku] = meta.product_family_id
        if meta.sku_category:
            prev_c = batch_categories.get(meta.sku)
            if prev_c and not are_sku_categories_compatible(prev_c, meta.sku_category):
                kept_c = (
                    prev_c
                    if prev_c in NON_STACKABLE_CATEGORIES
                    else (
                        meta.sku_category
                        if meta.sku_category in NON_STACKABLE_CATEGORIES
                        else prev_c
                    )
                )
                warn_msg = (
                    f"Conflicting sku_category values for SKU '{meta.sku}' within same request: "
                    f"keeping '{kept_c}'."
                )
                logger.warning(warn_msg)
                catalog_warnings.append(warn_msg)
                batch_categories[meta.sku] = kept_c
                meta.sku_category = kept_c
            elif prev_c is None or prev_c == "untagged":
                batch_categories[meta.sku] = meta.sku_category

    registered_any = False
    if trusted_merchant_metadata and state_engine is not None and pending_registrations:
        for meta in pending_registrations:
            if not meta.sku:
                raise ValueError("Internal metadata registration requires a non-empty SKU.")
            if meta.sku_category:
                effective_cat = state_engine.register_sku_category(
                    sku=meta.sku,
                    category=meta.sku_category,
                    product_family_id=meta.product_family_id,
                    allow_downgrade=False,
                )
                meta.sku_category = effective_cat
            elif meta.product_family_id:
                effective_fam = state_engine.register_sku_family(
                    sku=meta.sku,
                    product_family_id=meta.product_family_id,
                    allow_overwrite=False,
                )
                meta.product_family_id = effective_fam
            meta.registered_in_catalog = True
            registered_any = True

    return RewrittenOrderPayload(
        paypal_payload=sanitized,
        original_intent=raw_intent,
        effective_intent="AUTHORIZE",
        was_intent_rewritten=was_rewritten,
        currency=raw_currency,
        normalized_amount=norm_total_str,
        extracted_items=extracted_metadata,
        trusted_metadata_registered=registered_any,
        catalog_conflict_warnings=catalog_warnings,
    )


def create_shielded_paypal_order(
    paypal_client: PayPalSandboxClient,
    order_payload: Dict[str, Any],
    state_engine: Optional[VelocityStateEngine] = None,
    *,
    trusted_merchant_metadata: bool = False,
    reject_untrusted_internal_metadata: bool = False,
    paypal_request_id: Optional[str] = None,
    checkout_attempt_id: Optional[str] = None,
    checkout_session_id: Optional[str] = None,
) -> Tuple[RewrittenOrderPayload, Dict[str, Any]]:
    """
    Rewrites and sanitizes the checkout payload to `intent="AUTHORIZE"`, derives a
    per-checkout `PayPal-Request-Id` ONLY when `paypal_request_id`, `checkout_attempt_id`
    (or `checkout_session_id`), or `invoice_id` is supplied (sending `None` otherwise),
    and creates the order on PayPal via `POST /v2/checkout/orders`.
    """
    rewritten = rewrite_order_payload(
        order_payload=order_payload,
        state_engine=state_engine,
        trusted_merchant_metadata=trusted_merchant_metadata,
        reject_untrusted_internal_metadata=reject_untrusted_internal_metadata,
    )
    effective_req_id = derive_create_order_request_id(
        rewritten.paypal_payload,
        paypal_request_id=paypal_request_id,
        checkout_attempt_id=checkout_attempt_id,
        checkout_session_id=checkout_session_id,
    )
    paypal_response = paypal_client.create_order(
        rewritten.paypal_payload,
        paypal_request_id=effective_req_id,
    )
    return rewritten, paypal_response