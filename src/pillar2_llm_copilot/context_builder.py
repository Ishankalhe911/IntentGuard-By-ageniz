"""Explicit privacy allowlist from P3's DTO to the P2 model input."""
from __future__ import annotations

import re
from typing import Any, Dict, Optional

CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
WRAPPER_START = "<untrusted_buyer_data>"
WRAPPER_END = "</untrusted_buyer_data>"


def _get(context: Any, field: str, default: Any = None) -> Any:
    if isinstance(context, dict):
        return context.get(field, default)
    return getattr(context, field, default)


def _unwrap_and_clean(value: Any, max_chars: int) -> str:
    if value is None:
        return ""
    text = str(value)
    if text.startswith(WRAPPER_START) and text.endswith(WRAPPER_END):
        text = text[len(WRAPPER_START):-len(WRAPPER_END)]
    text = CONTROL_CHARS.sub("", text)
    # Keep content as text, but neutralize any attempt to forge our wrapper boundary.
    text = re.sub(r"<\s*/?\s*untrusted_buyer_data\b[^>]*>", "[REDACTED_BOUNDARY_TAG]", text, flags=re.I)
    return text[:max_chars]


def _optional_bool(value: Any) -> Optional[bool]:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    return None


def build_model_context(context: Any, *, max_text_field_chars: int = 800) -> Dict[str, Any]:
    """Build only model-relevant features. Never serialize the P3 dataclass wholesale."""
    if max_text_field_chars < 1:
        raise ValueError("max_text_field_chars must be positive")

    current_text = {
        "sku": _unwrap_and_clean(_get(context, "untrusted_sku_xml"), max_text_field_chars),
        "item_name": _unwrap_and_clean(_get(context, "untrusted_item_name_xml"), max_text_field_chars),
        "description": _unwrap_and_clean(_get(context, "untrusted_description_xml"), max_text_field_chars),
        "note_to_payer": _unwrap_and_clean(_get(context, "untrusted_note_to_payer_xml"), max_text_field_chars),
    }
    anchor_text = {
        "sku": _unwrap_and_clean(_get(context, "anchor_untrusted_sku_xml"), max_text_field_chars),
        "item_name": _unwrap_and_clean(_get(context, "anchor_untrusted_item_name_xml"), max_text_field_chars),
        "description": _unwrap_and_clean(_get(context, "anchor_untrusted_description_xml"), max_text_field_chars),
        "note_to_payer": _unwrap_and_clean(_get(context, "anchor_untrusted_note_to_payer_xml"), max_text_field_chars),
    }

    # The raw cart_fingerprint field is deliberately never read here. P3 retains its legacy XML
    # wrapper only for callback compatibility; the model receives this enum instead.
    payload: Dict[str, Any] = {
        "decision_mode": str(_get(context, "decision_mode", "UNKNOWN")),
        "p1_evidence": {
            "sku_category": str(_get(context, "sku_category", "untagged")),
            "repeat_count": int(_get(context, "repeat_count", 0) or 0),
            "time_delta_seconds": _get(context, "time_delta_seconds"),
            "is_deadlock": bool(_get(context, "is_deadlock", False)),
            "deadlock_reason": str(_get(context, "deadlock_reason", "UNKNOWN")),
            "velocity_flag_reason": str(_get(context, "velocity_flag_reason", "UNKNOWN")),
            "address_changed_vs_anchor": bool(_get(context, "address_changed_vs_anchor", False)),
            "identity_strength": str(_get(context, "identity_strength", "UNKNOWN")),
            "matched_identity_strength": str(_get(context, "matched_identity_strength", "NONE")),
            "has_reliable_identity": bool(_get(context, "has_reliable_identity", False)),
            "used_ip_fallback": bool(_get(context, "used_ip_fallback", False)),
            "variant_match_mode": _get(context, "variant_match_mode"),
            "cart_fingerprint_complete": bool(_get(context, "cart_fingerprint_complete", False)),
            "refund_count_in_window": int(_get(context, "refund_count_in_window", 0) or 0),
            "time_since_last_refund_seconds": _get(context, "time_since_last_refund_seconds"),
            "deadlock_match_confidence": str(_get(context, "deadlock_match_confidence", "NONE")),
            "has_prompt_injection_signal": _optional_bool(_get(context, "has_prompt_injection_signal")),
            "has_retry_marker_signal": _optional_bool(_get(context, "has_retry_marker_signal")),
            "cart_relationship": str(_get(context, "cart_relationship", "UNKNOWN")),
            "same_amount_as_anchor": _optional_bool(_get(context, "same_amount_as_anchor")),
            "same_currency_as_anchor": _optional_bool(_get(context, "same_currency_as_anchor")),
            "anchor_cart_fingerprint_complete": _optional_bool(_get(context, "anchor_cart_fingerprint_complete")),
            "p1_auto_capture_eligible": bool(_get(context, "p1_auto_capture_eligible", False)),
        },
        "current_item_text_untrusted": current_text,
        "anchor_item_text_untrusted": anchor_text,
    }
    return payload
