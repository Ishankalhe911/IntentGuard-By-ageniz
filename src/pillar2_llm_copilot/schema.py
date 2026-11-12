"""Provider-neutral, strict checkout triage output contract for IntentGuard Pillar 2."""
from __future__ import annotations

import math
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, field_validator, model_validator


class Classification(str, Enum):
    AGENT_RETRY_LOOP = "AGENT_RETRY_LOOP"
    BUY_REFUND_DEADLOCK = "BUY_REFUND_DEADLOCK"
    PROMPT_INJECTION = "PROMPT_INJECTION"
    LEGITIMATE_REPEAT_BUYER = "LEGITIMATE_REPEAT_BUYER"


class CheckoutAction(str, Enum):
    HOLD_AUTHORIZE = "HOLD_AUTHORIZE"
    VOID_IMMEDIATELY = "VOID_IMMEDIATELY"
    ALLOW_CAPTURE = "ALLOW_CAPTURE"


class CheckoutTriageOutput(BaseModel):
    """Only model-authored fields. P3 computes `estimated_fee_saved_usd` independently."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=False)

    classification: Classification
    confidence: float
    recommended_action: CheckoutAction
    merchant_summary: str

    @field_validator("confidence", mode="before")
    @classmethod
    def reject_boolean_confidence(cls, value: Any) -> Any:
        if isinstance(value, bool):
            raise ValueError("confidence must be numeric, not boolean")
        return value

    @field_validator("confidence")
    @classmethod
    def validate_finite_confidence(cls, value: float) -> float:
        if not math.isfinite(value) or not 0.0 <= value <= 1.0:
            raise ValueError("confidence must be finite and between 0.0 and 1.0")
        return value

    @field_validator("merchant_summary")
    @classmethod
    def validate_summary_length(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("merchant_summary must not be empty")
        if len(cleaned) > 400:
            raise ValueError("merchant_summary must be at most 400 characters")
        return cleaned

    @model_validator(mode="after")
    def validate_decision_consistency(self) -> "CheckoutTriageOutput":
        if self.recommended_action == CheckoutAction.ALLOW_CAPTURE:
            if self.classification != Classification.LEGITIMATE_REPEAT_BUYER:
                raise ValueError("ALLOW_CAPTURE requires LEGITIMATE_REPEAT_BUYER")
            if self.confidence < 0.85:
                raise ValueError("ALLOW_CAPTURE requires confidence >= 0.85")
        if self.confidence < 0.85 and self.recommended_action != CheckoutAction.HOLD_AUTHORIZE:
            raise ValueError("confidence below 0.85 requires HOLD_AUTHORIZE")
        if self.recommended_action == CheckoutAction.VOID_IMMEDIATELY:
            suspicious = {
                Classification.AGENT_RETRY_LOOP,
                Classification.BUY_REFUND_DEADLOCK,
                Classification.PROMPT_INJECTION,
            }
            if self.classification not in suspicious or self.confidence < 0.85:
                raise ValueError(
                    "VOID_IMMEDIATELY requires a suspicious classification and confidence >= 0.85"
                )
        return self


def normalize_output(value: Any) -> CheckoutTriageOutput:
    """Validate provider output locally even when the provider enforces a JSON schema."""
    if isinstance(value, CheckoutTriageOutput):
        # Revalidation ensures mutated models or custom providers cannot bypass validation.
        return CheckoutTriageOutput.model_validate(value.model_dump())
    if hasattr(value, "model_dump"):
        value = value.model_dump()
    if not isinstance(value, dict):
        raise ValueError("provider_output_must_be_object")
    return CheckoutTriageOutput.model_validate(value)
