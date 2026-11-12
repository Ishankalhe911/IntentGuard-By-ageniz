"""Deadline-bounded primary/fallback router for checkout triage."""
from __future__ import annotations

import time
from typing import Dict, Optional

from .context_builder import build_model_context
from .provider_errors import (
    ProviderCallError,
    ProviderDeadlineExceeded,
    ProviderErrorKind,
    ProviderOutputError,
    classify_provider_exception,
)
from .schema import CheckoutAction, CheckoutTriageOutput, normalize_output
from .settings import P2Settings
from .telemetry import emit_provider_event
from .token_budget import compact_json, enforce_input_budget
from .triage_prompt import CHECKOUT_SYSTEM_PROMPT


class ProviderRouter:
    def __init__(self, settings: P2Settings, providers: Dict[str, object]):
        settings.validate_configuration()
        self.settings = settings
        self.providers = providers
        if settings.primary_provider not in providers:
            raise ValueError(f"Primary provider '{settings.primary_provider}' is not configured")
        if settings.fallback_provider and settings.fallback_provider not in providers:
            raise ValueError(f"Fallback provider '{settings.fallback_provider}' is not configured")

    @staticmethod
    def _invoke(provider_name: str, provider: object, serialized: str, timeout: float,
                max_output_tokens: int) -> CheckoutTriageOutput:
        try:
            raw = provider.analyze(
                serialized,
                timeout_seconds=timeout,
                max_output_tokens=max_output_tokens,
            )
        except ProviderCallError:
            raise
        except Exception as exc:
            raise classify_provider_exception(provider_name, exc) from exc
        try:
            return normalize_output(raw)
        except Exception as exc:
            # Schema/semantic output failures do not trigger a second model call.
            raise ProviderOutputError(provider_name, f"provider output failed local validation: {type(exc).__name__}") from exc

    @staticmethod
    def _usage(provider: object) -> dict:
        value = getattr(provider, "last_usage", None)
        return value if isinstance(value, dict) else {}

    def analyze(self, context: object) -> CheckoutTriageOutput:
        model_context = build_model_context(
            context,
            max_text_field_chars=self.settings.max_text_field_chars,
        )
        serialized = compact_json(model_context)
        enforce_input_budget(
            serialized,
            CHECKOUT_SYSTEM_PROMPT,
            self.settings.max_estimated_input_tokens,
        )

        started = time.monotonic()
        deadline = started + self.settings.shared_deadline_seconds
        primary_name = self.settings.primary_provider
        primary = self.providers[primary_name]
        fallback_name = self.settings.fallback_provider
        remaining = deadline - time.monotonic()
        primary_cap = (
            self.settings.primary_timeout_seconds
            if fallback_name
            else self.settings.shared_deadline_seconds
        )
        primary_reserve = self.settings.response_buffer_seconds if fallback_name else 0.0
        primary_timeout = min(primary_cap, remaining - primary_reserve)
        if primary_timeout <= 0:
            raise ProviderDeadlineExceeded(primary_name, "no_time_remaining_for_primary_provider")

        primary_start = time.monotonic()
        try:
            output = self._invoke(
                primary_name, primary, serialized, primary_timeout, self.settings.max_output_tokens
            )
            if time.monotonic() > deadline:
                raise ProviderDeadlineExceeded(primary_name, "primary_provider_exceeded_shared_deadline")
            emit_provider_event(
                provider=primary_name, model=getattr(primary, "model", "unknown"),
                attempt=1, started_at=primary_start, outcome="success",
                input_tokens=self._usage(primary).get("input_tokens"),
                output_tokens=self._usage(primary).get("output_tokens"),
            )
            return self._apply_p1_ceiling(output, model_context)
        except ProviderCallError as exc:
            emit_provider_event(
                provider=primary_name, model=getattr(primary, "model", "unknown"),
                attempt=1, started_at=primary_start, outcome="failure", error_kind=exc.kind.value,
            )
            if not fallback_name or not exc.fallback_eligible:
                raise
            remaining = deadline - time.monotonic()
            fallback_timeout = remaining - self.settings.response_buffer_seconds
            if fallback_timeout <= 0.05:
                raise ProviderDeadlineExceeded(fallback_name, "insufficient_time_for_fallback") from exc

        fallback = self.providers[fallback_name]
        fallback_start = time.monotonic()
        try:
            output = self._invoke(
                fallback_name, fallback, serialized, fallback_timeout, self.settings.max_output_tokens
            )
            if time.monotonic() > deadline:
                raise ProviderDeadlineExceeded(fallback_name, "fallback_provider_exceeded_shared_deadline")
            emit_provider_event(
                provider=fallback_name, model=getattr(fallback, "model", "unknown"),
                attempt=2, started_at=fallback_start, outcome="success",
                input_tokens=self._usage(fallback).get("input_tokens"),
                output_tokens=self._usage(fallback).get("output_tokens"),
            )
            return self._apply_p1_ceiling(output, model_context)
        except ProviderCallError as exc:
            emit_provider_event(
                provider=fallback_name, model=getattr(fallback, "model", "unknown"),
                attempt=2, started_at=fallback_start, outcome="failure", error_kind=exc.kind.value,
            )
            raise

    @staticmethod
    def _apply_p1_ceiling(output: CheckoutTriageOutput, context: dict) -> CheckoutTriageOutput:
        eligible = bool(context.get("p1_evidence", {}).get("p1_auto_capture_eligible", False))
        if not eligible and output.recommended_action == CheckoutAction.ALLOW_CAPTURE:
            # P1 remains authoritative. Preserve the model's classification/explanation but clamp
            # the action before returning to P3; P3 independently enforces its existing hard gate.
            output = output.model_copy(update={"recommended_action": CheckoutAction.HOLD_AUTHORIZE})
        return output
