"""Environment-backed settings for the bounded Pillar 2 checkout triage path."""
from __future__ import annotations

import math
import os
from dataclasses import dataclass
from typing import Optional


class SettingsError(ValueError):
    pass


def _float_env(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = float(raw)
    except ValueError as exc:
        raise SettingsError(f"{name} must be a number") from exc
    if not math.isfinite(value) or value <= 0:
        raise SettingsError(f"{name} must be finite and greater than zero")
    return value


def _int_env(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise SettingsError(f"{name} must be an integer") from exc
    if value <= 0:
        raise SettingsError(f"{name} must be greater than zero")
    return value


def _validate_model_identifier(env_name: str, model: Optional[str]) -> None:
    """Reject copied KEY=VALUE assignments and whitespace; never silently repair config."""
    if model is None or model == "":
        return
    if not isinstance(model, str):
        raise SettingsError(f"{env_name} must be a model ID string")
    if model != model.strip() or "=" in model or any(char.isspace() for char in model):
        raise SettingsError(
            f"{env_name} must contain only the model ID, not a KEY=VALUE assignment "
            "or surrounding/embedded whitespace"
        )


@dataclass(frozen=True)
class P2Settings:
    primary_provider: str = "gemini"
    fallback_provider: Optional[str] = None
    gemini_api_key: Optional[str] = None
    gemini_model: Optional[str] = None
    openai_api_key: Optional[str] = None
    openai_model: Optional[str] = None
    shared_deadline_seconds: float = 4.5
    primary_timeout_seconds: float = 2.7
    response_buffer_seconds: float = 0.15
    p3_outer_timeout_seconds: float = 5.0
    max_output_tokens: int = 180
    max_estimated_input_tokens: int = 3500
    max_text_field_chars: int = 800

    @classmethod
    def from_env(cls) -> "P2Settings":
        # Load a local .env for development when python-dotenv is installed. In deployed
        # environments, injected process variables take precedence (override=False).
        try:
            from dotenv import load_dotenv
            load_dotenv(override=False)
        except ImportError:
            # Environment variables supplied by the runtime remain fully supported.
            pass
        fallback_raw = os.getenv("P2_FALLBACK_PROVIDER", "").strip().lower()
        settings = cls(
            primary_provider=os.getenv("P2_PRIMARY_PROVIDER", "gemini").strip().lower(),
            fallback_provider=fallback_raw or None,
            gemini_api_key=os.getenv("GEMINI_API_KEY"),
            gemini_model=os.getenv("P2_GEMINI_MODEL"),
            openai_api_key=os.getenv("OPENAI_API_KEY"),
            openai_model=os.getenv("P2_OPENAI_MODEL"),
            shared_deadline_seconds=_float_env("P2_SHARED_DEADLINE_SECONDS", 4.5),
            primary_timeout_seconds=_float_env("P2_PRIMARY_TIMEOUT_SECONDS", 2.7),
            response_buffer_seconds=_float_env("P2_RESPONSE_BUFFER_SECONDS", 0.15),
            p3_outer_timeout_seconds=_float_env("P2_P3_OUTER_TIMEOUT_SECONDS", 5.0),
            max_output_tokens=_int_env("P2_MAX_OUTPUT_TOKENS", 180),
            max_estimated_input_tokens=_int_env("P2_MAX_ESTIMATED_INPUT_TOKENS", 3500),
            max_text_field_chars=_int_env("P2_MAX_TEXT_FIELD_CHARS", 800),
        )
        settings.validate_configuration()
        return settings

    def validate_configuration(self) -> None:
        allowed = {"gemini", "openai"}
        if self.primary_provider not in allowed:
            raise SettingsError("P2_PRIMARY_PROVIDER must be 'gemini' or 'openai'")
        if self.fallback_provider and self.fallback_provider not in allowed:
            raise SettingsError("P2_FALLBACK_PROVIDER must be 'gemini', 'openai', or unset")
        if self.fallback_provider == self.primary_provider:
            raise SettingsError("P2 fallback provider must differ from primary provider")
        for field_name, value in (
            ("shared_deadline_seconds", self.shared_deadline_seconds),
            ("primary_timeout_seconds", self.primary_timeout_seconds),
            ("response_buffer_seconds", self.response_buffer_seconds),
            ("p3_outer_timeout_seconds", self.p3_outer_timeout_seconds),
        ):
            if not math.isfinite(value) or value <= 0:
                raise SettingsError(f"{field_name} must be finite and greater than zero")
        if self.shared_deadline_seconds >= self.p3_outer_timeout_seconds:
            raise SettingsError("P2 shared deadline must be shorter than P3 outer timeout")
        if self.primary_timeout_seconds > self.shared_deadline_seconds:
            raise SettingsError("P2 primary timeout cannot exceed the shared deadline")
        if self.response_buffer_seconds >= self.shared_deadline_seconds:
            raise SettingsError("P2 response buffer must be smaller than the shared deadline")
        if self.fallback_provider and (
            self.primary_timeout_seconds + self.response_buffer_seconds >= self.shared_deadline_seconds
        ):
            raise SettingsError(
                "With fallback configured, primary timeout plus response buffer must leave time for fallback"
            )
        primary_key = self.gemini_api_key if self.primary_provider == "gemini" else self.openai_api_key
        primary_model = self.gemini_model if self.primary_provider == "gemini" else self.openai_model
        if not primary_model:
            raise SettingsError(f"Model name not configured for primary provider '{self.primary_provider}'")

        # Validate all configured model IDs. This specifically catches the observed
        # P2_GEMINI_MODEL='P2_GEMINI_MODEL=gemini-3.5-flash-lite' mistake.
        _validate_model_identifier("P2_GEMINI_MODEL", self.gemini_model)
        _validate_model_identifier("P2_OPENAI_MODEL", self.openai_model)

        # A missing/invalid primary API key can fail over, but only when an independently
        # configured fallback provider is present. Otherwise there is no callable provider.
        if not primary_key and not self.fallback_provider:
            raise SettingsError(f"API key not configured for primary provider '{self.primary_provider}'")
        if self.fallback_provider == "gemini" and (not self.gemini_model or not self.gemini_api_key):
            raise SettingsError("Gemini fallback requires GEMINI_API_KEY and P2_GEMINI_MODEL")
        if self.fallback_provider == "openai" and (not self.openai_model or not self.openai_api_key):
            raise SettingsError("OpenAI fallback requires OPENAI_API_KEY and P2_OPENAI_MODEL")

    def provider_model(self, provider_name: str) -> str:
        model = self.gemini_model if provider_name == "gemini" else self.openai_model
        if not model:
            raise SettingsError(f"Model name not configured for provider '{provider_name}'")
        _validate_model_identifier(
            "P2_GEMINI_MODEL" if provider_name == "gemini" else "P2_OPENAI_MODEL",
            model,
        )
        return model
