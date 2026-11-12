"""Google Gemini direct REST adapter using httpx (no google-genai SDK overhead or X-Server-Timeout injection)."""
from __future__ import annotations
import logging
import os
from pydantic import ValidationError

logger = logging.getLogger(__name__)
import json
from typing import Any, Dict, Optional

import httpx

from ..provider_errors import (
    ProviderCallError,
    ProviderErrorKind,
    ProviderOutputError,
    classify_provider_exception,
)
from ..schema import (
    CheckoutAction,
    CheckoutTriageOutput,
    Classification,
    normalize_output,
)
from ..triage_prompt import CHECKOUT_SYSTEM_PROMPT

GEMINI_API_BASE_URL = "https://generativelanguage.googleapis.com/v1beta/models"

GEMINI_RESPONSE_SCHEMA: Dict[str, Any] = {
    "type": "OBJECT",
    "properties": {
        "classification": {
            "type": "STRING",
            "enum": [item.value for item in Classification],
        },
        "confidence": {
            "type": "NUMBER",
        },
        "recommended_action": {
            "type": "STRING",
            "enum": [item.value for item in CheckoutAction],
        },
        "merchant_summary": {
            "type": "STRING",
        },
    },
    "required": [
        "classification",
        "confidence",
        "recommended_action",
        "merchant_summary",
    ],
}


class _GeminiHttpStatusError(Exception):
    """Carries HTTP status_code and response body for classify_provider_exception."""

    def __init__(self, status_code: int, message: str):
        super().__init__(f"HTTP {status_code}: {message}")
        self.status_code = status_code


def _normalize_model_id(raw_model: str) -> str:
    cleaned = raw_model.strip()
    if "=" in cleaned:
        cleaned = cleaned.split("=", 1)[1].strip()
    if cleaned.startswith("models/"):
        cleaned = cleaned[len("models/") :].strip()
    if not cleaned:
        raise ValueError("Gemini model is required")
    return cleaned


class GeminiProvider:
    name = "gemini"

    def __init__(
        self,
        *,
        api_key: str,
        model: str,
        transport: Optional[httpx.BaseTransport] = None,
    ):
        if not model or not model.strip():
            raise ValueError("Gemini model is required")
        self.api_key = api_key
        self.model = _normalize_model_id(model)
        self._transport = transport
        self.last_usage: Dict[str, Optional[int]] = {
            "input_tokens": None,
            "output_tokens": None,
        }

    def analyze(
        self,
        serialized_context: str,
        *,
        timeout_seconds: float,
        max_output_tokens: int,
    ) -> CheckoutTriageOutput:
        if not self.api_key:
            raise ProviderCallError(
                self.name, ProviderErrorKind.AUTH, "Gemini API key is not configured"
            )

        timeout_s = max(0.05, float(timeout_seconds))
        # Reserve enough token headroom for Gemini 2.5/3.x minimal thinking tokens so the
        # JSON payload is not truncated; normalize_output() still enforces merchant_summary <= 400 chars.
        effective_max_output_tokens = max(int(max_output_tokens), 512)

        url = f"{GEMINI_API_BASE_URL}/{self.model}:generateContent"
        headers = {
            "Content-Type": "application/json",
            "x-goog-api-key": self.api_key,
        }
        payload: Dict[str, Any] = {
            "systemInstruction": {
                "parts": [{"text": CHECKOUT_SYSTEM_PROMPT}],
            },
            "contents": [
                {
                    "role": "user",
                    "parts": [{"text": serialized_context}],
                }
            ],
            "generationConfig": {
                "responseMimeType": "application/json",
                "responseSchema": GEMINI_RESPONSE_SCHEMA,
                "temperature": 0,
                "maxOutputTokens": effective_max_output_tokens,
                "candidateCount": 1,
            },
        }

        try:
            with httpx.Client(
                timeout=httpx.Timeout(timeout_s),
                transport=self._transport,
            ) as client:
                response = client.post(url, headers=headers, json=payload)

            if response.status_code != 200:
                raise _GeminiHttpStatusError(response.status_code, response.text[:600])

            try:
                data = response.json()
            except ValueError as exc:
                raise ProviderOutputError(
                    self.name, "Gemini returned non-JSON HTTP response"
                ) from exc

            usage = data.get("usageMetadata") or {}
            if isinstance(usage, dict):
                self.last_usage = {
                    "input_tokens": usage.get("promptTokenCount"),
                    "output_tokens": usage.get("candidatesTokenCount"),
                }

            candidates = data.get("candidates") or []
            if not candidates or not isinstance(candidates[0], dict):
                raise ProviderOutputError(
                    self.name, "Gemini returned no candidates", refusal=True
                )

            candidate = candidates[0]
            finish_reason = str(candidate.get("finishReason") or "").upper()
            if finish_reason in (
                "SAFETY",
                "RECITATION",
                "PROHIBITED_CONTENT",
                "BLOCKLIST",
                "SPII",
            ):
                raise ProviderOutputError(
                    self.name,
                    f"Gemini blocked output with finishReason={finish_reason}",
                    refusal=True,
                )

            content = candidate.get("content") or {}
            parts = content.get("parts") if isinstance(content, dict) else None
            if not isinstance(parts, list) or not parts:
                raise ProviderOutputError(
                    self.name, "Gemini returned no structured content", refusal=True
                )

            text_chunks = [
                part.get("text", "")
                for part in parts
                if isinstance(part, dict)
                and not part.get("thought")
                and isinstance(part.get("text"), str)
            ]
            raw_text = "".join(text_chunks).strip()
            if not raw_text:
                raise ProviderOutputError(
                    self.name, "Gemini returned empty text part", refusal=True
                )

            try:
                parsed = json.loads(raw_text)
            except (TypeError, json.JSONDecodeError) as exc:
                raise ProviderOutputError(
                    self.name, "Gemini returned malformed JSON"
                ) from exc

            try:
                return normalize_output(parsed)

            except ValidationError as exc:
                validation_errors = exc.errors(
                    include_input=False,
                    include_url=False,
                )

                logger.error(
                    "Gemini Pydantic validation errors: %s",
                    json.dumps(validation_errors, default=str),
                )

                if os.getenv("INTENTGUARD_P2_DIAGNOSTICS") == "1":
                    logger.error(
                        "Gemini raw response text: %s",
                        raw_text[:4000],
                    )

                raise ProviderOutputError(
                    self.name,
                    "Gemini structured output failed local validation: "
                    + json.dumps(validation_errors, default=str),
                ) from exc

            except Exception as exc:
                raise ProviderOutputError(
                    self.name,
                    f"Gemini output normalization failed: {type(exc).__name__}",
                ) from exc
        except ProviderCallError:
            raise
        except Exception as exc:
            raise classify_provider_exception(self.name, exc) from exc