"""OpenAI Responses API adapter using Pydantic Structured Outputs, with SDK retries off."""
from __future__ import annotations

from ..provider_errors import ProviderCallError, ProviderErrorKind, ProviderOutputError, classify_provider_exception
from ..schema import CheckoutTriageOutput, normalize_output
from ..triage_prompt import CHECKOUT_SYSTEM_PROMPT


class OpenAIProvider:
    name = "openai"

    def __init__(self, *, api_key: str, model: str):
        if not model:
            raise ValueError("OpenAI model is required")
        self.model = model
        self.api_key = api_key
        self._client = None
        self.last_usage = {"input_tokens": None, "output_tokens": None}

    def analyze(self, serialized_context: str, *, timeout_seconds: float,
                max_output_tokens: int) -> CheckoutTriageOutput:
        if not self.api_key:
            raise ProviderCallError(self.name, ProviderErrorKind.AUTH, "OpenAI API key is not configured")
        try:
            if self._client is None:
                try:
                    from openai import OpenAI
                except ImportError as exc:
                    raise ProviderCallError(self.name, ProviderErrorKind.AUTH, "openai package is not installed") from exc
                self._client = OpenAI(api_key=self.api_key, max_retries=0, timeout=5.0)
            client = self._client.with_options(timeout=max(0.05, timeout_seconds), max_retries=0)
            response = client.responses.parse(
                model=self.model,
                input=[
                    {"role": "system", "content": CHECKOUT_SYSTEM_PROMPT},
                    {"role": "user", "content": serialized_context},
                ],
                text_format=CheckoutTriageOutput,
                max_output_tokens=max_output_tokens,
            )
            usage = getattr(response, "usage", None)
            if usage is not None:
                self.last_usage = {
                    "input_tokens": getattr(usage, "input_tokens", None),
                    "output_tokens": getattr(usage, "output_tokens", None),
                }
            parsed = getattr(response, "output_parsed", None)
            if parsed is None:
                # A refusal is not an invitation to retry with a second policy/model.
                refusal = False
                for item in getattr(response, "output", []) or []:
                    for content in getattr(item, "content", []) or []:
                        if getattr(content, "type", "") == "refusal":
                            refusal = True
                raise ProviderOutputError(
                    self.name,
                    "OpenAI returned no parsed structured output",
                    refusal=refusal,
                )
            try:
                return normalize_output(parsed)
            except Exception as exc:
                raise ProviderOutputError(self.name, f"OpenAI structured output failed local validation: {type(exc).__name__}") from exc
        except ProviderCallError:
            raise
        except Exception as exc:
            raise classify_provider_exception(self.name, exc) from exc

    def close(self) -> None:
        try:
            if self._client is not None:
                self._client.close()
        except Exception:
            pass
