"""Provider protocol shared by Gemini, OpenAI and deterministic test doubles."""
from __future__ import annotations
from typing import Protocol
from ..schema import CheckoutTriageOutput


class CheckoutTriageProvider(Protocol):
    name: str
    model: str

    def analyze(self, serialized_context: str, *, timeout_seconds: float,
                max_output_tokens: int) -> CheckoutTriageOutput:
        ...
