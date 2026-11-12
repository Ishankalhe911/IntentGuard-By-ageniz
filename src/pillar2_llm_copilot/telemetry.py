"""PII-free structured telemetry for P2 provider attempts."""
from __future__ import annotations
import logging
import time
from typing import Any, Dict, Optional

logger = logging.getLogger("intentguard.pillar2")


def emit_provider_event(*, provider: str, model: str, attempt: int, started_at: float,
                        outcome: str, error_kind: Optional[str] = None,
                        input_tokens: Optional[int] = None, output_tokens: Optional[int] = None) -> None:
    latency_ms = max(0, int((time.monotonic() - started_at) * 1000))
    # Never log prompt/context contents, buyer identity, IDs, or provider response bodies.
    logger.info(
        "p2_provider_attempt provider=%s model=%s attempt=%s outcome=%s latency_ms=%s error_kind=%s input_tokens=%s output_tokens=%s",
        provider, model, attempt, outcome, latency_ms, error_kind or "none",
        input_tokens if input_tokens is not None else -1,
        output_tokens if output_tokens is not None else -1,
    )
