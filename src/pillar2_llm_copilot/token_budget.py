"""Conservative local input-size guard. No per-checkout token-count API call is made."""
from __future__ import annotations

import json
import math
from typing import Any, Mapping


class InputBudgetExceeded(ValueError):
    pass


def compact_json(payload: Mapping[str, Any]) -> str:
    # Escape angle brackets to reduce the chance that data is visually confused with delimiters.
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return raw.replace("<", "\\u003c").replace(">", "\\u003e")


def estimate_tokens(text: str) -> int:
    # Heuristic only. It is intentionally conservative and is not represented as exact tokenization.
    return max(1, math.ceil(len(text) / 3.5))


def enforce_input_budget(serialized_context: str, system_prompt: str, max_tokens: int) -> int:
    estimate = estimate_tokens(serialized_context) + estimate_tokens(system_prompt)
    if estimate > max_tokens:
        raise InputBudgetExceeded(
            f"estimated_input_tokens_exceed_limit:{estimate}>{max_tokens}"
        )
    return estimate
