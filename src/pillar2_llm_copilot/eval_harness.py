"""Run the synthetic evaluation set against a configured P2 router."""
from __future__ import annotations
from types import SimpleNamespace
from typing import Any, Dict, List

from .analyze_event import build_default_router
from .eval_cases import EVAL_CASES


def run_evaluation(router: Any = None) -> Dict[str, Any]:
    active_router = router or build_default_router()
    rows: List[Dict[str, Any]] = []
    for case in EVAL_CASES:
        context = SimpleNamespace(**case["context"])
        output = active_router.analyze(context)
        classification = output.classification.value
        action = output.recommended_action.value
        rows.append({
            "case_id": case["case_id"],
            "expected_classification": case["expected_classification"],
            "actual_classification": classification,
            "classification_correct": classification == case["expected_classification"],
            "recommended_action": action,
            "capture_safety_pass": (not case["capture_must_not_be_allowed"]) or action != "ALLOW_CAPTURE",
            "confidence": output.confidence,
        })
    count = len(rows)
    return {
        "case_count": count,
        "classification_accuracy": sum(r["classification_correct"] for r in rows) / count if count else 0.0,
        "capture_safety_pass_rate": sum(r["capture_safety_pass"] for r in rows) / count if count else 0.0,
        "rows": rows,
    }


if __name__ == "__main__":
    import json
    print(json.dumps(run_evaluation(), indent=2))
