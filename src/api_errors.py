"""Structured HTTP error translation contract for PayPal provider exceptions (`src/api_errors.py`)."""
from __future__ import annotations

from fastapi import HTTPException

from src.config.paypal_client import (
    PayPalAmbiguousNetworkError,
    PayPalAPIError,
    PayPalAuthError,
    PayPalError,
)


def paypal_http_exception(exc: Exception) -> HTTPException:
    """Translate a PayPal client exception into a deterministic FastAPI HTTPException.

    Contract verified by `tests/test_mvp_integration_guards.py`:
    - `PayPalAuthError` -> HTTP 502, `operation_outcome="NOT_SUBMITTED"`, `reconciliation_required=False`
    - `PayPalAPIError` -> HTTP 4xx (default 422) or 502, `operation_outcome="REJECTED"`, `reconciliation_required=False`
    - `PayPalAmbiguousNetworkError` -> HTTP 202, `operation_outcome="UNKNOWN"`, `reconciliation_required=True`
    """
    if isinstance(exc, PayPalAuthError):
        return HTTPException(
            status_code=502,
            detail={
                "code": getattr(exc, "error_name", None) or "PAYPAL_AUTH_ERROR",
                "message": str(exc),
                "operation_outcome": "NOT_SUBMITTED",
                "retryable": False,
                "reconciliation_required": False,
                "retry_instruction": "Verify PAYPAL_CLIENT_ID and PAYPAL_CLIENT_SECRET in the firewall environment.",
            },
        )
    if isinstance(exc, PayPalAmbiguousNetworkError):
        return HTTPException(
            status_code=202,
            detail={
                "code": "PAYPAL_AMBIGUOUS_NETWORK_ERROR",
                "message": str(exc),
                "paypal_request_id": getattr(exc, "paypal_request_id", None),
                "operation_outcome": "UNKNOWN",
                "retryable": True,
                "reconciliation_required": True,
                "retry_instruction": "Reuse the exact same checkout_attempt_id or run reconciliation before retrying.",
            },
        )
    if isinstance(exc, PayPalAPIError):
        raw_status = int(getattr(exc, "status_code", 422) or 422)
        http_status = raw_status if 400 <= raw_status < 500 else 502
        issue = getattr(exc, "issue", None) or getattr(exc, "error_name", None) or "PAYPAL_API_ERROR"
        return HTTPException(
            status_code=http_status,
            detail={
                "code": str(issue),
                "message": str(exc),
                "paypal_debug_id": getattr(exc, "debug_id", None),
                "operation_outcome": "REJECTED",
                "retryable": False,
                "reconciliation_required": False,
                "retry_instruction": "Do not blindly retry; inspect the PayPal validation issue and payload.",
            },
        )
    if isinstance(exc, PayPalError):
        return HTTPException(
            status_code=502,
            detail={
                "code": "PAYPAL_PROVIDER_ERROR",
                "message": str(exc),
                "operation_outcome": "UNKNOWN",
                "retryable": False,
                "reconciliation_required": True,
                "retry_instruction": "Inspect provider status and reconcile before retrying.",
            },
        )
    return HTTPException(
        status_code=500,
        detail={
            "code": "INTERNAL_ERROR",
            "message": str(exc),
            "operation_outcome": "UNKNOWN",
            "retryable": False,
            "reconciliation_required": True,
        },
    )