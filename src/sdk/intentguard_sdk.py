"""Drop-in synchronous Python SDK for a merchant backend integrating with IntentGuard (`src/sdk/intentguard_sdk.py`).

The SDK communicates strictly over the documented HTTP contract (`/api/v1/mcp/*`), never imports
Pillar 1-4 internals, and authenticates using `X-Merchant-Key` (`INTENTGUARD_MERCHANT_API_KEY`) —
never the dashboard administrator key (`INTENTGUARD_ADMIN_API_KEY`).
"""
from __future__ import annotations

import os
from typing import Any, Dict, Optional
import httpx


class IntentGuardError(RuntimeError):
    """Structured error raised when the IntentGuard Firewall returns a non-2xx HTTP status."""

    def __init__(self, status_code: int, detail: Any, *, response: Optional[httpx.Response] = None) -> None:
        self.status_code = status_code
        self.detail = detail
        self.response = response
        if isinstance(detail, dict):
            self.code = detail.get("code")
            self.message = detail.get("message") or str(detail)
            self.operation_outcome = detail.get("operation_outcome", "UNKNOWN")
            self.retryable = bool(detail.get("retryable", False))
            self.reconciliation_required = bool(detail.get("reconciliation_required", False))
            self.retry_instruction = detail.get("retry_instruction")
            self.paypal_debug_id = detail.get("paypal_debug_id")
        else:
            self.code = None
            self.message = str(detail)
            self.operation_outcome = "UNKNOWN"
            self.retryable = False
            self.reconciliation_required = status_code >= 500
            self.retry_instruction = "Inspect the error and reconcile before retrying."
            self.paypal_debug_id = None
        super().__init__(f"IntentGuard HTTP {status_code}: {detail}")


class IntentGuardMerchantSDK:
    """Server-side Merchant SDK for IntentGuard (`create_order`, `settle_order`, `get_gate_status`, `refund_order`)."""

    def __init__(
        self,
        firewall_url: Optional[str] = None,
        merchant_api_key: Optional[str] = None,
        *,
        timeout: float = 90.0,
        http_client: Optional[httpx.Client] = None,
    ) -> None:
        resolved_url = (firewall_url or os.getenv("INTENTGUARD_URL") or "http://127.0.0.1:8000").strip()
        resolved_key = (
            merchant_api_key
            if merchant_api_key is not None
            else os.getenv("INTENTGUARD_MERCHANT_API_KEY")
        )
        resolved_key = (resolved_key or "").strip()
        if not resolved_url or not resolved_key:
            raise ValueError(
                "firewall_url and a real merchant_api_key are required; no development credential is assumed"
            )
        self.base_url = resolved_url.rstrip("/")
        self.merchant_api_key = resolved_key
        self._client = http_client or httpx.Client(timeout=timeout)
        self._owns_client = http_client is None
        self._headers = {
            "X-Merchant-Key": self.merchant_api_key,
            "Accept": "application/json",
        }

    def _request(self, method: str, path: str, **kwargs: Any) -> Dict[str, Any]:
        req_headers = dict(self._headers)
        if "headers" in kwargs and isinstance(kwargs["headers"], dict):
            req_headers.update(kwargs.pop("headers"))
        try:
            response = self._client.request(
                method,
                f"{self.base_url}{path}",
                headers=req_headers,
                **kwargs,
            )
        except httpx.TimeoutException as exc:
            raise IntentGuardError(
                504,
                {
                    "code": "INTENTGUARD_UPSTREAM_TIMEOUT",
                    "message": f"Timed out waiting for IntentGuard Firewall / PayPal Sandbox on {method} {path}: {exc}",
                    "operation_outcome": "AMBIGUOUS_IN_FLIGHT",
                    "retryable": True,
                    "reconciliation_required": True,
                    "retry_instruction": "Check get_gate_status(order_id) before retrying; settlement may have completed.",
                },
            ) from exc
        except httpx.RequestError as exc:
            raise IntentGuardError(
                502,
                {
                    "code": "INTENTGUARD_CONNECTION_ERROR",
                    "message": f"Could not reach IntentGuard Firewall at {self.base_url}{path}: {exc}",
                    "operation_outcome": "NOT_SUBMITTED",
                    "retryable": True,
                    "reconciliation_required": False,
                    "retry_instruction": "Verify the IntentGuard Firewall server is running on port 8000.",
                },
            ) from exc
        try:
            data = response.json()
        except ValueError:
            data = {"message": response.text[:1000]}
        if response.is_error:
            detail = data.get("detail", data) if isinstance(data, dict) else data
            raise IntentGuardError(response.status_code, detail, response=response)
        return data if isinstance(data, dict) else {"data": data}

    def create_order(
        self,
        *,
        order_payload: Dict[str, Any],
        checkout_attempt_id: str,
    ) -> Dict[str, Any]:
        """Creates a shielded PayPal order (`intent: CAPTURE` -> `AUTHORIZE`) with mandatory `checkout_attempt_id`."""
        if not checkout_attempt_id or not str(checkout_attempt_id).strip():
            raise ValueError(
                "checkout_attempt_id is required and must be reused for retries of the same checkout"
            )
        return self._request(
            "POST",
            "/api/v1/mcp/orders/create",
            json={
                "order_payload": order_payload,
                "checkout_attempt_id": str(checkout_attempt_id).strip(),
            },
        )

    def settle_order(
        self,
        *,
        order_id: str,
        note_to_payer: Optional[str] = None,
        product_family_id: Optional[str] = None,
        customer_id: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Settles an APPROVED PayPal order through IntentGuard P1 + P2 + P3."""
        clean_oid = (order_id or "").strip()
        if not clean_oid:
            raise ValueError("order_id is required")
        return self._request(
            "POST",
            f"/api/v1/mcp/orders/{clean_oid}/settle",
            json={
                "note_to_payer": note_to_payer,
                "product_family_id": product_family_id,
                "customer_id": customer_id,
                "session_id": session_id,
            },
        )

    def get_gate_status(self, *, order_id: str) -> Dict[str, Any]:
        """Fetches the pre-execution MCP gate status (`ALLOW_FULFILLMENT` vs `GATE_HOLD_DO_NOT_RETRY`)."""
        clean_oid = (order_id or "").strip()
        if not clean_oid:
            raise ValueError("order_id is required")
        return self._request("GET", f"/api/v1/mcp/orders/{clean_oid}/gate-status")

    def simulate_buyer_approval(
        self,
        *,
        order_id: str,
        payer_id: str = "SIM-BUYER-001",
        payer_email: str = "simulated-buyer@example.test",
        shipping_address: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Explicit local-simulation helper; firewall rejects it with HTTP 409 in live_sandbox mode."""
        clean_oid = (order_id or "").strip()
        if not clean_oid:
            raise ValueError("order_id is required")
        body: Dict[str, Any] = {
            "payer_id": payer_id,
            "payer_email": payer_email,
        }
        if shipping_address:
            body["shipping_address"] = shipping_address
        return self._request(
            "POST",
            f"/api/v1/mcp/orders/{clean_oid}/simulate-buyer-approval",
            json=body,
        )

    def refund_order(
        self,
        *,
        order_id: str,
        reason: str = "Merchant requested refund",
        amount: Optional[str] = None,
        currency: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Executes a merchant-authenticated guarded refund and arms the 60m Deadlock Detector."""
        clean_oid = (order_id or "").strip()
        if not clean_oid:
            raise ValueError("order_id is required")
        body: Dict[str, Any] = {"reason": reason}
        if amount is not None:
            body["amount"] = str(amount)
        if currency is not None:
            body["currency"] = str(currency)
        return self._request("POST", f"/api/v1/mcp/orders/{clean_oid}/refund", json=body)

    def register_sku_category(self, *, sku: str, category: str) -> Dict[str, Any]:
        """Registers a SKU category policy (`single_seat_saas`, `non_stackable_entitlement`, etc.)."""
        return self._request(
            "POST",
            "/api/v1/mcp/catalog/sku-category",
            json={"sku": sku, "category": category},
        )

    def register_sku_family(self, *, sku: str, family_id: str) -> Dict[str, Any]:
        """Registers a SKU variant family (`TOKEN-FAM`, `SHIRT-FAM`, etc.) for 0ms variant exchange."""
        return self._request(
            "POST",
            "/api/v1/mcp/catalog/sku-family",
            json={"sku": sku, "family_id": family_id},
        )

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> "IntentGuardMerchantSDK":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()