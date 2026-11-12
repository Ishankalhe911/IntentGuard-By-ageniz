"""Pillar 4 MCP Agent Pre-Execution Gate & Merchant Storefront Routes (`routes/mcp_gate.py`).

Responsibilities:
- `POST /api/v1/dashboard/orders/create` & `POST /api/v1/mcp/orders/create`:
  Intercepts AI agent / merchant checkout order payloads, enforces the locked MVP shape contract
  (`len(purchase_units) == 1`, no `payment_instruction`, no caller `payee`, non-empty `items` if present),
  and rewrites `intent: "CAPTURE"` -> `"AUTHORIZE"`.
- `POST /api/v1/dashboard/orders/{order_id}/settle` & `POST /api/v1/mcp/orders/{order_id}/settle`:
  Settles an `APPROVED` PayPal order through P1 + P2 + P3 (and enforces the 24h Chronic Refund Watchlist
  `auto_hold_enabled` circuit breaker when toggled by the merchant).
- `GET /api/v1/mcp/orders/{order_id}/gate-status`:
  Sanitized status gate for an MCP agent or merchant storefront to inspect whether an order is
  `CAPTURED`, `AUTHORIZED_HOLD` (do NOT retry!), `VOIDED`, or `NEEDS_ATTENTION`.
- `POST /api/v1/mcp/orders/{order_id}/refund`:
  Merchant-authenticated guarded refund endpoint (`X-Merchant-Key`) that executes a guarded PayPal
  refund via `WebhookRefundMutex` and ingests the verified refund into P1 `BuyRefundDeadlockDetector`
  and P4 `ChronicRefundLoopMonitor`.
- `POST /api/v1/mcp/orders/{order_id}/simulate-buyer-approval`:
  Explicit local-simulation helper (`X-Merchant-Key`) that transitions a local simulated order from
  `CREATED` to `APPROVED` with customizable buyer identity (`payer_id`, `payer_email`, `shipping_address`).
  Strictly rejected (`HTTP 409`) when the firewall is running in `live_sandbox` mode.
- `POST /api/v1/dashboard/catalog/sku-category` & `POST /api/v1/dashboard/catalog/sku-family`
  (plus merchant-authenticated `/api/v1/mcp/catalog/sku-category` & `/api/v1/mcp/catalog/sku-family`):
  Catalog policy registration (`single_seat_saas`, `non_stackable_entitlement`, variant exchange families).
"""
from __future__ import annotations

import copy
from datetime import datetime, timezone
import hmac
import os
import time
from typing import Any, Callable, Dict, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from src.api_errors import paypal_http_exception
from pydantic import BaseModel, Field
try:
    from pydantic import ConfigDict
    class _StrictModel(BaseModel):
        model_config = ConfigDict(extra="forbid")
except ImportError:
    class _StrictModel(BaseModel):
        class Config:
            extra = "forbid"

from src.config.paypal_client import (
    PayPalAmbiguousNetworkError,
    PayPalAPIError,
    PayPalAuthError,
    PayPalError,
)
from src.pillar4_dashboard_api.dashboard_service import GlassBoxDashboardService
from src.pillar4_dashboard_api.routes.kill_switch import (
    _resolve_configured_admin_key,
    make_admin_key_dependency,
)


def _resolve_configured_merchant_key(explicit_key: Optional[str] = None) -> Optional[str]:
    """Resolve active merchant SDK key, prioritizing live rotated env state (`INTENTGUARD_MERCHANT_API_KEY`)."""
    env_raw = (os.getenv("INTENTGUARD_MERCHANT_API_KEY") or os.getenv("X_MERCHANT_KEY") or "").strip()
    if env_raw and not env_raw.upper().startswith("YOUR_"):
        return env_raw
    raw = (explicit_key or "").strip()
    if not raw or raw.upper().startswith("YOUR_"):
        return None
    return raw


def make_merchant_key_dependency(
    explicit_key: Optional[str] = None,
    explicit_admin_key: Optional[str] = None,
) -> Callable[..., None]:
    """Legacy single-key dependency. New multi-merchant routes use TenantSecurityMiddleware.

    This helper intentionally fails closed and never treats an admin credential as a merchant key.
    It remains exported for compatibility with callers that still use a single configured merchant.
    """
    def _verify_merchant_key(
        x_merchant_key: Optional[str] = Header(default=None, alias="X-Merchant-Key"),
        authorization: Optional[str] = Header(default=None, alias="Authorization"),
    ) -> None:
        expected = _resolve_configured_merchant_key(explicit_key)
        if not expected:
            raise HTTPException(status_code=503, detail="Merchant API-key authentication is not configured.")
        candidate = (x_merchant_key or "").strip()
        if not candidate and authorization:
            auth_val = authorization.strip()
            if auth_val.lower().startswith("bearer "):
                candidate = auth_val[7:].strip()
        if not candidate:
            raise HTTPException(
                status_code=401,
                detail={
                    "code": "MISSING_MERCHANT_API_KEY",
                    "message": "Missing required X-Merchant-Key header for merchant route.",
                    "operation_outcome": "REJECTED",
                    "retryable": False,
                    "reconciliation_required": False,
                    "retry_instruction": "Configure a merchant API key in the SDK.",
                },
            )
        if not hmac.compare_digest(candidate.encode("utf-8"), expected.encode("utf-8")):
            raise HTTPException(
                status_code=403,
                detail={
                    "code": "INVALID_MERCHANT_API_KEY",
                    "message": "Invalid X-Merchant-Key credentials for merchant route.",
                    "operation_outcome": "REJECTED",
                    "retryable": False,
                    "reconciliation_required": False,
                    "retry_instruction": "Verify the merchant API key.",
                },
            )

    return _verify_merchant_key


def _raise_structured_paypal_http_error(exc: Exception) -> None:
    """Translate PayPal client exceptions into a deterministic SDK HTTP error contract (Issue #5)."""
    raise paypal_http_exception(exc) from exc
    if isinstance(exc, PayPalAuthError):
        raise HTTPException(
            status_code=502,
            detail={
                "code": getattr(exc, "error_name", None) or "PAYPAL_AUTH_ERROR",
                "message": str(exc),
                "operation_outcome": "NOT_SUBMITTED",
                "retryable": False,
                "reconciliation_required": False,
                "retry_instruction": "Verify PAYPAL_CLIENT_ID and PAYPAL_CLIENT_SECRET in the firewall environment.",
            },
        ) from exc
    if isinstance(exc, PayPalAmbiguousNetworkError):
        raise HTTPException(
            status_code=503,
            detail={
                "code": "PAYPAL_AMBIGUOUS_NETWORK_ERROR",
                "message": str(exc),
                "operation_outcome": "AMBIGUOUS_IN_FLIGHT",
                "retryable": True,
                "reconciliation_required": True,
                "retry_instruction": "Reuse the exact same checkout_attempt_id or run reconciliation before retrying.",
            },
        ) from exc
    if isinstance(exc, PayPalAPIError):
        raw_status = int(getattr(exc, "status_code", 422) or 422)
        http_status = raw_status if 400 <= raw_status < 500 else 502
        issue = getattr(exc, "issue", None) or getattr(exc, "error_name", None) or "PAYPAL_API_ERROR"
        raise HTTPException(
            status_code=http_status,
            detail={
                "code": str(issue),
                "message": str(exc),
                "paypal_debug_id": getattr(exc, "debug_id", None),
                "operation_outcome": "PROVIDER_REJECTED",
                "retryable": False,
                "reconciliation_required": False,
                "retry_instruction": "Do not blindly retry; inspect the PayPal validation issue and payload.",
            },
        ) from exc
    if isinstance(exc, PayPalError):
        raise HTTPException(
            status_code=502,
            detail={
                "code": "PAYPAL_PROVIDER_ERROR",
                "message": str(exc),
                "operation_outcome": "UNKNOWN",
                "retryable": False,
                "reconciliation_required": True,
                "retry_instruction": "Inspect provider status and reconcile before retrying.",
            },
        ) from exc


class CreateShieldedOrderRequest(_StrictModel):
    order_payload: Dict[str, Any]
    checkout_attempt_id: Optional[str] = None


class SettleOrderRequest(_StrictModel):
    note_to_payer: Optional[str] = None
    product_family_id: Optional[str] = None
    customer_id: Optional[str] = None
    session_id: Optional[str] = None


class SimulateBuyerApprovalRequest(_StrictModel):
    payer_id: str = Field(default="SIM-BUYER-001", min_length=1, max_length=120)
    payer_email: Optional[str] = Field(default="simulated-buyer@example.test", max_length=200)
    shipping_address: Optional[Dict[str, str]] = None


class MerchantRefundOrderRequest(_StrictModel):
    reason: str = Field(default="Merchant requested refund", min_length=1, max_length=300)
    amount: Optional[str] = None
    currency: Optional[str] = None


class SkuCategoryRequest(_StrictModel):
    sku: str = Field(..., min_length=1, max_length=120)
    category: str = Field(..., min_length=1, max_length=80)


class SkuFamilyRequest(_StrictModel):
    sku: str = Field(..., min_length=1, max_length=120)
    family_id: str = Field(..., min_length=1, max_length=120)


def build_mcp_gate_router(
    *,
    dashboard_service: GlassBoxDashboardService,
    webhook_handler: Optional[Any] = None,
    admin_api_key: Optional[str] = None,
    merchant_api_key: Optional[str] = None,
) -> APIRouter:
    """Create the MCP Agent Gate, Shielded Order Creation, Settlement, Refund, and Catalog Policy router."""
    router = APIRouter(tags=["Pillar 4: MCP Agent Gate & Checkout Shield"])
    verify_admin = make_admin_key_dependency(admin_api_key)
    verify_merchant = make_merchant_key_dependency(merchant_api_key, admin_api_key)

    def get_service() -> GlassBoxDashboardService:
        return dashboard_service

    @router.post("/api/v1/dashboard/orders/create")
    @router.post("/api/v1/mcp/orders/create")
    def create_order_route(
        body: CreateShieldedOrderRequest,
        request: Request,
        svc: GlassBoxDashboardService = Depends(get_service),
    ) -> Dict[str, Any]:
        try:
            result = svc.create_shielded_order(
                body.order_payload, checkout_attempt_id=body.checkout_attempt_id
            )
            merchant_id = getattr(request.state, "merchant_id", None)
            if merchant_id and result.get("order_id"):
                request.app.state.merchant_security.claim_order(merchant_id, result["order_id"])
            return result
        except (ValueError, PermissionError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except PayPalError as exc:
            _raise_structured_paypal_http_error(exc)
        except RuntimeError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @router.post("/api/v1/dashboard/orders/{order_id}/settle")
    @router.post("/api/v1/mcp/orders/{order_id}/settle")
    def settle_order_route(
        order_id: str,
        body: SettleOrderRequest,
        request: Request,
        svc: GlassBoxDashboardService = Depends(get_service),
    ) -> Dict[str, Any]:
        merchant_id = getattr(request.state, "merchant_id", None)
        if merchant_id:
            store = request.app.state.merchant_security
            if not store.owns(merchant_id, "order", order_id):
                rec = svc.get_order_record(order_id)
                if not rec or not store.adopt_unassigned_order_for_sole_merchant(merchant_id, rec):
                    store.assert_owner(merchant_id, "order", order_id)
        try:
            result = svc.settle_order(
                order_id,
                note_to_payer=body.note_to_payer,
                product_family_id=body.product_family_id,
                customer_id=body.customer_id,
                session_id=body.session_id,
            )
            if merchant_id:
                rec = svc.get_order_record(order_id)
                if rec:
                    request.app.state.merchant_security.claim_order(
                        merchant_id, order_id, authorization_id=rec.authorization_id,
                        capture_id=rec.capture_id, incident_id=rec.incident_id, payer_id=rec.payer_id,
                    )
            return result
        except (ValueError, PermissionError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except PayPalError as exc:
            _raise_structured_paypal_http_error(exc)

    @router.get("/api/v1/mcp/orders/{order_id}/gate-status")
    def get_mcp_order_gate_status(
        order_id: str,
        request: Request,
        svc: GlassBoxDashboardService = Depends(get_service),
    ) -> Dict[str, Any]:
        """Sanitized pre-execution gate status for the authenticated owning merchant."""
        merchant_id = getattr(request.state, "merchant_id", None)
        if merchant_id:
            store = request.app.state.merchant_security
            if not store.owns(merchant_id, "order", order_id):
                rec0 = svc.get_order_record(order_id)
                if not rec0 or not store.adopt_unassigned_order_for_sole_merchant(merchant_id, rec0):
                    store.assert_owner(merchant_id, "order", order_id)
        rec = svc.get_order_record(order_id) if hasattr(svc, "get_order_record") else svc.state_engine.get_order(order_id)
        if rec is None:
            raise HTTPException(status_code=404, detail=f"Order '{order_id}' not found.")
        status = rec.resolution_status
        if status == "CAPTURED":
            directive = "PAYMENT_CAPTURED_COMPLETE: Do not submit duplicate orders."
            decision = "ALLOW_FULFILLMENT"
        elif status in ("AUTHORIZED_HOLD", "ANALYZING_HOLD", "NEEDS_ATTENTION"):
            directive = (
                "PAYMENT_HELD_FOR_MERCHANT_REVIEW: Funds are already authorized and held on PayPal. "
                "Do NOT retry or create a duplicate checkout order; await merchant decision."
            )
            decision = "GATE_HOLD_DO_NOT_RETRY"
        elif status == "VOIDED":
            directive = "PAYMENT_AUTHORIZATION_VOIDED: Merchant rejected or voided this authorization. Do NOT auto-retry."
            decision = "GATE_VOIDED_DO_NOT_RETRY"
        else:
            directive = f"PAYMENT_STATUS_{status}: Do NOT auto-retry."
            decision = "GATE_HOLD_DO_NOT_RETRY"
        return {
            "order_id": rec.order_id,
            "resolution_status": status,
            "mcp_gate_decision": decision,
            "agent_should_retry": False,
            "agent_directive": directive,
            "authorization_id": rec.authorization_id,
            "capture_id": rec.capture_id,
            "authorization_id_present": bool(rec.authorization_id),
            "capture_id_present": bool(rec.capture_id),
            "amount": rec.amount,
            "currency": rec.currency,
            "sku": rec.sku,
            "item_name": rec.item_name,
        }

    @router.post("/api/v1/mcp/orders/{order_id}/simulate-buyer-approval")
    def simulate_buyer_approval_route(
        order_id: str,
        body: SimulateBuyerApprovalRequest,
        request: Request,
        svc: GlassBoxDashboardService = Depends(get_service),
    ) -> Dict[str, Any]:
        """Transitions a local simulated order from CREATED to APPROVED. Blocked in live_sandbox mode."""
        clean_oid = (order_id or "").strip()
        merchant_id = getattr(request.state, "merchant_id", None)
        if merchant_id:
            store = request.app.state.merchant_security
            if not store.owns(merchant_id, "order", clean_oid):
                rec0 = svc.get_order_record(clean_oid)
                if not rec0 or not store.adopt_unassigned_order_for_sole_merchant(merchant_id, rec0):
                    store.assert_owner(merchant_id, "order", clean_oid)
        gateway_mode = getattr(request.app.state, "gateway_mode", "auto")
        gw = svc.settlement_client.paypal_client

        if gateway_mode == "live_sandbox" or getattr(gw, "allow_local_fallback", True) is False:
            raise HTTPException(
                status_code=409,
                detail={
                    "code": "SIMULATION_DISABLED_IN_LIVE_SANDBOX",
                    "message": "simulate-buyer-approval is disabled when INTENTGUARD_GATEWAY_MODE=live_sandbox. Approve the order on sandbox.paypal.com.",
                    "operation_outcome": "REJECTED",
                    "retryable": False,
                    "reconciliation_required": False,
                    "retry_instruction": "Open the PayPal Sandbox approval_url in a browser to approve the order.",
                },
            )

        if hasattr(gw, "reload_from_db"):
            gw.reload_from_db()
        orders_dict = getattr(gw, "orders", None)
        if not isinstance(orders_dict, dict) or clean_oid not in orders_dict:
            raise HTTPException(
                status_code=404,
                detail={
                    "code": "SIMULATED_ORDER_NOT_FOUND",
                    "message": f"Order '{clean_oid}' not found in local simulation store.",
                    "operation_outcome": "REJECTED",
                    "retryable": False,
                    "reconciliation_required": False,
                },
            )

        lock = getattr(gw, "_lock", None)
        if lock is not None:
            with lock:
                if hasattr(gw, "reload_from_db"):
                    gw.reload_from_db()
                order = orders_dict[clean_oid]
                order["status"] = "APPROVED"
                order["payer"] = {
                    "payer_id": body.payer_id.strip(),
                    **({"email_address": body.payer_email.strip()} if body.payer_email and body.payer_email.strip() else {}),
                }
                if body.shipping_address and order.get("purchase_units"):
                    order["purchase_units"][0]["shipping"] = {
                        "name": {"full_name": "Simulated Buyer"},
                        "address": dict(body.shipping_address),
                    }
                if hasattr(gw, "_save_to_db_locked"):
                    gw._save_to_db_locked()
                updated = copy.deepcopy(order)
        else:
            order = orders_dict[clean_oid]
            order["status"] = "APPROVED"
            order["payer"] = {
                "payer_id": body.payer_id.strip(),
                **({"email_address": body.payer_email.strip()} if body.payer_email and body.payer_email.strip() else {}),
            }
            if body.shipping_address and order.get("purchase_units"):
                order["purchase_units"][0]["shipping"] = {
                    "name": {"full_name": "Simulated Buyer"},
                    "address": dict(body.shipping_address),
                }
            if hasattr(gw, "_save_to_db_locked"):
                gw._save_to_db_locked()
            updated = copy.deepcopy(order)

        return {
            "order_id": clean_oid,
            "status": updated["status"],
            "payer": updated.get("payer"),
            "gateway_mode": gateway_mode,
        }

    @router.post("/api/v1/mcp/orders/{order_id}/refund")
    def merchant_refund_order_route(
        order_id: str,
        body: MerchantRefundOrderRequest,
        request: Request,
        svc: GlassBoxDashboardService = Depends(get_service),
    ) -> Dict[str, Any]:
        """Merchant-authenticated guarded refund endpoint (`X-Merchant-Key`)."""
        clean_oid = (order_id or "").strip()
        merchant_id = getattr(request.state, "merchant_id", None)
        if merchant_id:
            store = request.app.state.merchant_security
            if not store.owns(merchant_id, "order", clean_oid):
                rec0 = svc.get_order_record(clean_oid)
                if not rec0 or not store.adopt_unassigned_order_for_sole_merchant(merchant_id, rec0):
                    store.assert_owner(merchant_id, "order", clean_oid)
        rec = svc.get_order_record(clean_oid) if hasattr(svc, "get_order_record") else svc.state_engine.get_order(clean_oid)
        if rec is None or not rec.capture_id:
            raise HTTPException(
                status_code=404,
                detail={
                    "code": "CAPTURED_ORDER_NOT_FOUND",
                    "message": f"Captured order '{clean_oid}' not found or has no capture_id.",
                    "operation_outcome": "REJECTED",
                    "retryable": False,
                    "reconciliation_required": False,
                },
            )
        try:
            res = svc.execute_guarded_refund(
                order_id=rec.order_id,
                capture_id=rec.capture_id,
                amount=body.amount or rec.amount,
                currency=body.currency or rec.currency,
                reason=body.reason,
                caller_source="MERCHANT_STOREFRONT_SDK",
            )
        except (ValueError, RuntimeError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except PayPalError as exc:
            _raise_structured_paypal_http_error(exc)

        status_str = str(res.get("status") or "UNKNOWN")
        if status_str == "RECONCILIATION_REQUIRED":
            op_id = res.get("operation_id")
            if op_id and hasattr(svc.settlement_client, "reconcile_guarded_refund"):
                rec_out = svc.settlement_client.reconcile_guarded_refund(op_id)
                rec_status = str(getattr(rec_out, "status", "RECONCILIATION_REQUIRED"))
                if rec_status == "SUCCEEDED":
                    res = {
                        **res,
                        "executed": True,
                        "status": "SUCCEEDED",
                        "operation_outcome": "SUCCEEDED",
                        "reconciliation_required": False,
                        "paypal_refund_id": getattr(rec_out, "paypal_refund_id", None) or res.get("paypal_refund_id"),
                    }
                    status_str = "SUCCEEDED"
                else:
                    return JSONResponse(
                        status_code=202,
                        content={
                            **res,
                            "status": rec_status,
                            "operation_outcome": rec_status,
                            "reconciliation_required": True,
                            "retryable": False,
                            "message": getattr(rec_out, "message", res.get("message")),
                        },
                    )
            else:
                return JSONResponse(
                    status_code=202,
                    content={
                        **res,
                        "operation_outcome": "RECONCILIATION_REQUIRED",
                        "reconciliation_required": True,
                        "retryable": False,
                    },
                )



        ref_id = res.get("paypal_refund_id")
        active_wh = webhook_handler or getattr(request.app.state, "webhook_handler", None)
        gw = svc.settlement_client.paypal_client
        if status_str == "SUCCEEDED" and ref_id and active_wh is not None:
            try:
                remote_ref = gw.get_refund(ref_id)
            except Exception:
                iso_now = datetime.fromtimestamp(time.time(), tz=timezone.utc).isoformat().replace("+00:00", "Z")
                remote_ref = {
                    "id": ref_id,
                    "status": "COMPLETED",
                    "amount": {"currency_code": rec.currency, "value": body.amount or rec.amount},
                    "create_time": iso_now,
                    "links": [{"rel": "up", "href": f"https://api-m.sandbox.paypal.com/v2/payments/captures/{rec.capture_id}"}],
                }
            wh_res = active_wh.handle_webhook_payload(
                {
                    "id": f"WH-MERCHANT-REF-{ref_id}",
                    "event_type": "PAYMENT.CAPTURE.REFUNDED",
                    "resource": remote_ref,
                },
                internal_trusted_caller=True,
            )
            res["refund_ledger_ingestion"] = getattr(wh_res, "status", "PROCESSED")
        res.setdefault("operation_outcome", status_str)
        res.setdefault("reconciliation_required", False)
        return res

    @router.post("/api/v1/mcp/catalog/sku-category")
    @router.post("/api/v1/dashboard/catalog/sku-category", dependencies=[Depends(verify_admin)])
    def register_sku_category_route(
        body: SkuCategoryRequest,
        request: Request,
        svc: GlassBoxDashboardService = Depends(get_service),
    ) -> Dict[str, Any]:
        # Catalog rules still live in one shared P1 catalog. Permit merchant-side catalog
        # registration only in the single-merchant MVP; multi-tenant catalogs need a separate
        # tenant-scoped P1 policy store before this can safely be enabled for multiple merchants.
        merchant_id = getattr(request.state, "merchant_id", None)
        if merchant_id and request.app.state.merchant_security.active_merchant_count() > 1:
            raise HTTPException(status_code=409, detail="Merchant SKU catalog registration is disabled in multi-merchant mode until catalog policies are tenant-scoped. Ask the platform admin to configure shared catalog rules.")
        try:
            svc.state_engine.register_sku_category(body.sku, body.category)
            return {
                "sku": body.sku,
                "category": svc.state_engine.get_sku_category(body.sku),
                "status": "REGISTERED",
            }
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @router.post("/api/v1/mcp/catalog/sku-family")
    @router.post("/api/v1/dashboard/catalog/sku-family", dependencies=[Depends(verify_admin)])
    def register_sku_family_route(
        body: SkuFamilyRequest,
        request: Request,
        svc: GlassBoxDashboardService = Depends(get_service),
    ) -> Dict[str, Any]:
        merchant_id = getattr(request.state, "merchant_id", None)
        if merchant_id and request.app.state.merchant_security.active_merchant_count() > 1:
            raise HTTPException(status_code=409, detail="Merchant SKU catalog registration is disabled in multi-merchant mode until catalog policies are tenant-scoped. Ask the platform admin to configure shared catalog rules.")
        try:
            svc.state_engine.register_sku_family(body.sku, body.family_id)
            return {
                "sku": body.sku,
                "family_id": svc.state_engine.get_sku_family(body.sku),
                "status": "REGISTERED",
            }
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    return router