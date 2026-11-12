"""Pillar 4 Merchant Circuit-Breaker & Override Routes (`routes/kill_switch.py`).

Supports resolving held/flagged orders in BOTH directions plus managing the 24h Chronic Refund Watchlist:
1. Direction A (Reject & Release Hold Back to Buyer):
   - 1-Tap Void (`POST /api/v1/dashboard/holds/{authorization_id}/void` and `/api/v1/dashboard/authorizations/{authorization_id}/void`)
   - Scoped Incident Bulk Void (`POST /api/v1/dashboard/incidents/{incident_id}/bulk-void`, skipping `LEGITIMATE_REPEAT_BUYER`)
2. Direction B (Approve & Capture Held Order Into Completed Sale):
   - Guarded Merchant Approve & Capture (`POST /api/v1/dashboard/holds/{authorization_id}/approve-capture`
     and `/api/v1/dashboard/authorizations/{authorization_id}/capture`)
     verifying live PayPal `GET /v2/payments/authorizations/{id} == CREATED` and enforcing
     `validate_order_ready_for_capture(..., capture_mode='MANUAL_MERCHANT_OVERRIDE', allow_manual_override=True)`.
3. Guarded Outbound Refund, Stuck-Hold Reconciliation & 24h Chronic Loop Policy:
   - Guarded Refund (`POST /api/v1/dashboard/refunds/guarded`)
   - Stuck-Hold Reconciliation (`POST /api/v1/dashboard/reconcile`)
   - 24h Chronic Refund Buyer Auto-Hold Policy Toggle (`POST /api/v1/dashboard/watchlist/chronic-refunds/{payer_id}/policy`)
   - 24h Chronic Refund Alert Acknowledge (`POST /api/v1/dashboard/watchlist/chronic-refunds/{payer_id}/acknowledge`)
"""
from __future__ import annotations

import hmac
import os
from typing import Any, Dict, Optional

from fastapi import APIRouter, Body, Depends, Header, HTTPException, Request
from pydantic import BaseModel, Field
try:
    from pydantic import ConfigDict
    class _StrictModel(BaseModel):
        model_config = ConfigDict(extra="forbid")
except ImportError:
    class _StrictModel(BaseModel):
        class Config:
            extra = "forbid"

from src.pillar4_dashboard_api.dashboard_service import GlassBoxDashboardService
from src.security.tenant_security import MerchantSecurityStore


def _resolve_configured_admin_key(explicit_key: Optional[str] = None) -> Optional[str]:
    raw = (
        explicit_key
        if explicit_key is not None
        else (os.getenv("INTENTGUARD_ADMIN_API_KEY") or os.getenv("X_ADMIN_KEY") or "")
    ).strip()
    if not raw or raw.upper().startswith("YOUR_"):
        return None
    return raw


def make_admin_key_dependency(explicit_key: Optional[str] = None):
    """Build a constant-time `X-Admin-Key` / `Bearer` FastAPI dependency for merchant admin mutation routes."""
    def _verify_admin_key(
        request: Request,
        x_admin_key: Optional[str] = Header(default=None, alias="X-Admin-Key"),
        authorization: Optional[str] = Header(default=None, alias="Authorization"),
    ) -> None:
        expected = _resolve_configured_admin_key(explicit_key)
        if not expected:
            if getattr(request.app.state, "security_enforced", False):
                raise HTTPException(status_code=503, detail="Admin authentication is not configured.")
            return
        candidate = (x_admin_key or "").strip()
        if not candidate and authorization:
            auth_val = authorization.strip()
            if auth_val.lower().startswith("bearer "):
                candidate = auth_val[7:].strip()
        if not candidate:
            raise HTTPException(
                status_code=401,
                detail="Missing required X-Admin-Key header for merchant mutation route.",
            )
        if not hmac.compare_digest(candidate.encode("utf-8"), expected.encode("utf-8")):
            raise HTTPException(
                status_code=403,
                detail="Invalid X-Admin-Key credentials for merchant mutation route.",
            )

    return _verify_admin_key


class VoidHoldRequest(_StrictModel):
    merchant_actor: str = Field(default="merchant_admin", min_length=1, max_length=120)
    reason: str = Field(
        default="Merchant voided held authorization from Glass-Box Control Plane",
        min_length=1,
        max_length=300,
    )


class BulkVoidIncidentRequest(_StrictModel):
    merchant_actor: str = Field(default="merchant_admin", min_length=1, max_length=120)
    reason: str = Field(
        default="Scoped bulk void of incident holds from Glass-Box Control Plane",
        min_length=1,
        max_length=300,
    )


class ApproveCaptureHoldRequest(_StrictModel):
    merchant_actor: str = Field(default="merchant_admin", min_length=1, max_length=120)
    override_reason: str = Field(
        default="Verified legitimate customer order from Glass-Box Control Plane",
        min_length=3,
        max_length=300,
    )


class GuardedRefundRequest(_StrictModel):
    order_id: Optional[str] = None
    capture_id: Optional[str] = None
    amount: Optional[str] = None
    currency: Optional[str] = "USD"
    reason: str = Field(
        default="Merchant initiated guarded refund from Glass-Box Control Plane",
        min_length=1,
        max_length=300,
    )


class ChronicWatchlistPolicyRequest(_StrictModel):
    auto_hold_enabled: bool = False
    merchant_note: str = Field(default="", max_length=240)


def build_kill_switch_router(
    *,
    dashboard_service: GlassBoxDashboardService,
    admin_api_key: Optional[str] = None,
) -> APIRouter:
    """Create the Merchant Kill-Switch, Manual Override Capture, Refund, and Watchlist Policy router."""
    verify_admin = make_admin_key_dependency(admin_api_key)
    # Merchant control actions are session-authenticated and tenant-scoped by the app security layer.
    # Only platform-wide reconciliation remains admin-only.
    router = APIRouter(tags=["Pillar 4: Kill-Switch & Merchant Overrides"])

    def get_service() -> GlassBoxDashboardService:
        return dashboard_service

    def _assert_merchant_resource(request: Request, svc: GlassBoxDashboardService, resource_type: str, resource_id: str) -> None:
        merchant_id = getattr(request.state, "merchant_id", None)
        if not merchant_id:
            return
        store: MerchantSecurityStore = request.app.state.merchant_security
        if store.owns(merchant_id, resource_type, resource_id):
            return
        rec = None
        if resource_type == "authorization":
            rec = svc.state_engine.get_order_by_auth_id(resource_id)
        elif resource_type == "capture":
            rec = svc.state_engine.get_order_by_capture_id(resource_id)
        elif resource_type == "order":
            rec = svc.get_order_record(resource_id)
        if rec and store.adopt_unassigned_order_for_sole_merchant(merchant_id, rec):
            return
        store.assert_owner(merchant_id, resource_type, resource_id)

    @router.post("/api/v1/dashboard/holds/{authorization_id}/void")
    @router.post("/api/v1/dashboard/authorizations/{authorization_id}/void")
    def void_hold_route(
        authorization_id: str,
        request: Request,
        body: Optional[VoidHoldRequest] = Body(default=None),
        svc: GlassBoxDashboardService = Depends(get_service),
    ) -> Dict[str, Any]:
        _assert_merchant_resource(request, svc, "authorization", authorization_id)
        req = body or VoidHoldRequest()
        try:
            result = svc.void_held_order(
                authorization_id,
                merchant_actor=req.merchant_actor,
                reason=req.reason,
            )
            merchant_id = getattr(request.state, "merchant_id", None)
            if merchant_id:
                rec = svc.get_order_record(str(result.get("order_id") or ""))
                if rec:
                    request.app.state.merchant_security.claim_order(
                        merchant_id, rec.order_id, authorization_id=rec.authorization_id,
                        capture_id=rec.capture_id, incident_id=rec.incident_id, payer_id=rec.payer_id,
                    )
            return result
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except RuntimeError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @router.post("/api/v1/dashboard/incidents/{incident_id}/bulk-void")
    def bulk_void_incident_route(
        incident_id: str,
        request: Request,
        body: Optional[BulkVoidIncidentRequest] = Body(default=None),
        svc: GlassBoxDashboardService = Depends(get_service),
    ) -> Dict[str, Any]:
        merchant_id = getattr(request.state, "merchant_id", None)
        if merchant_id:
            store: MerchantSecurityStore = request.app.state.merchant_security
            owned_orders = store.incident_order_ids(merchant_id, incident_id)
            if not owned_orders or not store.owns(merchant_id, "incident", incident_id):
                raise HTTPException(status_code=404, detail="Incident not found.")
            # Prevent a shared incident identifier from acting on another tenant's order.
            svc._sync_order_ledger()
            incident_orders = [o for o in svc._dashboard_order_ledger.values() if o.incident_id == incident_id]
            if any(o.order_id not in owned_orders for o in incident_orders):
                raise HTTPException(status_code=409, detail="Incident contains resources outside this merchant account.")
        req = body or BulkVoidIncidentRequest()
        try:
            return svc.bulk_void_incident(
                incident_id,
                merchant_actor=req.merchant_actor,
                reason=req.reason,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @router.post("/api/v1/dashboard/holds/{authorization_id}/approve-capture")
    @router.post("/api/v1/dashboard/authorizations/{authorization_id}/capture")
    def approve_and_capture_hold_route(
        authorization_id: str,
        request: Request,
        body: Optional[ApproveCaptureHoldRequest] = Body(default=None),
        svc: GlassBoxDashboardService = Depends(get_service),
    ) -> Dict[str, Any]:
        _assert_merchant_resource(request, svc, "authorization", authorization_id)
        req = body or ApproveCaptureHoldRequest()
        try:
            result = svc.approve_and_capture_held_order(
                authorization_id,
                merchant_actor=req.merchant_actor,
                override_reason=req.override_reason,
            )
            merchant_id = getattr(request.state, "merchant_id", None)
            if merchant_id:
                rec = svc.get_order_record(str(result.get("order_id") or ""))
                if rec:
                    request.app.state.merchant_security.claim_order(
                        merchant_id, rec.order_id, authorization_id=rec.authorization_id,
                        capture_id=rec.capture_id, incident_id=rec.incident_id, payer_id=rec.payer_id,
                    )
            return result
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except RuntimeError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @router.post("/api/v1/dashboard/refunds/guarded")
    def guarded_refund_route(
        body: GuardedRefundRequest,
        request: Request,
        svc: GlassBoxDashboardService = Depends(get_service),
    ) -> Dict[str, Any]:
        merchant_id = getattr(request.state, "merchant_id", None)
        if merchant_id:
            store: MerchantSecurityStore = request.app.state.merchant_security
            if body.order_id:
                _assert_merchant_resource(request, svc, "order", body.order_id)
            elif body.capture_id:
                _assert_merchant_resource(request, svc, "capture", body.capture_id)
            else:
                raise HTTPException(status_code=422, detail="order_id or capture_id is required.")
        try:
            result = svc.execute_guarded_refund(
                order_id=body.order_id,
                capture_id=body.capture_id,
                amount=body.amount,
                currency=body.currency,
                reason=body.reason,
            )
            merchant_id = getattr(request.state, "merchant_id", None)
            if merchant_id and body.order_id:
                rec = svc.get_order_record(body.order_id)
                if rec:
                    request.app.state.merchant_security.claim_order(
                        merchant_id, rec.order_id, authorization_id=rec.authorization_id,
                        capture_id=rec.capture_id, incident_id=rec.incident_id, payer_id=rec.payer_id,
                    )
            return result
        except (ValueError, RuntimeError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @router.post("/api/v1/dashboard/reconcile")
    def reconcile_stuck_holds_route(
        older_than_seconds: float = 60.0,
        _admin: bool = Depends(verify_admin),
        svc: GlassBoxDashboardService = Depends(get_service),
    ) -> Dict[str, Any]:
        return svc.run_reconciliation_sweep(older_than_seconds=older_than_seconds)

    @router.post("/api/v1/dashboard/watchlist/chronic-refunds/{payer_id}/policy")
    def update_chronic_refund_buyer_policy(
        payer_id: str,
        body: ChronicWatchlistPolicyRequest,
        request: Request,
        svc: GlassBoxDashboardService = Depends(get_service),
    ) -> Dict[str, Any]:
        merchant_id = getattr(request.state, "merchant_id", None)
        if merchant_id:
            request.app.state.merchant_security.assert_owner(merchant_id, "payer", payer_id)
        try:
            updated = svc.chronic_monitor.set_buyer_auto_hold_policy(
                payer_id,
                enabled=body.auto_hold_enabled,
                merchant_note=body.merchant_note,
            )
            alert = svc.chronic_monitor.evaluate_buyer_24h_cycle(payer_id)
            return {
                "policy": updated,
                "current_alert": alert.to_dict() if alert else None,
            }
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @router.post("/api/v1/dashboard/watchlist/chronic-refunds/{payer_id}/acknowledge")
    def acknowledge_chronic_refund_buyer(
        payer_id: str,
        body: ChronicWatchlistPolicyRequest,
        request: Request,
        svc: GlassBoxDashboardService = Depends(get_service),
    ) -> Dict[str, Any]:
        merchant_id = getattr(request.state, "merchant_id", None)
        if merchant_id:
            request.app.state.merchant_security.assert_owner(merchant_id, "payer", payer_id)
        try:
            return svc.chronic_monitor.acknowledge_buyer_alert(
                payer_id, merchant_note=body.merchant_note
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    return router