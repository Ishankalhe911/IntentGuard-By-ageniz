"""Pillar 4 Glass-Box Event Feed, Telemetry, Watchlist Inspection & WebSocket Routes (`routes/events.py`).

Responsibilities:
- `GET /api/v1/dashboard/summary` — Real-time KPI summary & fee savings telemetry.
- `GET /api/v1/dashboard/orders` — List all orders with 3-pillar Glass-Box decision badges.
- `GET /api/v1/dashboard/orders/{order_id}` — Detailed single-order Glass-Box view.
- `GET /api/v1/dashboard/holds` — Active `AUTHORIZED_HOLD` queue for the Merchant Cockpit.
- `GET /api/v1/dashboard/watchlist/chronic-refunds` — 24-Hour Chronic Refund-Loop Watchlist (`3+` cycles in `24h`, including `>60m` spacing).
- `GET /api/v1/dashboard/webhook-echoes` — Blocked duplicate/echo refunds from `WebhookRefundMutex`.
- `GET /api/v1/dashboard/events` — Recent real-time Glass-Box event stream buffer.
- `POST /webhooks/paypal` — Verified PayPal webhook ingestion endpoint (`PAYMENT.CAPTURE.REFUNDED`, etc.).
- `WS /ws/dashboard` — Real-time WebSocket stream for the Glass-Box Merchant Cockpit.
"""
from __future__ import annotations

from dataclasses import asdict
import json
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse

from src.pillar4_dashboard_api.dashboard_service import GlassBoxDashboardService
from src.webhooks.paypal_webhook_handler import PayPalWebhookHandler
from src.security.tenant_security import MERCHANT_SESSION_COOKIE, MerchantSecurityStore

MAX_WEBHOOK_BODY_BYTES = 262_144  # 256 KB DoS guard for public webhook endpoint


def build_events_router(
    *,
    dashboard_service: GlassBoxDashboardService,
    webhook_handler: PayPalWebhookHandler,
) -> APIRouter:
    """Create tenant-scoped Glass-Box telemetry routes plus the public verified PayPal webhook."""
    router = APIRouter(tags=["Pillar 4: Glass-Box Events & Telemetry"])

    def get_service() -> GlassBoxDashboardService:
        return dashboard_service

    def get_webhook_handler() -> PayPalWebhookHandler:
        return webhook_handler

    def _merchant_id(request: Request) -> Optional[str]:
        return getattr(request.state, "merchant_id", None)

    def _owned_orders(request: Request, svc: GlassBoxDashboardService) -> list[Dict[str, Any]]:
        orders = svc.list_orders(limit=500)
        merchant_id = _merchant_id(request)
        if not merchant_id:
            return orders
        store: MerchantSecurityStore = request.app.state.merchant_security
        allowed = store.order_ids(merchant_id)
        return [item for item in orders if str(item.get("order_id") or "") in allowed]

    def _incident_is_exclusive(store: MerchantSecurityStore, merchant_id: str, incident_id: str, svc: GlassBoxDashboardService) -> bool:
        owned = store.incident_order_ids(merchant_id, incident_id)
        if not owned:
            return False
        try:
            svc._sync_order_ledger()
            all_incident_orders = {
                str(order.order_id)
                for order in svc._dashboard_order_ledger.values()
                if str(getattr(order, "incident_id", "") or "") == incident_id
            }
        except Exception:
            return False
        return bool(all_incident_orders) and all_incident_orders.issubset(owned)

    @router.get("/api/v1/dashboard/summary")
    def get_summary(request: Request, svc: GlassBoxDashboardService = Depends(get_service)) -> Dict[str, Any]:
        merchant_id = _merchant_id(request)
        if not merchant_id:
            return svc.get_dashboard_summary()
        orders = _owned_orders(request, svc)
        status_counts = {name: 0 for name in ("CAPTURED", "AUTHORIZED_HOLD", "NEEDS_ATTENTION", "VOIDED", "ANALYZING_HOLD")}
        for item in orders:
            status = str(item.get("resolution_status") or "")
            if status in status_counts:
                status_counts[status] += 1
        echoes = [e for e in svc.get_persisted_blocked_echoes() if str(e.get("order_id") or "") in {o.get("order_id") for o in orders}]
        store: MerchantSecurityStore = request.app.state.merchant_security
        payer_ids = store.resource_ids(merchant_id, "payer")
        alerts = [a for a in svc.chronic_monitor.get_all_watchlist_alerts() if str(getattr(a, "payer_id", "")) in payer_ids]
        saved_voids = round(sum(float(o.get("estimated_fee_saved_usd") or 0) for o in orders if o.get("resolution_status") == "VOIDED"), 2)
        protected_holds = round(sum(float(o.get("paypal_fee_at_stake_usd") or 0) for o in orders if o.get("resolution_status") in ("AUTHORIZED_HOLD", "NEEDS_ATTENTION", "ANALYZING_HOLD")), 2)
        return {
            "timestamp_epoch": __import__("time").time(),
            "totals": {
                "total_orders": len(orders), "captured_count": status_counts["CAPTURED"],
                "authorized_hold_count": status_counts["AUTHORIZED_HOLD"],
                "needs_attention_count": status_counts["NEEDS_ATTENTION"], "voided_count": status_counts["VOIDED"],
                "analyzing_hold_count": status_counts["ANALYZING_HOLD"],
                "blocked_webhook_echo_count": len(echoes), "chronic_24h_watchlist_count": len(alerts),
            },
            "financial_protection": {
                "realized_fee_saved_on_voids_usd": saved_voids,
                "active_fee_protected_on_holds_usd": protected_holds,
                "total_fee_shielded_usd": round(saved_voids + protected_holds, 2),
                "chronic_24h_refund_fee_bleed_usd": round(sum(float(getattr(a, "cumulative_fee_bleed_usd", 0) or 0) for a in alerts), 2),
            },
            "active_websocket_clients": 0,
        }

    @router.get("/api/v1/dashboard/orders")
    def list_orders(
        request: Request,
        status: Optional[str] = None,
        incident_id: Optional[str] = None,
        limit: int = 100,
        svc: GlassBoxDashboardService = Depends(get_service),
    ) -> Dict[str, Any]:
        bounded_limit = max(1, min(int(limit), 500))
        items = _owned_orders(request, svc)
        if status:
            items = [o for o in items if str(o.get("resolution_status") or "").upper() == status.strip().upper()]
        if incident_id:
            items = [o for o in items if o.get("incident_id") == incident_id.strip()]
        return {"count": len(items[:bounded_limit]), "orders": items[:bounded_limit]}

    @router.get("/api/v1/dashboard/orders/{order_id}")
    def get_order_detail(
        order_id: str,
        request: Request,
        svc: GlassBoxDashboardService = Depends(get_service),
    ) -> Dict[str, Any]:
        merchant_id = _merchant_id(request)
        if merchant_id:
            request.app.state.merchant_security.assert_owner(merchant_id, "order", order_id)
        rec = svc.get_order_record(order_id) if hasattr(svc, "get_order_record") else svc.state_engine.get_order(order_id)
        if rec is None:
            raise HTTPException(status_code=404, detail=f"Order '{order_id}' not found.")
        return svc.serialize_order(rec)

    @router.get("/api/v1/dashboard/holds")
    def list_holds(
        request: Request,
        incident_id: Optional[str] = None,
        voidable_only: bool = False,
        svc: GlassBoxDashboardService = Depends(get_service),
    ) -> Dict[str, Any]:
        holds = svc.list_active_holds(incident_id=incident_id, voidable_only=voidable_only)
        merchant_id = _merchant_id(request)
        if merchant_id:
            allowed = request.app.state.merchant_security.order_ids(merchant_id)
            holds = [h for h in holds if h.get("order_id") in allowed]
        return {"count": len(holds), "holds": holds}

    @router.get("/api/v1/dashboard/watchlist/chronic-refunds")
    def list_chronic_refund_watchlist(request: Request, svc: GlassBoxDashboardService = Depends(get_service)) -> Dict[str, Any]:
        alerts = [a for a in svc.chronic_monitor.get_all_watchlist_alerts()]
        merchant_id = _merchant_id(request)
        if merchant_id:
            payer_ids = request.app.state.merchant_security.resource_ids(merchant_id, "payer")
            alerts = [a for a in alerts if str(getattr(a, "payer_id", "")) in payer_ids]
        rows = [a.to_dict() for a in alerts]
        return {"window_hours": int(svc.chronic_monitor.window_seconds // 3600), "refund_threshold": svc.chronic_monitor.refund_threshold, "order_threshold": svc.chronic_monitor.order_threshold, "count": len(rows), "alerts": rows}

    @router.get("/api/v1/dashboard/webhook-echoes")
    def list_blocked_webhook_echoes(
        request: Request, order_id: Optional[str] = None, svc: GlassBoxDashboardService = Depends(get_service),
    ) -> Dict[str, Any]:
        if hasattr(svc, "get_persisted_blocked_echoes"):
            events = svc.get_persisted_blocked_echoes(order_id=order_id)
        else:
            raw_echoes = svc.webhook_mutex.get_blocked_echoes()
            events = [asdict(e) for e in raw_echoes]
        merchant_id = _merchant_id(request)
        if merchant_id:
            allowed = request.app.state.merchant_security.order_ids(merchant_id)
            events = [e for e in events if str(e.get("order_id") or "") in allowed]
        return {"count": len(events), "blocked_echoes": events}

    @router.get("/api/v1/dashboard/events")
    def list_recent_glassbox_events(request: Request, limit: int = 50, svc: GlassBoxDashboardService = Depends(get_service)) -> Dict[str, Any]:
        bounded_limit = max(1, min(int(limit), 500))
        events = svc.ws_manager.get_recent_events(limit=bounded_limit)
        merchant_id = _merchant_id(request)
        if merchant_id:
            store: MerchantSecurityStore = request.app.state.merchant_security
            allowed_orders = store.order_ids(merchant_id)
            allowed_incidents = store.resource_ids(merchant_id, "incident")
            # Order ownership takes precedence. A shared incident may contain multiple merchants' orders.
            events = [
                e for e in events
                if (bool(e.get("order_id")) and str(e.get("order_id")) in allowed_orders)
                or (not e.get("order_id") and e.get("incident_id") and str(e.get("incident_id")) in allowed_incidents
                    and _incident_is_exclusive(store, merchant_id, str(e.get("incident_id")), svc))
            ]
        return {"count": len(events), "events": events}

    @router.post("/webhooks/paypal")
    async def receive_paypal_webhook(
        request: Request,
        handler: PayPalWebhookHandler = Depends(get_webhook_handler),
    ) -> JSONResponse:
        raw_body = await request.body()
        if len(raw_body) > MAX_WEBHOOK_BODY_BYTES:
            raise HTTPException(
                status_code=413,
                detail=f"Webhook body exceeds maximum allowed size ({MAX_WEBHOOK_BODY_BYTES} bytes).",
            )
        try:
            payload = json.loads(raw_body.decode("utf-8"))
        except Exception as exc:
            raise HTTPException(status_code=400, detail="Invalid JSON webhook body.") from exc
        headers = {str(k).lower(): str(v) for k, v in request.headers.items()}
        try:
            result = handler.handle_webhook_payload(payload, headers=headers)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return JSONResponse(status_code=result.http_status, content=result.to_dict())

    @router.websocket("/ws/dashboard")
    async def dashboard_websocket_endpoint(websocket: WebSocket, svc: GlassBoxDashboardService = Depends(get_service)) -> None:
        security_store: MerchantSecurityStore = websocket.app.state.merchant_security
        identity = None
        if getattr(websocket.app.state, "security_enforced", False):
            supplied_ticket = websocket.query_params.get("ticket")
            if supplied_ticket:
                # A supplied ticket is an explicit one-time credential. Do not fall back to
                # the session cookie if it is invalid, expired, or already consumed.
                identity = security_store.consume_ws_ticket(supplied_ticket)
            else:
                identity = security_store.resolve_session(websocket.cookies.get(MERCHANT_SESSION_COOKIE))
        if getattr(websocket.app.state, "security_enforced", False) and not identity:
            await websocket.close(code=4401, reason="Merchant login required")
            return
        if identity and getattr(identity, "is_admin", False):
            merchant_id = None  # Admins get a global view (bypass the tenant filter)
        else:
            merchant_id = identity.merchant_id if identity else None
        store = security_store

        class TenantFilteredSocket:
            def __init__(self, inner):
                self.inner = inner
            def __getattr__(self, name):
                return getattr(self.inner, name)
            async def send_text(self, data: str):
                if merchant_id:
                    try:
                        packet = json.loads(data)
                        def allowed(evt):
                            if not isinstance(evt, dict):
                                return False
                            # Do not let a shared incident identifier expose another tenant's order event.
                            if evt.get("order_id"):
                                return store.owns(merchant_id, "order", str(evt["order_id"]))
                            if evt.get("incident_id"):
                                incident_id = str(evt["incident_id"])
                                return store.owns(merchant_id, "incident", incident_id) and _incident_is_exclusive(store, merchant_id, incident_id, svc)
                            return False
                        if packet.get("type") == "INITIAL_SNAPSHOT":
                            packet["recent_events"] = [e for e in packet.get("recent_events", []) if allowed(e)]
                            data = json.dumps(packet, default=str)
                        elif packet.get("type") == "GLASSBOX_EVENT" and not allowed(packet.get("event", {})):
                            return
                    except Exception:
                        return
                await self.inner.send_text(data)
        filtered = TenantFilteredSocket(websocket)
        await svc.ws_manager.connect(filtered)
        try:
            while True:
                msg = await filtered.receive_text()
                if msg.strip().lower() == "ping":
                    await filtered.send_text('{"type":"PONG"}')
        except WebSocketDisconnect:
            svc.ws_manager.disconnect(filtered)
        except Exception:
            svc.ws_manager.disconnect(filtered)

    return router