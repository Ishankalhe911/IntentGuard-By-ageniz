"""Pillar 4 Routes Package (`src/pillar4_dashboard_api/routes/__init__.py`).

Composes the three modular Pillar 4 route modules matching the repository layout:
- `events.py`: Glass-Box KPI summary, order/hold lists, 24h chronic watchlist view, webhook ingestion, WebSocket stream.
- `kill_switch.py`: 1-Tap Void, Scoped Incident Bulk Void, Guarded Merchant Approve & Capture, Guarded Refund, Reconciliation, Watchlist Policy Toggle.
- `mcp_gate.py`: Shielded order creation (`CAPTURE` -> `AUTHORIZE`), post-approval settlement, MCP agent gate-status, merchant refund, local-sim approval, and catalog policy registration.
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter

from src.pillar4_dashboard_api.dashboard_service import GlassBoxDashboardService
from src.pillar4_dashboard_api.routes.events import build_events_router
from src.pillar4_dashboard_api.routes.kill_switch import (
    ApproveCaptureHoldRequest,
    BulkVoidIncidentRequest,
    ChronicWatchlistPolicyRequest,
    GuardedRefundRequest,
    VoidHoldRequest,
    build_kill_switch_router,
    make_admin_key_dependency,
)
from src.pillar4_dashboard_api.routes.mcp_gate import (
    CreateShieldedOrderRequest,
    MerchantRefundOrderRequest,
    SettleOrderRequest,
    SimulateBuyerApprovalRequest,
    SkuCategoryRequest,
    SkuFamilyRequest,
    build_mcp_gate_router,
    make_merchant_key_dependency,
)
from src.webhooks.paypal_webhook_handler import PayPalWebhookHandler


def build_dashboard_router(
    *,
    dashboard_service: GlassBoxDashboardService,
    webhook_handler: PayPalWebhookHandler,
    admin_api_key: Optional[str] = None,
    merchant_api_key: Optional[str] = None,
) -> APIRouter:
    """Assemble `events`, `kill_switch`, and `mcp_gate` routers into a unified FastAPI APIRouter."""
    router = APIRouter()
    router.include_router(
        build_events_router(
            dashboard_service=dashboard_service,
            webhook_handler=webhook_handler,
        )
    )
    router.include_router(
        build_kill_switch_router(
            dashboard_service=dashboard_service,
            admin_api_key=admin_api_key,
        )
    )
    router.include_router(
        build_mcp_gate_router(
            dashboard_service=dashboard_service,
            admin_api_key=admin_api_key,
            merchant_api_key=merchant_api_key,
        )
    )
    return router


__all__ = [
    "build_dashboard_router",
    "build_events_router",
    "build_kill_switch_router",
    "build_mcp_gate_router",
    "make_admin_key_dependency",
    "make_merchant_key_dependency",
    "VoidHoldRequest",
    "BulkVoidIncidentRequest",
    "ApproveCaptureHoldRequest",
    "GuardedRefundRequest",
    "CreateShieldedOrderRequest",
    "SettleOrderRequest",
    "SimulateBuyerApprovalRequest",
    "MerchantRefundOrderRequest",
    "SkuCategoryRequest",
    "SkuFamilyRequest",
    "ChronicWatchlistPolicyRequest",
]