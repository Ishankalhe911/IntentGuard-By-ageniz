"""Focused tests for IntentGuard's MVP merchant/admin integration boundary."""
from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from src.config.paypal_client import PayPalAPIError, PayPalAmbiguousNetworkError, PayPalAuthError
from src.main import PersistentHybridPayPalGateway, create_app
from src.pillar3_capture_shield.intent_rewriter import rewrite_order_payload

ADMIN_KEY = "test-admin-secret-should-not-be-used-by-merchant"
MERCHANT_KEY = "test-merchant-secret-distinct-from-admin"


def make_app(tmp_path):
    return create_app(
        db_path=str(tmp_path / "integration-guards.sqlite3"),
        admin_api_key=ADMIN_KEY,
        merchant_api_key=MERCHANT_KEY,
        llm_triage_callback=lambda _ctx: {
            "classification": "LEGITIMATE_REPEAT_BUYER",
            "confidence": 0.9,
            "recommended_action": "ALLOW_CAPTURE",
            "merchant_summary": "Test-only deterministic callback.",
        },
    )


def checkout_payload():
    return {
        "intent": "CAPTURE",
        "purchase_units": [{
            "invoice_id": "INV-API-001",
            "amount": {"currency_code": "USD", "value": "10.00"},
            "items": [{
                "name": "MVP Test Item",
                "sku": "SKU-MVP-001",
                "quantity": "1",
                "unit_amount": {"currency_code": "USD", "value": "10.00"},
            }],
        }],
    }


def test_admin_and_merchant_credentials_are_separate_and_enforced(tmp_path):
    app = make_app(tmp_path)
    client = TestClient(app)

    assert client.get("/api/v1/dashboard/summary").status_code == 401
    assert client.get(
        "/api/v1/dashboard/summary",
        headers={"X-Merchant-Key": MERCHANT_KEY},
    ).status_code == 401
    assert client.get(
        "/api/v1/dashboard/summary",
        headers={"X-Admin-Key": ADMIN_KEY},
    ).status_code == 200

    payload = {"order_payload": checkout_payload(), "checkout_attempt_id": "attempt-auth-001"}
    assert client.post("/api/v1/mcp/orders/create", json=payload).status_code == 401
    assert client.post(
        "/api/v1/mcp/orders/create",
        json=payload,
        headers={"X-Admin-Key": ADMIN_KEY},
    ).status_code == 401
    assert client.post(
        "/api/v1/dashboard/holds/not-a-real-auth/void",
        json={"merchant_actor": "test", "reason": "not authorized"},
        headers={"X-Merchant-Key": MERCHANT_KEY},
    ).status_code == 401
    merchant_create = client.post(
        "/api/v1/mcp/orders/create",
        json=payload,
        headers={"X-Merchant-Key": MERCHANT_KEY},
    )
    assert merchant_create.status_code == 200, merchant_create.text
    assert merchant_create.json()["rewritten_intent"] == "AUTHORIZE"

    assert client.post(
        "/api/v1/mcp/orders/create",
        json={"order_payload": checkout_payload()},
        headers={"X-Merchant-Key": MERCHANT_KEY},
    ).status_code == 422


def test_dashboard_websocket_ticket_is_admin_authenticated_and_single_use(tmp_path):
    app = make_app(tmp_path)
    client = TestClient(app)

    assert client.post("/api/v1/dashboard/ws-ticket").status_code == 401
    issued = client.post(
        "/api/v1/dashboard/ws-ticket",
        headers={"X-Admin-Key": ADMIN_KEY},
    )
    assert issued.status_code == 200
    ticket = issued.json()["ticket"]

    with client.websocket_connect(f"/ws/dashboard?ticket={ticket}") as websocket:
        snapshot = websocket.receive_json()
        assert snapshot["type"] == "INITIAL_SNAPSHOT"

    with pytest.raises(Exception):
        with client.websocket_connect(f"/ws/dashboard?ticket={ticket}"):
            pass


def test_merchant_refund_uses_guarded_refund_and_authoritative_get(tmp_path):
    app = make_app(tmp_path)
    client = TestClient(app)
    gateway = app.state.paypal_client
    state_engine = app.state.state_engine
    service = app.state.dashboard_service

    rewritten = rewrite_order_payload(checkout_payload(), state_engine=state_engine)
    gateway.seed_approved_order(
        "ORDER-MERCHANT-REFUND-001",
        rewritten.paypal_payload,
        payer_id="BUYER-REFUND-001",
        payer_email="buyer-refund@example.test",
    )
    settled = service.settle_order("ORDER-MERCHANT-REFUND-001")
    assert settled["final_status"] == "CAPTURED"

    response = client.post(
        "/api/v1/mcp/orders/ORDER-MERCHANT-REFUND-001/refund",
        json={"reason": "MVP refund API test"},
        headers={"X-Merchant-Key": MERCHANT_KEY},
    )
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["status"] == "SUCCEEDED"
    assert data["operation_outcome"] == "SUCCEEDED"
    assert data["paypal_refund_id"]
    assert data["refund_ledger_ingestion"] == "PROCESSED"

    replay = client.post(
        "/api/v1/mcp/orders/ORDER-MERCHANT-REFUND-001/refund",
        json={"reason": "MVP refund API test"},
        headers={"X-Merchant-Key": MERCHANT_KEY},
    )
    assert replay.status_code == 409


def test_live_sandbox_mode_fails_closed_without_required_configuration(monkeypatch, tmp_path):
    for key in (
        "PAYPAL_CLIENT_ID", "PAYPAL_CLIENT_SECRET", "PAYPAL_WEBHOOK_ID",
        "INTENTGUARD_ADMIN_API_KEY", "INTENTGUARD_MERCHANT_API_KEY",
    ):
        monkeypatch.delenv(key, raising=False)

    with pytest.raises(RuntimeError, match="live_sandbox mode is fail-closed"):
        create_app(db_path=str(tmp_path / "live.sqlite3"), paypal_mode="live_sandbox")


def test_live_gateway_disables_local_simulation_records():
    class DummyLiveClient:
        def create_order(self, payload, paypal_request_id=None):
            return {"id": "PAYPAL-LIVE-ORDER", "status": "CREATED"}

    gateway = PersistentHybridPayPalGateway(
        live_sandbox_client=DummyLiveClient(),
        allow_local_simulation=False,
    )
    with pytest.raises(RuntimeError, match="seeding is disabled"):
        gateway.seed_approved_order("SIM-ORDER", checkout_payload(), payer_id=None, payer_email=None)
    with pytest.raises(RuntimeError, match="Local simulation is disabled"):
        gateway.create_order({**checkout_payload(), "_force_local_sim": True})


def test_paypal_error_contract_distinguishes_auth_rejection_and_ambiguity():
    from src.api_errors import paypal_http_exception

    auth = paypal_http_exception(PayPalAuthError("bad oauth", status_code=401))
    rejected = paypal_http_exception(PayPalAPIError("rejected", status_code=422, issue="INVALID_REQUEST"))
    ambiguous = paypal_http_exception(PayPalAmbiguousNetworkError("timeout", paypal_request_id="ig-test-id"))

    assert auth.status_code == 502
    assert auth.detail["operation_outcome"] == "NOT_SUBMITTED"
    assert rejected.status_code == 422
    assert rejected.detail["operation_outcome"] == "REJECTED"
    assert ambiguous.status_code == 202
    assert ambiguous.detail["operation_outcome"] == "UNKNOWN"
    assert ambiguous.detail["reconciliation_required"] is True


def test_live_sandbox_mode_uses_live_gateway_and_enforces_webhook_signature(monkeypatch, tmp_path):
    monkeypatch.setenv("PAYPAL_CLIENT_ID", "sandbox-client-id-for-test")
    monkeypatch.setenv("PAYPAL_CLIENT_SECRET", "sandbox-client-secret-for-test")
    monkeypatch.setenv("PAYPAL_WEBHOOK_ID", "WH-TEST-CONFIGURED")
    monkeypatch.setenv("PAYPAL_BASE_URL", "https://api-m.sandbox.paypal.com")

    app = create_app(
        db_path=str(tmp_path / "live-mode.sqlite3"),
        admin_api_key=ADMIN_KEY,
        merchant_api_key=MERCHANT_KEY,
        paypal_mode="live_sandbox",
        llm_triage_callback=lambda _ctx: {
            "classification": "LEGITIMATE_REPEAT_BUYER",
            "confidence": 0.9,
            "recommended_action": "ALLOW_CAPTURE",
            "merchant_summary": "Test-only callback.",
        },
    )

    assert app.state.paypal_mode == "live_sandbox"
    assert app.state.paypal_client.allow_local_simulation is False
    assert app.state.webhook_handler.verify_webhook_signature is True
    assert app.state.webhook_handler.webhook_id == "WH-TEST-CONFIGURED"


def test_live_gateway_never_accepts_synthetic_webhook_signature():
    class LiveVerifier:
        def __init__(self):
            self.calls = []

        def verify_webhook_signature(self, **kwargs):
            self.calls.append(kwargs)
            return False

    verifier = LiveVerifier()
    gateway = PersistentHybridPayPalGateway(
        live_sandbox_client=verifier,
        allow_local_simulation=False,
    )

    accepted = gateway.verify_webhook_signature(
        auth_algo="test-algorithm",
        cert_url="https://api-m.sandbox.paypal.com/cert",
        transmission_id="transmission-1",
        transmission_sig="SIM-VALID-SIG-event-1",
        transmission_time="2026-11-09T10:00:00Z",
        webhook_id="WH-LIVE-TEST",
        webhook_event={"id": "event-1", "event_type": "PAYMENT.CAPTURE.REFUNDED"},
    )

    assert accepted is False
    assert len(verifier.calls) == 1
    assert verifier.calls[0]["transmission_sig"] == "SIM-VALID-SIG-event-1"


def test_local_simulation_gateway_still_accepts_matching_synthetic_webhook_signature():
    gateway = PersistentHybridPayPalGateway(allow_local_simulation=True)
    accepted = gateway.verify_webhook_signature(
        auth_algo="SIM",
        cert_url="https://example.test/cert",
        transmission_id="sim-transmission",
        transmission_sig="SIM-VALID-SIG-event-local",
        transmission_time="2026-11-09T10:00:00Z",
        webhook_id="WH-LOCAL-TEST",
        webhook_event={"id": "event-local"},
    )
    assert accepted is True


def test_checkout_attempt_id_produces_stable_paypal_request_id(tmp_path):
    class RecordingPayPalClient:
        def __init__(self):
            self.request_ids = []
            self.counter = 0

        def create_order(self, payload, paypal_request_id=None):
            self.request_ids.append(paypal_request_id)
            self.counter += 1
            return {"id": f"PAYPAL-ORDER-{self.counter}", "status": "CREATED"}

    provider = RecordingPayPalClient()
    app = create_app(
        db_path=str(tmp_path / "idempotency.sqlite3"),
        paypal_client=provider,
        admin_api_key=ADMIN_KEY,
        merchant_api_key=MERCHANT_KEY,
        llm_triage_callback=lambda _ctx: {},
    )
    client = TestClient(app)
    headers = {"X-Merchant-Key": MERCHANT_KEY}

    for attempt_id in ("checkout-logical-001", "checkout-logical-001", "checkout-logical-002"):
        response = client.post(
            "/api/v1/mcp/orders/create",
            json={"order_payload": checkout_payload(), "checkout_attempt_id": attempt_id},
            headers=headers,
        )
        assert response.status_code == 200, response.text

    assert provider.request_ids[0]
    assert provider.request_ids[0] == provider.request_ids[1]
    assert provider.request_ids[0] != provider.request_ids[2]


def test_merchant_refund_ambiguous_result_triggers_get_reconciliation_not_second_post(tmp_path, monkeypatch):
    app = make_app(tmp_path)
    client = TestClient(app)
    gateway = app.state.paypal_client
    state_engine = app.state.state_engine
    service = app.state.dashboard_service

    rewritten = rewrite_order_payload(checkout_payload(), state_engine=state_engine)
    gateway.seed_approved_order(
        "ORDER-MERCHANT-REFUND-AMBIG-001",
        rewritten.paypal_payload,
        payer_id="BUYER-REFUND-AMBIG-001",
        payer_email="buyer-ambig@example.test",
    )
    settled = service.settle_order("ORDER-MERCHANT-REFUND-AMBIG-001")
    assert settled["final_status"] == "CAPTURED"

    monkeypatch.setattr(
        service,
        "execute_guarded_refund",
        lambda **_kwargs: {
            "executed": False,
            "status": "RECONCILIATION_REQUIRED",
            "message": "Original refund POST outcome is unknown.",
            "paypal_refund_id": None,
            "operation_id": "op:cap:CAPTURE-UNKNOWN-001",
        },
    )
    reconciled_ids = []

    def reconcile(operation_id):
        reconciled_ids.append(operation_id)
        return SimpleNamespace(
            status="RECONCILIATION_REQUIRED",
            message="Fresh PayPal GET has not resolved the outcome yet.",
            paypal_refund_id=None,
            operation=None,
        )

    monkeypatch.setattr(service.settlement_client, "reconcile_guarded_refund", reconcile)
    response = client.post(
        "/api/v1/mcp/orders/ORDER-MERCHANT-REFUND-AMBIG-001/refund",
        json={"reason": "Ambiguous refund test"},
        headers={"X-Merchant-Key": MERCHANT_KEY},
    )

    assert response.status_code == 202, response.text
    assert reconciled_ids == ["op:cap:CAPTURE-UNKNOWN-001"]
    assert response.json()["operation_outcome"] == "RECONCILIATION_REQUIRED"
    assert response.json()["reconciliation_required"] is True
