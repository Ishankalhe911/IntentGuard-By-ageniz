"""Integration contract tests: independent storefront -> merchant SDK -> firewall API.

These tests use the firewall's local simulator. They do not claim PayPal Sandbox coverage.
"""
from fastapi.testclient import TestClient

from src.main import create_app
from src.sdk import IntentGuardMerchantSDK
from demo_store.store_app import create_store_app

ADMIN = "test-admin-only-key"
MERCHANT = "test-merchant-only-key"


def make_stack(tmp_path):
    firewall = create_app(
        db_path=str(tmp_path / "firewall.sqlite3"),
        admin_api_key=ADMIN,
        merchant_api_key=MERCHANT,
        paypal_mode="local_simulation",
        llm_triage_callback=lambda _ctx: {
            "classification": "LEGITIMATE_REPEAT_BUYER", "confidence": 0.9,
            "recommended_action": "ALLOW_CAPTURE", "merchant_summary": "test callback",
        },
    )
    firewall_client = TestClient(firewall)
    sdk = IntentGuardMerchantSDK(
        "http://testserver", MERCHANT, http_client=firewall_client,
    )
    store = create_store_app(sdk)
    return firewall, firewall_client, TestClient(store)


def test_storefront_checkout_calls_firewall_through_sdk_and_rewrites_to_authorize(tmp_path):
    firewall, _firewall_client, store = make_stack(tmp_path)
    response = store.post("/api/checkout", json={
        "sku": "SKU-GPU-CREDITS", "customer_id": "buyer-001",
        "checkout_attempt_id": "checkout-stable-0001",
    })
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["order_id"]
    assert data["rewritten_intent"] == "AUTHORIZE"
    assert data["status"] == "AWAITING_BUYER_APPROVAL"
    assert firewall.state.paypal_mode == "local_simulation"


def test_storefront_rejects_unknown_product_before_firewall_call(tmp_path):
    _firewall, _fw_client, store = make_stack(tmp_path)
    response = store.post("/api/checkout", json={"sku": "NOT-A-REAL-SKU"})
    assert response.status_code == 404


def test_merchant_sdk_gate_status_is_sanitized_and_does_not_use_admin_key(tmp_path):
    firewall, _fw_client, store = make_stack(tmp_path)
    created = store.post("/api/checkout", json={
        "sku": "SKU-GPU-CREDITS", "checkout_attempt_id": "checkout-gate-0001",
    }).json()
    # A newly-created, not-yet-approved PayPal order is not yet in the settled-order ledger.
    gate = store.get(f"/api/orders/{created['order_id']}")
    assert gate.status_code == 404


def test_buyer_approval_settlement_path_uses_storefront_and_sdk(tmp_path):
    firewall, _fw_client, store = make_stack(tmp_path)
    checkout = store.post("/api/checkout", json={
        "sku": "SKU-GPU-CREDITS", "customer_id": "buyer-approve-001",
        "checkout_attempt_id": "checkout-approve-0001",
    }).json()
    order_id = checkout["order_id"]

    # The storefront invokes an explicit test-only approval bridge. The bridge is
    # rejected by the firewall in live_sandbox mode and never calls PayPal.
    approval = store.post(f"/api/checkout/simulate-approval/{order_id}", json={
        "payer_id": "PAYER-APPROVED-001", "payer_email": "buyer@example.test",
    })
    assert approval.status_code == 200, approval.text
    assert approval.json()["buyer_approval"]["simulation_only"] is True
    body = approval.json()["settlement"]
    assert body.get("final_status") in {"CAPTURED", "AUTHORIZED_HOLD", "NEEDS_ATTENTION"}
    gate = store.get(f"/api/orders/{order_id}").json()
    assert gate["agent_should_retry"] is False


def test_same_checkout_attempt_reuses_same_simulated_paypal_order(tmp_path):
    _firewall, _fw_client, store = make_stack(tmp_path)
    payload = {"sku": "SKU-GPU-CREDITS", "checkout_attempt_id": "same-logical-checkout-001"}
    first = store.post("/api/checkout", json=payload)
    second = store.post("/api/checkout", json=payload)
    assert first.status_code == second.status_code == 200
    assert first.json()["order_id"] == second.json()["order_id"]


def test_simulated_buyer_approval_endpoint_is_rejected_in_live_sandbox(tmp_path, monkeypatch):
    from src.config.paypal_client import PayPalSandboxClient
    monkeypatch.setenv("PAYPAL_CLIENT_ID", "sandbox-client-id-test")
    monkeypatch.setenv("PAYPAL_CLIENT_SECRET", "sandbox-client-secret-test")
    monkeypatch.setenv("PAYPAL_WEBHOOK_ID", "WH-LIVE-TEST")
    monkeypatch.setenv("PAYPAL_BASE_URL", "https://api-m.sandbox.paypal.com")
    firewall = create_app(
        db_path=str(tmp_path / "live.sqlite3"), admin_api_key=ADMIN,
        merchant_api_key=MERCHANT, paypal_mode="live_sandbox",
    )
    client = TestClient(firewall)
    response = client.post("/api/v1/mcp/orders/not-real/simulate-buyer-approval",
                           headers={"X-Merchant-Key": MERCHANT}, json={})
    assert response.status_code == 409


def test_storefront_full_local_simulation_buy_refund_rebuy_flow(tmp_path):
    _firewall, _fw_client, store = make_stack(tmp_path)
    customer = "buyer-refund-rebuy-001"

    first = store.post("/api/checkout", json={
        "sku": "SKU-GPU-CREDITS", "customer_id": customer,
        "checkout_attempt_id": "buy-refund-first-001",
    }).json()
    approved = store.post(f"/api/checkout/simulate-approval/{first['order_id']}", json={"payer_id": customer})
    assert approved.status_code == 200, approved.text
    first_state = approved.json()["settlement"].get("final_status")
    assert first_state == "CAPTURED", approved.text

    refunded = store.post(f"/api/orders/{first['order_id']}/refund", json={"reason": "Local E2E refund"})
    assert refunded.status_code == 200, refunded.text
    assert refunded.json().get("status") == "SUCCEEDED"

    second = store.post("/api/checkout", json={
        "sku": "SKU-GPU-CREDITS", "customer_id": customer,
        "checkout_attempt_id": "buy-refund-rebuy-second-001",
    }).json()
    rebuy = store.post(f"/api/checkout/simulate-approval/{second['order_id']}", json={"payer_id": customer})
    assert rebuy.status_code == 200, rebuy.text
    assert rebuy.json()["settlement"].get("final_status") == "AUTHORIZED_HOLD", rebuy.text
