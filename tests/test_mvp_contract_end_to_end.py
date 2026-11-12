"""Diagnostic contract tests for the frozen IntentGuard MVP.

These tests use the recovered Pillar 1 modules, the repaired Pillar 3 modules, and a fake
PayPal client. No HTTP calls, PayPal credentials, or real money movement are used.

Run from the project root:
    python -m pytest -q tests/test_mvp_contract_end_to_end.py -ra

The suite asserts the frozen MVP contract, including recovery and fail-closed behavior.
Do not convert contract failures into xfails merely to make the suite green.
"""
from __future__ import annotations

import copy
import sys
from pathlib import Path
from typing import Any, Dict, Optional

import pytest

# Support `python -m pytest` from the repository root.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.config.paypal_client import PayPalAPIError, PayPalAmbiguousNetworkError, PayPalAuthError, PayPalSandboxClient
from src.pillar1_velocity_engine.deadlock_detector import (
    BuyRefundDeadlockDetector,
    evaluate_approved_paypal_order,
    evaluate_checkout_pillar1,
)
from src.pillar1_velocity_engine.state_engine import (
    VelocityStateEngine,
    validate_order_ready_for_capture,
)
from src.pillar1_velocity_engine.webhook_mutex import WebhookRefundMutex
from src.pillar3_capture_shield.intent_rewriter import (
    create_shielded_paypal_order,
    rewrite_order_payload,
)
from src.pillar3_capture_shield import settlement_client as settlement_module
from src.pillar3_capture_shield.settlement_client import (
    PaymentOperationRecord,
    SettlementClient,
)


NOW = 1_800_000_000.0
AMOUNT = "25.00"
CURRENCY = "USD"
PAYER = "PAYER-MVP-1"
SKU = "SKU-STACKABLE-001"


def make_purchase_unit(*, sku: str = SKU, amount: str = AMOUNT) -> Dict[str, Any]:
    return {
        "reference_id": "default",
        "invoice_id": "INV-MVP-001",
        "amount": {"currency_code": CURRENCY, "value": amount},
        "items": [
            {
                "name": "MVP item",
                "sku": sku,
                "quantity": "1",
                "unit_amount": {"currency_code": CURRENCY, "value": amount},
            }
        ],
    }


def make_approved_order(
    order_id: str = "ORDER-MVP-1",
    *,
    sku: str = SKU,
    amount: str = AMOUNT,
    purchase_units: Optional[list] = None,
) -> Dict[str, Any]:
    return {
        "id": order_id,
        "status": "APPROVED",
        "intent": "AUTHORIZE",
        "payer": {"payer_id": PAYER, "email_address": "buyer@example.test"},
        "purchase_units": purchase_units if purchase_units is not None else [make_purchase_unit(sku=sku, amount=amount)],
    }


class FakePayPalClient:
    """Small, deterministic fake for the PayPal methods called by SettlementClient."""

    def __init__(self, order: Optional[Dict[str, Any]] = None):
        self.order = copy.deepcopy(order) if order is not None else None
        self.calls: list[tuple] = []
        self.authorization_status = "CREATED"
        self.authorization_id = "AUTH-MVP-1"
        self.authorize_result: Optional[Dict[str, Any]] = None
        self.capture_result = {"id": "CAP-MVP-1", "status": "COMPLETED"}
        self.refund_result = {"id": "REFUND-MVP-1", "status": "COMPLETED"}
        self.order_error: Optional[Exception] = None

    def create_order(self, payload: Dict[str, Any], paypal_request_id: Optional[str] = None):
        self.calls.append(("create_order", copy.deepcopy(payload), paypal_request_id))
        return {"id": "ORDER-CREATED-1", "status": "CREATED", "intent": payload["intent"]}

    def get_order(self, order_id: str):
        self.calls.append(("get_order", order_id))
        if self.order_error is not None:
            raise self.order_error
        assert self.order is not None
        return copy.deepcopy(self.order)

    def authorize_order(self, order_id: str, paypal_request_id: str, payload: Optional[dict] = None):
        self.calls.append(("authorize_order", order_id, paypal_request_id))
        if self.authorize_result is not None:
            return copy.deepcopy(self.authorize_result)
        return {
            "id": order_id,
            "purchase_units": [
                {"payments": {"authorizations": [{"id": self.authorization_id, "status": self.authorization_status}]}}
            ],
        }

    def get_authorization(self, authorization_id: str):
        self.calls.append(("get_authorization", authorization_id))
        return {"id": authorization_id, "status": self.authorization_status}

    def capture_authorization(self, authorization_id: str, paypal_request_id: str, payload: Optional[dict] = None):
        self.calls.append(("capture_authorization", authorization_id, paypal_request_id, copy.deepcopy(payload or {})))
        return copy.deepcopy(self.capture_result)

    def void_authorization(self, authorization_id: str, paypal_request_id: str):
        self.calls.append(("void_authorization", authorization_id, paypal_request_id))
        return {"status": "VOIDED"}

    def refund_capture(self, capture_id: str, paypal_request_id: str, payload: Optional[dict] = None):
        self.calls.append(("refund_capture", capture_id, paypal_request_id, copy.deepcopy(payload or {})))
        return copy.deepcopy(self.refund_result)

    # Deliberately present on the fake so the expected reconciliation contract can be
    # tested after PayPalSandboxClient gains the real wrapper.
    def get_refund(self, refund_id: str):
        self.calls.append(("get_refund", refund_id))
        return {"id": refund_id, "status": self.refund_result.get("status", "COMPLETED")}


@pytest.fixture

def engines():
    return VelocityStateEngine(), BuyRefundDeadlockDetector()


def seed_prior_order(state_engine: VelocityStateEngine, deadlock: BuyRefundDeadlockDetector, *, now: float = NOW - 120):
    return evaluate_checkout_pillar1(
        state_engine=state_engine,
        deadlock_detector=deadlock,
        order_id="ORDER-PRIOR-1",
        amount=AMOUNT,
        currency=CURRENCY,
        payer_id=PAYER,
        sku=SKU,
        description="MVP item",
        intent="AUTHORIZE",
        now=now,
    )


def make_settlement(order: Dict[str, Any], *, state_engine=None, deadlock=None, paypal=None, llm=None):
    state_engine = state_engine or VelocityStateEngine()
    deadlock = deadlock or BuyRefundDeadlockDetector()
    paypal = paypal or FakePayPalClient(order)
    return SettlementClient(
        paypal_client=paypal,
        state_engine=state_engine,
        deadlock_detector=deadlock,
        llm_triage_callback=llm,
    ), state_engine, deadlock, paypal


# ---------------------------------------------------------------------------
# Order creation and order-shape scope
# ---------------------------------------------------------------------------

def test_checkout_creation_rewrites_every_order_to_authorize_not_capture():
    payload = {"intent": "CAPTURE", "purchase_units": [make_purchase_unit()]}
    fake = FakePayPalClient()
    rewritten, response = create_shielded_paypal_order(
        paypal_client=fake,
        order_payload=payload,
        checkout_attempt_id="attempt-unique-001",
    )
    assert rewritten.paypal_payload["intent"] == "AUTHORIZE"
    assert response["intent"] == "AUTHORIZE"
    assert [c[0] for c in fake.calls] == ["create_order"]
    assert not any(c[0] in {"authorize_order", "capture_authorization"} for c in fake.calls)


def test_multiple_purchase_units_are_rejected_at_checkout_creation():
    payload = {
        "intent": "CAPTURE",
        "purchase_units": [make_purchase_unit(), make_purchase_unit(sku="SKU-OTHER")],
    }
    with pytest.raises(ValueError, match="exactly 1|only 1"):
        rewrite_order_payload(payload)


def test_marketplace_split_payment_fields_are_rejected_even_with_one_purchase_unit():
    """One purchase_unit does not by itself rule out marketplace/platform fee splits."""
    pu = make_purchase_unit()
    pu["payment_instruction"] = {
        "disbursement_mode": "DELAYED",
        "platform_fees": [
            {
                "amount": {"currency_code": "USD", "value": "1.00"},
                "payee": {"email_address": "platform@example.test"},
            }
        ],
    }
    with pytest.raises(ValueError, match="marketplace|split|platform|payee"):
        rewrite_order_payload({"intent": "AUTHORIZE", "purchase_units": [pu]})


def test_pillar1_rejects_capture_intent_and_multiple_purchase_units(engines):
    state_engine, deadlock = engines
    bad_intent = make_approved_order()
    bad_intent["intent"] = "CAPTURE"
    with pytest.raises(ValueError, match="AUTHORIZE"):
        evaluate_approved_paypal_order(state_engine, deadlock, bad_intent, now=NOW)

    too_many = make_approved_order(
        purchase_units=[make_purchase_unit(), make_purchase_unit(sku="SKU-OTHER")]
    )
    with pytest.raises(ValueError, match="only 1 purchase_unit"):
        evaluate_approved_paypal_order(state_engine, deadlock, too_many, now=NOW)


# ---------------------------------------------------------------------------
# One authorization / one full capture invariants
# ---------------------------------------------------------------------------

def test_one_order_cannot_be_bound_to_a_second_authorization(engines):
    state_engine, _ = engines
    state_engine.check_and_record_order(
        order_id="ORDER-AUTH-1", amount=AMOUNT, currency=CURRENCY,
        payer_id=PAYER, intent="AUTHORIZE", now=NOW,
    )
    assert state_engine.mark_order_authorized("ORDER-AUTH-1", "AUTH-1", now=NOW + 1)
    with pytest.raises(ValueError, match="already bound|cannot replace"):
        state_engine.mark_order_authorized("ORDER-AUTH-1", "AUTH-2", now=NOW + 2)


def test_one_order_cannot_register_a_second_capture(engines):
    state_engine, _ = engines
    state_engine.check_and_record_order(
        order_id="ORDER-CAP-1", amount=AMOUNT, currency=CURRENCY,
        payer_id=PAYER, intent="AUTHORIZE", now=NOW,
    )
    assert state_engine.mark_order_authorized("ORDER-CAP-1", "AUTH-CAP-1", now=NOW + 1)
    state_engine.register_capture(
        "ORDER-CAP-1", "CAP-1", authorization_id="AUTH-CAP-1", now=NOW + 2
    )
    with pytest.raises(ValueError, match="one capture|already has capture"):
        state_engine.register_capture(
            "ORDER-CAP-1", "CAP-2", authorization_id="AUTH-CAP-1", now=NOW + 3
        )


def test_partial_capture_mode_is_rejected_by_pillar1(engines):
    state_engine, _ = engines
    state_engine.check_and_record_order(
        order_id="ORDER-PARTIAL-1", amount=AMOUNT, currency=CURRENCY,
        payer_id=PAYER, intent="AUTHORIZE", now=NOW,
    )
    state_engine.mark_order_authorized("ORDER-PARTIAL-1", "AUTH-PARTIAL-1", now=NOW + 1)
    allowed, reason = validate_order_ready_for_capture(
        state_engine.get_order("ORDER-PARTIAL-1"),
        decision_allows_capture=True,
        paypal_auth_status="CREATED",
        paypal_auth_status_verified=True,
        allow_partial_captures=True,
    )
    assert allowed is False
    assert reason == "PARTIAL_CAPTURES_DISABLED_IN_MVP"


def test_public_manual_capture_path_is_disabled_and_never_calls_paypal(engines):
    state_engine, deadlock = engines
    state_engine.check_and_record_order(
        order_id="ORDER-MANUAL-1", amount=AMOUNT, currency=CURRENCY,
        payer_id=PAYER, intent="AUTHORIZE", now=NOW,
    )
    state_engine.mark_order_authorized("ORDER-MANUAL-1", "AUTH-MANUAL-1", status="AUTHORIZED_HOLD", now=NOW + 1)
    paypal = FakePayPalClient(make_approved_order("ORDER-MANUAL-1"))
    client = SettlementClient(paypal, state_engine, deadlock)
    # Check the P1 policy with all required auth evidence supplied, so we isolate
    # the manual-override restriction from the separate P3 missing-verification bug.
    allowed, reason = validate_order_ready_for_capture(
        state_engine.get_order("ORDER-MANUAL-1"),
        decision_allows_capture=False,
        capture_mode="MANUAL_MERCHANT_OVERRIDE",
        paypal_auth_status="CREATED",
        paypal_auth_status_verified=True,
        merchant_actor="merchant-1",
        override_reason="MVP disabled",
    )
    assert allowed is False
    assert reason == "MANUAL_CAPTURE_OVERRIDE_DISABLED_IN_MVP"

    # The P3 public manual entrypoint is explicitly disabled under the frozen MVP.
    with pytest.raises(PermissionError):
        client.manual_capture_authorization(
            "AUTH-MANUAL-1", merchant_actor="merchant-1", override_reason="MVP disabled",
            amount=AMOUNT, final_capture=False, paypal_auth_status="CREATED", now=NOW + 2,
        )
    assert not any(call[0] == "capture_authorization" for call in paypal.calls)


# ---------------------------------------------------------------------------
# Authorization -> (P1 + P2) -> capture sequence
# ---------------------------------------------------------------------------

def test_clean_flow_evaluates_p1_then_authorizes_then_verifies_then_captures(monkeypatch, engines):
    state_engine, deadlock = engines
    order = make_approved_order("ORDER-CLEAN-FLOW")
    trace: list[str] = []
    paypal = FakePayPalClient(order)
    client, _, _, _ = make_settlement(order, state_engine=state_engine, deadlock=deadlock, paypal=paypal)

    real_eval = settlement_module.evaluate_approved_paypal_order

    def tracked_eval(*args, **kwargs):
        trace.append("p1_evaluated")
        return real_eval(*args, **kwargs)

    monkeypatch.setattr(settlement_module, "evaluate_approved_paypal_order", tracked_eval)
    original_get_auth = paypal.get_authorization
    original_authorize = paypal.authorize_order
    original_capture = paypal.capture_authorization

    def tracked_authorize(*args, **kwargs):
        trace.append("authorize")
        return original_authorize(*args, **kwargs)

    def tracked_get_auth(*args, **kwargs):
        trace.append("get_authorization")
        return original_get_auth(*args, **kwargs)

    def tracked_capture(*args, **kwargs):
        trace.append("capture")
        return original_capture(*args, **kwargs)

    paypal.authorize_order = tracked_authorize
    paypal.get_authorization = tracked_get_auth
    paypal.capture_authorization = tracked_capture

    outcome = client.settle_approved_order("ORDER-CLEAN-FLOW", now=NOW)
    assert outcome.final_status == "CAPTURED"
    assert trace.index("p1_evaluated") < trace.index("authorize")
    assert trace.index("authorize") < trace.index("get_authorization") < trace.index("capture")


def test_flagged_flow_waits_for_both_authorize_and_p2_approval_before_capture(monkeypatch, engines):
    state_engine, deadlock = engines
    seed_prior_order(state_engine, deadlock)
    order = make_approved_order("ORDER-FLAGGED-FLOW")
    trace: list[str] = []
    paypal = FakePayPalClient(order)

    def llm_callback(_context):
        trace.append("p2_completed")
        return {
            "classification": "LEGITIMATE_REPEAT_BUYER",
            "confidence": 0.99,
            "recommended_action": "ALLOW_CAPTURE",
            "estimated_fee_saved_usd": 0,
            "merchant_summary": "Verified legitimate repeat purchase.",
        }

    client, _, _, _ = make_settlement(
        order, state_engine=state_engine, deadlock=deadlock, paypal=paypal, llm=llm_callback
    )
    real_eval = settlement_module.evaluate_approved_paypal_order

    def tracked_eval(*args, **kwargs):
        trace.append("p1_evaluated")
        return real_eval(*args, **kwargs)

    monkeypatch.setattr(settlement_module, "evaluate_approved_paypal_order", tracked_eval)
    original_authorize = paypal.authorize_order
    original_get_auth = paypal.get_authorization
    original_capture = paypal.capture_authorization

    def tracked_authorize(*args, **kwargs):
        trace.append("authorize")
        return original_authorize(*args, **kwargs)

    def tracked_get_auth(*args, **kwargs):
        trace.append("get_authorization")
        return original_get_auth(*args, **kwargs)

    def tracked_capture(*args, **kwargs):
        trace.append("capture")
        return original_capture(*args, **kwargs)

    paypal.authorize_order = tracked_authorize
    paypal.get_authorization = tracked_get_auth
    paypal.capture_authorization = tracked_capture

    outcome = client.settle_approved_order("ORDER-FLAGGED-FLOW", now=NOW)
    assert outcome.final_status == "CAPTURED"
    assert trace.index("p1_evaluated") < trace.index("authorize")
    assert trace.index("authorize") < trace.index("capture")
    assert trace.index("p2_completed") < trace.index("capture")
    assert trace.index("get_authorization") < trace.index("capture")


def test_flagged_order_with_p2_rejection_remains_authorized_and_is_not_captured(engines):
    state_engine, deadlock = engines
    seed_prior_order(state_engine, deadlock)
    order = make_approved_order("ORDER-P2-REJECT")
    paypal = FakePayPalClient(order)

    def rejecting_llm(_context):
        return {
            "classification": "AGENT_RETRY_LOOP",
            "confidence": 0.99,
            "recommended_action": "HOLD_AUTHORIZE",
            "estimated_fee_saved_usd": 0,
            "merchant_summary": "Retry loop detected.",
        }

    client, _, _, _ = make_settlement(
        order, state_engine=state_engine, deadlock=deadlock, paypal=paypal, llm=rejecting_llm
    )
    outcome = client.settle_approved_order("ORDER-P2-REJECT", now=NOW)
    assert outcome.final_status == "AUTHORIZED_HOLD"
    assert not any(call[0] == "capture_authorization" for call in paypal.calls)


def test_hard_hold_is_not_routed_through_the_clean_no_llm_capture_path(engines):
    state_engine, deadlock = engines
    state_engine.register_sku_category("SKU-SUB-001", "subscription")
    order = make_approved_order("ORDER-HARD-HOLD", sku="SKU-SUB-001")
    paypal = FakePayPalClient(order)
    client, _, _, _ = make_settlement(order, state_engine=state_engine, deadlock=deadlock, paypal=paypal)

    outcome = client.settle_approved_order("ORDER-HARD-HOLD", now=NOW)
    assert outcome.capture_allowed is False
    assert outcome.decision_mode == "EXPLANATION_ONLY"
    # A hard-hold SKU cannot be routed through the clean-order path, even when the
    # velocity result itself is not flagged.
    assert not any(call[0] == "capture_authorization" for call in paypal.calls)


# ---------------------------------------------------------------------------
# Authorization/capture reconciliation and ambiguity
# ---------------------------------------------------------------------------

def test_authorization_response_with_multiple_authorizations_is_rejected():
    response = {
        "purchase_units": [
            {"payments": {"authorizations": [
                {"id": "AUTH-1", "status": "CREATED"},
                {"id": "AUTH-2", "status": "CREATED"},
            ]}}
        ]
    }
    with pytest.raises(ValueError, match="multiple|exactly one|one authorization"):
        SettlementClient._extract_authorization_from_order_response(response)


def test_cached_succeeded_authorization_is_not_assumed_live_created(engines):
    """A persisted AUTHORIZE success is not proof the auth is still capturable."""
    state_engine, deadlock = engines
    order = make_approved_order("ORDER-AUTH-CACHED")
    paypal = FakePayPalClient(order)
    client, _, _, _ = make_settlement(order, state_engine=state_engine, deadlock=deadlock, paypal=paypal)
    client._operations["authorize:ORDER-AUTH-CACHED"] = PaymentOperationRecord(
        operation_id="authorize:ORDER-AUTH-CACHED",
        operation_type="AUTHORIZE",
        order_id="ORDER-AUTH-CACHED",
        authorization_id="AUTH-CACHED",
        paypal_request_id="auth-ORDER-AUTH-CACHED",
        payload_json="{}",
        status="SUCCEEDED",
        updated_at=NOW - 100,
    )
    paypal.authorization_status = "VOIDED"

    auth_id, auth_status, _, reconcile, _ = client._authorize_with_reconciliation(
        "ORDER-AUTH-CACHED", now=NOW
    )

    assert auth_id == "AUTH-CACHED"
    assert auth_status != "CREATED"
    assert not reconcile
    assert any(call[0] == "get_authorization" for call in paypal.calls)


def test_authorization_response_without_status_is_not_assumed_created(engines):
    state_engine, deadlock = engines
    order = make_approved_order("ORDER-AUTH-NO-STATUS")
    paypal = FakePayPalClient(order)
    paypal.authorize_result = {
        "purchase_units": [
            {"payments": {"authorizations": [{"id": "AUTH-NO-STATUS"}]}}
        ]
    }
    client, _, _, _ = make_settlement(order, state_engine=state_engine, deadlock=deadlock, paypal=paypal)
    auth_id, auth_status, _, reconcile, _ = client._authorize_with_reconciliation(
        "ORDER-AUTH-NO-STATUS", now=NOW
    )
    assert auth_id == "AUTH-NO-STATUS"
    assert auth_status != "CREATED"
    assert reconcile is True or auth_status is None


def test_authorize_response_missing_authorization_id_enters_reconciliation_not_failed(engines):
    state_engine, deadlock = engines
    order = make_approved_order("ORDER-AUTH-MISSING-ID")
    paypal = FakePayPalClient(order)
    paypal.authorize_result = {"purchase_units": [{"payments": {"authorizations": []}}]}
    client, _, _, _ = make_settlement(order, state_engine=state_engine, deadlock=deadlock, paypal=paypal)
    client._authorize_with_reconciliation("ORDER-AUTH-MISSING-ID", now=NOW)
    op = client.get_operation_record("authorize:ORDER-AUTH-MISSING-ID")
    assert op is not None
    assert op.status == "RECONCILIATION_REQUIRED"


def test_capture_response_missing_capture_id_enters_reconciliation_not_failed(engines, monkeypatch):
    state_engine, deadlock = engines
    state_engine.check_and_record_order(
        order_id="ORDER-CAP-MISSING-ID", amount=AMOUNT, currency=CURRENCY,
        payer_id=PAYER, intent="AUTHORIZE", now=NOW,
    )
    state_engine.mark_order_authorized("ORDER-CAP-MISSING-ID", "AUTH-CAP-MISSING-ID", now=NOW + 1)
    paypal = FakePayPalClient(make_approved_order("ORDER-CAP-MISSING-ID"))
    paypal.capture_result = {"status": "COMPLETED"}
    client = SettlementClient(paypal, state_engine, deadlock)
    real_validator = settlement_module.validate_order_ready_for_capture

    def verified_validator(*args, **kwargs):
        kwargs["paypal_auth_status_verified"] = True
        return real_validator(*args, **kwargs)

    monkeypatch.setattr(settlement_module, "validate_order_ready_for_capture", verified_validator)
    client._execute_capture_with_reconciliation(
        order_id="ORDER-CAP-MISSING-ID",
        authorization_id="AUTH-CAP-MISSING-ID",
        paypal_auth_status="CREATED",
        capture_mode="AUTO",
        decision_allows_capture=True,
        operation_key="full",
        now=NOW + 2,
    )
    op = client.get_operation_record("capture:AUTH-CAP-MISSING-ID:full")
    assert op is not None
    assert op.status == "RECONCILIATION_REQUIRED"


def test_capture_cannot_be_sent_under_an_authorization_different_from_local_order(engines, monkeypatch):
    state_engine, deadlock = engines
    state_engine.check_and_record_order(
        order_id="ORDER-AUTH-MISMATCH", amount=AMOUNT, currency=CURRENCY,
        payer_id=PAYER, intent="AUTHORIZE", now=NOW,
    )
    state_engine.mark_order_authorized("ORDER-AUTH-MISMATCH", "AUTH-LOCAL", now=NOW + 1)
    paypal = FakePayPalClient(make_approved_order("ORDER-AUTH-MISMATCH"))
    client = SettlementClient(paypal, state_engine, deadlock)
    real_validator = settlement_module.validate_order_ready_for_capture

    def verified_validator(*args, **kwargs):
        kwargs["paypal_auth_status_verified"] = True
        return real_validator(*args, **kwargs)

    monkeypatch.setattr(settlement_module, "validate_order_ready_for_capture", verified_validator)
    with pytest.raises((ValueError, PermissionError)):
        client._execute_capture_with_reconciliation(
            order_id="ORDER-AUTH-MISMATCH",
            authorization_id="AUTH-OTHER",
            paypal_auth_status="CREATED",
            capture_mode="AUTO",
            decision_allows_capture=True,
            operation_key="full",
            now=NOW + 2,
        )
    assert not any(call[0] == "capture_authorization" for call in paypal.calls)


def test_capture_reconciliation_rejects_a_candidate_missing_amount_and_currency(engines):
    state_engine, deadlock = engines
    state_engine.check_and_record_order(
        order_id="ORDER-MISSING-CAP-EVIDENCE", amount=AMOUNT, currency=CURRENCY,
        payer_id=PAYER, intent="AUTHORIZE", now=NOW,
    )
    state_engine.mark_order_authorized("ORDER-MISSING-CAP-EVIDENCE", "AUTH-MISSING-CAP-EVIDENCE", now=NOW + 1)
    paypal = FakePayPalClient(make_approved_order("ORDER-MISSING-CAP-EVIDENCE"))
    client = SettlementClient(paypal, state_engine, deadlock)
    remote = make_approved_order("ORDER-MISSING-CAP-EVIDENCE")
    remote["purchase_units"][0]["payments"] = {
        "captures": [{"id": "CAP-NO-AMOUNT", "status": "COMPLETED"}]
    }
    match = client._find_matching_unclaimed_capture(
        order_id="ORDER-MISSING-CAP-EVIDENCE",
        authorization_id="AUTH-MISSING-CAP-EVIDENCE",
        remote_order=remote,
        expected_amount=AMOUNT,
        expected_currency=CURRENCY,
        expected_invoice_id="INV-MVP-001",
    )
    assert match is None


def test_authoritative_order_404_does_not_fall_back_to_caller_snapshot(engines):
    state_engine, deadlock = engines
    order = make_approved_order("ORDER-404")
    paypal = FakePayPalClient(order)
    paypal.order_error = PayPalAPIError("not found", status_code=404, error_name="RESOURCE_NOT_FOUND")
    client, _, _, _ = make_settlement(order, state_engine=state_engine, deadlock=deadlock, paypal=paypal)
    with pytest.raises(PayPalAPIError):
        client.settle_approved_order("ORDER-404", paypal_order=order, now=NOW)
    assert not any(call[0] == "authorize_order" for call in paypal.calls)


def test_completed_order_is_not_rewritten_to_approved_for_new_settlement(engines):
    state_engine, deadlock = engines
    order = make_approved_order("ORDER-ALREADY-COMPLETED")
    order["status"] = "COMPLETED"
    order["purchase_units"][0]["payments"] = {
        "authorizations": [{"id": "AUTH-OLD", "status": "CAPTURED"}],
        "captures": [{"id": "CAP-OLD", "status": "COMPLETED", "amount": {"currency_code": "USD", "value": AMOUNT}}],
    }
    paypal = FakePayPalClient(order)
    client, _, _, _ = make_settlement(order, state_engine=state_engine, deadlock=deadlock, paypal=paypal)
    with pytest.raises(ValueError, match="status='COMPLETED'"):
        client.settle_approved_order("ORDER-ALREADY-COMPLETED", now=NOW)
    assert not any(call[0] in {"authorize_order", "capture_authorization"} for call in paypal.calls)


def test_reconciliation_quarantines_multiple_remote_captures_instead_of_picking_last(engines):
    state_engine, deadlock = engines
    order = make_approved_order("ORDER-REMOTE-MULTICAP")
    order["purchase_units"][0]["payments"] = {
        "authorizations": [{"id": "AUTH-REMOTE-MULTICAP", "status": "CREATED"}],
        "captures": [
            {"id": "CAP-A", "status": "COMPLETED", "amount": {"currency_code": "USD", "value": AMOUNT}},
            {"id": "CAP-B", "status": "COMPLETED", "amount": {"currency_code": "USD", "value": AMOUNT}},
        ],
    }
    state_engine.check_and_record_order(
        order_id="ORDER-REMOTE-MULTICAP", amount=AMOUNT, currency=CURRENCY,
        payer_id=PAYER, intent="AUTHORIZE", now=NOW - 100,
    )
    state_engine.mark_order_authorized(
        "ORDER-REMOTE-MULTICAP", "AUTH-REMOTE-MULTICAP", status="NEEDS_ATTENTION", now=NOW - 90
    )
    paypal = FakePayPalClient(order)
    client = SettlementClient(paypal, state_engine, deadlock)
    client._operations["capture:AUTH-REMOTE-MULTICAP:full"] = PaymentOperationRecord(
        operation_id="capture:AUTH-REMOTE-MULTICAP:full",
        operation_type="CAPTURE",
        order_id="ORDER-REMOTE-MULTICAP",
        authorization_id="AUTH-REMOTE-MULTICAP",
        paypal_request_id="capture-AUTH-REMOTE-MULTICAP",
        payload_json="{}",
        status="RECONCILIATION_REQUIRED",
        updated_at=NOW - 100,
    )

    report = client.reconcile_stuck_holds(older_than_seconds=0, now=NOW)
    refreshed = state_engine.get_order("ORDER-REMOTE-MULTICAP")
    assert refreshed.capture_id is None
    assert "ORDER-REMOTE-MULTICAP" not in report.resolved_captured_order_ids
    assert (
        "ORDER-REMOTE-MULTICAP" in report.escalated_needs_attention_order_ids
        or "ORDER-REMOTE-MULTICAP" in report.errors_by_order_id
    )


def test_repeated_pending_capture_is_not_reported_as_completed(engines, monkeypatch):
    state_engine, deadlock = engines
    state_engine.check_and_record_order(
        order_id="ORDER-PENDING-REPEAT", amount=AMOUNT, currency=CURRENCY,
        payer_id=PAYER, intent="AUTHORIZE", now=NOW,
    )
    state_engine.mark_order_authorized("ORDER-PENDING-REPEAT", "AUTH-PENDING-REPEAT", now=NOW + 1)
    paypal = FakePayPalClient(make_approved_order("ORDER-PENDING-REPEAT"))
    paypal.capture_result = {"id": "CAP-PENDING-REPEAT", "status": "PENDING"}
    client = SettlementClient(paypal, state_engine, deadlock)

    # Isolate provider-status persistence from the separate missing-verification integration
    # defect: simulate a caller that has actually performed the required live auth lookup.
    real_validator = settlement_module.validate_order_ready_for_capture

    def verified_validator(*args, **kwargs):
        kwargs["paypal_auth_status_verified"] = True
        return real_validator(*args, **kwargs)

    monkeypatch.setattr(settlement_module, "validate_order_ready_for_capture", verified_validator)
    first = client._execute_capture_with_reconciliation(
        order_id="ORDER-PENDING-REPEAT",
        authorization_id="AUTH-PENDING-REPEAT",
        paypal_auth_status="CREATED",
        capture_mode="AUTO",
        decision_allows_capture=True,
        operation_key="full",
        now=NOW + 2,
    )
    assert first[-1] == "PENDING"
    second = client._execute_capture_with_reconciliation(
        order_id="ORDER-PENDING-REPEAT",
        authorization_id="AUTH-PENDING-REPEAT",
        paypal_auth_status="CREATED",
        capture_mode="AUTO",
        decision_allows_capture=True,
        operation_key="full",
        now=NOW + 3,
    )
    assert second[-1] == "PENDING"


# ---------------------------------------------------------------------------
# Refund scope and provider reconciliation
# ---------------------------------------------------------------------------

def prepared_refund_client(status: str = "COMPLETED", refund_id: Optional[str] = "REFUND-1"):
    state_engine = VelocityStateEngine()
    deadlock = BuyRefundDeadlockDetector()
    state_engine.check_and_record_order(
        order_id="ORDER-REFUND-1", amount="100.00", currency="USD",
        payer_id=PAYER, intent="AUTHORIZE", now=NOW,
    )
    state_engine.mark_order_authorized("ORDER-REFUND-1", "AUTH-REFUND-1", status="AUTHORIZED_HOLD", now=NOW + 1)
    state_engine.register_capture(
        "ORDER-REFUND-1", "CAPTURE-REFUND-1", authorization_id="AUTH-REFUND-1", now=NOW + 2
    )
    mutex = WebhookRefundMutex()
    mutex.register_order_capture_link(
        "ORDER-REFUND-1", "CAPTURE-REFUND-1", state_engine=state_engine, now=NOW + 3
    )
    paypal = FakePayPalClient()
    paypal.refund_result = {"id": refund_id, "status": status} if refund_id else {"status": status}
    client = SettlementClient(paypal, state_engine, deadlock, webhook_mutex=mutex)
    return client, mutex, paypal


def test_one_logical_refund_operation_per_capture_is_enforced_by_p1():
    client, mutex, _ = prepared_refund_client()
    allowed, _, op = mutex.reserve_outbound_refund(
        capture_id="CAPTURE-REFUND-1", order_id="ORDER-REFUND-1", operation_id="REFUND-OP-1",
        amount="10.00", currency="USD", state_engine=client.state_engine, now=NOW + 4,
    )
    assert allowed and op is not None
    mutex.complete_outbound_refund(
        operation_id=op.operation_id,
        outcome="SUCCEEDED",
        claim_token=op.claim_token,
        paypal_refund_id="REFUND-1",
        provider_status="COMPLETED",
        now=NOW + 5,
    )
    with pytest.raises(ValueError, match="CONFLICTING_REFUND_ON_SAME_CAPTURE"):
        mutex.reserve_outbound_refund(
            capture_id="CAPTURE-REFUND-1", order_id="ORDER-REFUND-1", operation_id="REFUND-OP-2",
            amount="5.00", currency="USD", state_engine=client.state_engine, now=NOW + 6,
        )


@pytest.mark.parametrize(
    ("provider_status", "expected_internal"),
    [
        ("COMPLETED", "SUCCEEDED"),
        ("PENDING", "PENDING"),
        ("FAILED", "FAILED"),
        ("CANCELLED", "FAILED"),
    ],
)
def test_refund_provider_status_maps_exactly_to_p1(provider_status, expected_internal):
    client, _, _ = prepared_refund_client(status=provider_status)
    outcome = client.execute_guarded_refund(
        capture_id="CAPTURE-REFUND-1", order_id="ORDER-REFUND-1", operation_id="REFUND-OP-1",
        amount="10.00", currency="USD", now=NOW + 4,
    )
    assert outcome.operation is not None
    assert outcome.operation.status == expected_internal


@pytest.mark.parametrize(
    "provider_response",
    [
        {"status": "COMPLETED"},                  # missing refund ID
        {"id": "REFUND-NO-STATUS"},                # missing provider status
        {"id": "REFUND-UNKNOWN", "status": "UNKNOWN_STATUS"},
    ],
)
def test_refund_missing_or_unknown_provider_evidence_goes_to_reconciliation(provider_response):
    client, _, paypal = prepared_refund_client()
    paypal.refund_result = provider_response
    outcome = client.execute_guarded_refund(
        capture_id="CAPTURE-REFUND-1", order_id="ORDER-REFUND-1", operation_id="REFUND-OP-1",
        amount="10.00", currency="USD", now=NOW + 4,
    )
    assert outcome.status == "RECONCILIATION_REQUIRED"
    assert outcome.operation is not None
    assert outcome.operation.status == "RECONCILIATION_REQUIRED"


def test_paypal_client_exposes_authoritative_refund_lookup_for_reconciliation():
    assert callable(getattr(PayPalSandboxClient, "get_refund", None))


def test_ambiguous_operation_reuses_the_same_paypal_request_id():
    order = make_approved_order("ORDER-IDEMPOTENCY-AMBIGUOUS")
    client, _, _, _ = make_settlement(order)
    client._operations["capture:AUTH-IDEMPOTENCY:full"] = PaymentOperationRecord(
        operation_id="capture:AUTH-IDEMPOTENCY:full",
        operation_type="CAPTURE",
        order_id="ORDER-IDEMPOTENCY-AMBIGUOUS",
        authorization_id="AUTH-IDEMPOTENCY",
        paypal_request_id="capture-stable-key",
        payload_json="{}",
        status="RECONCILIATION_REQUIRED",
        updated_at=NOW,
    )
    op = client._get_or_create_operation(
        operation_id="capture:AUTH-IDEMPOTENCY:full",
        operation_type="CAPTURE",
        order_id="ORDER-IDEMPOTENCY-AMBIGUOUS",
        authorization_id="AUTH-IDEMPOTENCY",
        default_paypal_request_id="capture-new-key",
        payload={},
        now=NOW + 1,
    )
    assert op.paypal_request_id == "capture-stable-key"
    assert op.status == "RECONCILIATION_REQUIRED"


def test_definite_failed_operation_rotates_request_id_only_on_retry():
    order = make_approved_order("ORDER-IDEMPOTENCY-FAILED")
    client, _, _, _ = make_settlement(order)
    client._operations["capture:AUTH-IDEMPOTENCY-FAILED:full"] = PaymentOperationRecord(
        operation_id="capture:AUTH-IDEMPOTENCY-FAILED:full",
        operation_type="CAPTURE",
        order_id="ORDER-IDEMPOTENCY-FAILED",
        authorization_id="AUTH-IDEMPOTENCY-FAILED",
        paypal_request_id="old-key",
        payload_json="{}",
        status="FAILED",
        updated_at=NOW,
    )
    op = client._get_or_create_operation(
        operation_id="capture:AUTH-IDEMPOTENCY-FAILED:full",
        operation_type="CAPTURE",
        order_id="ORDER-IDEMPOTENCY-FAILED",
        authorization_id="AUTH-IDEMPOTENCY-FAILED",
        default_paypal_request_id="base-key",
        payload={},
        now=NOW + 1,
    )
    assert op.paypal_request_id == "base-key-r1"
    assert op.status == "IN_FLIGHT"


# ---------------------------------------------------------------------------
# Deployment boundary: single instance / one active worker is operationally required.
# No test here pretends an in-process RLock is a distributed lock.
# ---------------------------------------------------------------------------


def prepared_full_capture_client(order_id="ORDER-FULL-CAPTURE-ONLY"):
    state_engine = VelocityStateEngine()
    deadlock = BuyRefundDeadlockDetector()
    state_engine.check_and_record_order(
        order_id=order_id, amount=AMOUNT, currency=CURRENCY, payer_id=PAYER, intent="AUTHORIZE", now=NOW,
    )
    state_engine.mark_order_authorized(order_id, "AUTH-FULL-CAPTURE-ONLY", now=NOW + 1)
    paypal = FakePayPalClient(make_approved_order(order_id))
    client = SettlementClient(paypal, state_engine, deadlock)
    return client, paypal


def test_p3_internal_capture_helper_rejects_final_capture_false_before_provider_call():
    client, paypal = prepared_full_capture_client("ORDER-PARTIAL-FINAL-FALSE")
    with pytest.raises(ValueError, match="PARTIAL_CAPTURES_DISABLED_IN_MVP"):
        client._execute_capture_with_reconciliation(
            order_id="ORDER-PARTIAL-FINAL-FALSE", authorization_id="AUTH-FULL-CAPTURE-ONLY",
            paypal_auth_status="CREATED", capture_mode="AUTO", decision_allows_capture=True,
            operation_key="full", final_capture=False, now=NOW + 2,
        )
    assert not any(call[0] == "capture_authorization" for call in paypal.calls)


def test_p3_internal_capture_helper_rejects_amount_below_order_total():
    client, paypal = prepared_full_capture_client("ORDER-PARTIAL-AMOUNT")
    with pytest.raises(ValueError, match="capture amount must equal the full order amount"):
        client._execute_capture_with_reconciliation(
            order_id="ORDER-PARTIAL-AMOUNT", authorization_id="AUTH-FULL-CAPTURE-ONLY",
            paypal_auth_status="CREATED", capture_mode="AUTO", decision_allows_capture=True,
            operation_key="full", final_capture=True,
            capture_payload={"amount": {"currency_code": "USD", "value": "10.00"}}, now=NOW + 2,
        )
    assert not any(call[0] == "capture_authorization" for call in paypal.calls)


def test_p3_live_authorization_lookup_blocks_voided_authorization():
    client, paypal = prepared_full_capture_client("ORDER-AUTH-VOIDED")
    paypal.authorization_status = "VOIDED"
    result = client._execute_capture_with_reconciliation(
        order_id="ORDER-AUTH-VOIDED", authorization_id="AUTH-FULL-CAPTURE-ONLY",
        paypal_auth_status="CREATED", capture_mode="AUTO", decision_allows_capture=True,
        operation_key="full", now=NOW + 2,
    )
    assert result[-1] == "VOIDED"
    assert any(call[0] == "get_authorization" for call in paypal.calls)
    assert not any(call[0] == "capture_authorization" for call in paypal.calls)


def test_unknown_refund_status_can_be_resolved_by_authoritative_refund_get():
    client, mutex, paypal = prepared_refund_client()
    paypal.refund_result = {"id": "REFUND-RECON-1", "status": "UNKNOWN_STATUS"}
    first = client.execute_guarded_refund(
        capture_id="CAPTURE-REFUND-1", order_id="ORDER-REFUND-1", operation_id="REFUND-OP-RECON-1",
        amount="10.00", currency="USD", now=NOW + 4,
    )
    assert first.status == "RECONCILIATION_REQUIRED"
    paypal.refund_result = {"id": "REFUND-RECON-1", "status": "COMPLETED"}
    reconciled = client.reconcile_guarded_refund("REFUND-OP-RECON-1", now=NOW + 6)
    assert reconciled.status == "SUCCEEDED"
    assert reconciled.operation is not None and reconciled.operation.provider_status == "COMPLETED"
    assert any(call[0] == "get_refund" for call in paypal.calls)


def test_refund_completion_uses_elapsed_time_and_expires_stale_claim(monkeypatch):
    client, mutex, paypal = prepared_refund_client()
    lease = mutex.outbound_op_lease_seconds
    monotonic_values = iter([100.0, 100.0 + lease + 1.0])
    monkeypatch.setattr(settlement_module.time, "monotonic", lambda: next(monotonic_values))
    outcome = client.execute_guarded_refund(
        capture_id="CAPTURE-REFUND-1", order_id="ORDER-REFUND-1", operation_id="REFUND-OP-LEASE",
        amount="10.00", currency="USD", now=NOW + 4,
    )
    assert outcome.status == "RECONCILIATION_REQUIRED"
    assert outcome.operation is not None and outcome.operation.status == "RECONCILIATION_REQUIRED"
    assert any(call[0] == "refund_capture" for call in paypal.calls)


def test_checkout_rewriter_rejects_customer_selected_payee():
    pu = make_purchase_unit()
    pu["payee"] = {"email_address": "attacker-controlled@example.test"}
    with pytest.raises(ValueError, match="CALLER_SELECTED_PAYEE_DISABLED_IN_MVP"):
        rewrite_order_payload({"intent": "AUTHORIZE", "purchase_units": [pu]})


# ---------------------------------------------------------------------------
# Crash recovery and retry fencing (P3 integration; P1 logic remains frozen)
# ---------------------------------------------------------------------------

def test_existing_remote_authorization_is_recovered_without_duplicate_authorize():
    order = make_approved_order("ORDER-REMOTE-AUTH-RECOVERY")
    order["purchase_units"][0]["payments"] = {
        "authorizations": [{"id": "AUTH-MVP-1", "status": "CREATED"}]
    }
    client, _, _, paypal = make_settlement(order)

    outcome = client.settle_approved_order("ORDER-REMOTE-AUTH-RECOVERY", now=NOW)

    assert outcome.final_status == "CAPTURED"
    assert outcome.authorization_id == "AUTH-MVP-1"
    assert any(call[0] == "get_authorization" and call[1] == "AUTH-MVP-1" for call in paypal.calls)
    assert not any(call[0] == "authorize_order" for call in paypal.calls)
    assert len([call for call in paypal.calls if call[0] == "capture_authorization"]) == 1


def test_multiple_remote_authorizations_are_quarantined_without_new_authorize():
    order = make_approved_order("ORDER-MULTI-REMOTE-AUTH")
    order["purchase_units"][0]["payments"] = {
        "authorizations": [
            {"id": "AUTH-REMOTE-1", "status": "CREATED"},
            {"id": "AUTH-REMOTE-2", "status": "CREATED"},
        ]
    }
    client, _, _, paypal = make_settlement(order)

    auth_id, auth_status, _, reconcile, error = client._authorize_with_reconciliation(
        "ORDER-MULTI-REMOTE-AUTH", now=NOW, paypal_order=order
    )

    assert auth_id is None and auth_status is None
    assert reconcile is True and error
    assert not any(call[0] == "authorize_order" for call in paypal.calls)


def test_capture_definite_failure_can_retry_with_rotated_request_id():
    client, paypal = prepared_full_capture_client("ORDER-CAPTURE-DEFINITE-RETRY")
    request_ids = []
    responses = [
        PayPalAPIError("definite rejection", status_code=422, issue="DECLINED"),
        {"id": "CAPTURE-RETRY-1", "status": "COMPLETED"},
    ]

    def capture_authorization(*, authorization_id, paypal_request_id, payload=None):
        request_ids.append(paypal_request_id)
        result = responses.pop(0)
        if isinstance(result, Exception):
            raise result
        return copy.deepcopy(result)

    paypal.capture_authorization = capture_authorization
    first = client._execute_capture_with_reconciliation(
        order_id="ORDER-CAPTURE-DEFINITE-RETRY", authorization_id="AUTH-FULL-CAPTURE-ONLY",
        paypal_auth_status="CREATED", capture_mode="AUTO", decision_allows_capture=True,
        operation_key="full", now=NOW + 2,
    )
    assert first[0] is None and first[1] == "capture:AUTH-FULL-CAPTURE-ONLY:full"
    assert first[3] is False and first[5] == "FAILED"

    second = client._execute_capture_with_reconciliation(
        order_id="ORDER-CAPTURE-DEFINITE-RETRY", authorization_id="AUTH-FULL-CAPTURE-ONLY",
        paypal_auth_status="CREATED", capture_mode="AUTO", decision_allows_capture=True,
        operation_key="full", now=NOW + 3,
    )
    assert second[0] == "CAPTURE-RETRY-1"
    assert second[5] == "COMPLETED"
    assert len(request_ids) == 2
    assert request_ids[0] != request_ids[1]
    assert request_ids[1].endswith("-r1")
    assert client.state_engine.get_order("ORDER-CAPTURE-DEFINITE-RETRY").resolution_status == "CAPTURED"


def test_ambiguous_capture_is_fenced_and_never_rotates_request_id():
    client, paypal = prepared_full_capture_client("ORDER-CAPTURE-AMBIGUOUS-FENCE")
    request_ids = []

    def ambiguous_capture(*, authorization_id, paypal_request_id, payload=None):
        request_ids.append(paypal_request_id)
        raise PayPalAmbiguousNetworkError("connection dropped after request transmission")

    paypal.capture_authorization = ambiguous_capture
    first = client._execute_capture_with_reconciliation(
        order_id="ORDER-CAPTURE-AMBIGUOUS-FENCE", authorization_id="AUTH-FULL-CAPTURE-ONLY",
        paypal_auth_status="CREATED", capture_mode="AUTO", decision_allows_capture=True,
        operation_key="full", now=NOW + 2,
    )
    assert first[3] is True
    assert first[1] == "capture:AUTH-FULL-CAPTURE-ONLY:full"

    second = client._execute_capture_with_reconciliation(
        order_id="ORDER-CAPTURE-AMBIGUOUS-FENCE", authorization_id="AUTH-FULL-CAPTURE-ONLY",
        paypal_auth_status="CREATED", capture_mode="AUTO", decision_allows_capture=True,
        operation_key="full", now=NOW + 3,
    )
    assert second[3] is True
    assert len(request_ids) == 1  # ambiguity is fenced immediately; no second provider mutation

def test_paypal_get_refund_uses_authoritative_refund_resource_endpoint(monkeypatch):
    paypal = PayPalSandboxClient(client_id="test", client_secret="test")
    captured = {}

    def fake_request(method, path, **kwargs):
        captured["method"] = method
        captured["path"] = path
        return {"id": "REFUND-ENDPOINT-1", "status": "COMPLETED"}

    monkeypatch.setattr(paypal, "_request", fake_request)
    result = paypal.get_refund("REFUND-ENDPOINT-1")
    assert result["id"] == "REFUND-ENDPOINT-1"
    assert captured == {"method": "GET", "path": "/v2/payments/refunds/REFUND-ENDPOINT-1"}


def test_legacy_definite_failed_capture_migrates_payload_before_safe_retry():
    client, paypal = prepared_full_capture_client("ORDER-LEGACY-FAILED-CAPTURE")
    operation_id = "capture:AUTH-FULL-CAPTURE-ONLY:full"
    client._operations[operation_id] = PaymentOperationRecord(
        operation_id=operation_id, operation_type="CAPTURE",
        order_id="ORDER-LEGACY-FAILED-CAPTURE", authorization_id="AUTH-FULL-CAPTURE-ONLY",
        paypal_request_id="legacy-capture-key", payload_json="{}", status="FAILED", updated_at=NOW,
    )
    request_ids = []

    def capture_authorization(*, authorization_id, paypal_request_id, payload=None):
        request_ids.append(paypal_request_id)
        return {"id": "CAPTURE-LEGACY-RETRY", "status": "COMPLETED"}

    paypal.capture_authorization = capture_authorization
    result = client._execute_capture_with_reconciliation(
        order_id="ORDER-LEGACY-FAILED-CAPTURE", authorization_id="AUTH-FULL-CAPTURE-ONLY",
        paypal_auth_status="CREATED", capture_mode="AUTO", decision_allows_capture=True,
        operation_key="full", now=NOW + 1,
    )
    assert result[0] == "CAPTURE-LEGACY-RETRY"
    assert len(request_ids) == 1 and request_ids[0].endswith("-r1")

def test_legacy_ambiguous_capture_payload_is_quarantined_not_replayed():
    client, paypal = prepared_full_capture_client("ORDER-LEGACY-AMBIG-CAPTURE")
    operation_id = "capture:AUTH-FULL-CAPTURE-ONLY:full"
    client._operations[operation_id] = PaymentOperationRecord(
        operation_id=operation_id, operation_type="CAPTURE",
        order_id="ORDER-LEGACY-AMBIG-CAPTURE", authorization_id="AUTH-FULL-CAPTURE-ONLY",
        paypal_request_id="legacy-ambiguous-key", payload_json="{}", status="IN_FLIGHT", updated_at=NOW,
    )
    result = client._execute_capture_with_reconciliation(
        order_id="ORDER-LEGACY-AMBIG-CAPTURE", authorization_id="AUTH-FULL-CAPTURE-ONLY",
        paypal_auth_status="CREATED", capture_mode="AUTO", decision_allows_capture=True,
        operation_key="full", now=NOW + 1,
    )
    assert result[3] is True
    assert client.get_operation_record(operation_id).status == "RECONCILIATION_REQUIRED"
    assert not any(call[0] == "capture_authorization" for call in paypal.calls)


def test_authorized_order_completed_status_allows_only_exact_failed_capture_recovery():
    order = make_approved_order("ORDER-COMPLETED-AUTH-RECOVERY")
    client, state_engine, _, paypal = make_settlement(order)
    request_ids = []
    capture_responses = [
        PayPalAPIError("definite capture rejection", status_code=422, issue="DECLINED"),
        {"id": "CAPTURE-RECOVERED-1", "status": "COMPLETED"},
    ]

    def capture_authorization(*, authorization_id, paypal_request_id, payload=None):
        request_ids.append(paypal_request_id)
        response = capture_responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return copy.deepcopy(response)

    paypal.capture_authorization = capture_authorization
    first = client.settle_approved_order("ORDER-COMPLETED-AUTH-RECOVERY", now=NOW)
    assert first.final_status == "NEEDS_ATTENTION"
    assert first.authorization_id == "AUTH-MVP-1"
    assert len(request_ids) == 1

    # Official PayPal Orders API behavior: after /authorize the order resource is
    # COMPLETED while the separate authorization resource remains CREATED.
    recovered_order = make_approved_order("ORDER-COMPLETED-AUTH-RECOVERY")
    recovered_order["status"] = "COMPLETED"
    recovered_order["purchase_units"][0]["payments"] = {
        "authorizations": [{"id": "AUTH-MVP-1", "status": "CREATED"}]
    }
    paypal.order = recovered_order

    second = client.settle_approved_order("ORDER-COMPLETED-AUTH-RECOVERY", now=NOW + 5)
    assert second.final_status == "CAPTURED"
    assert second.capture_id == "CAPTURE-RECOVERED-1"
    assert second.decision_mode == "AUTHORIZED_CAPTURE_RETRY"
    assert len(request_ids) == 2 and request_ids[0] != request_ids[1]
    assert request_ids[1].endswith("-r1")
    assert len([call for call in paypal.calls if call[0] == "authorize_order"]) == 1
    assert state_engine.get_order("ORDER-COMPLETED-AUTH-RECOVERY").resolution_status == "CAPTURED"


def test_clean_pre_capture_crash_recovers_completed_paypal_order_without_reauthorizing():
    order_id = "ORDER-CLEAN-PRECAPTURE-RECOVERY"
    state_engine = VelocityStateEngine()
    deadlock = BuyRefundDeadlockDetector()
    state_engine.check_and_record_order(
        order_id=order_id, amount=AMOUNT, currency=CURRENCY, payer_id=PAYER,
        intent="AUTHORIZE", now=NOW,
    )
    assert state_engine.mark_order_authorized(order_id, "AUTH-PRECAPTURE-1", status="AUTHORIZED_HOLD", now=NOW + 1)
    remote = make_approved_order(order_id)
    remote["status"] = "COMPLETED"
    remote["purchase_units"][0]["payments"] = {
        "authorizations": [{"id": "AUTH-PRECAPTURE-1", "status": "CREATED"}]
    }
    paypal = FakePayPalClient(remote)
    client, _, _, _ = make_settlement(remote, state_engine=state_engine, deadlock=deadlock, paypal=paypal)

    outcome = client.settle_approved_order(order_id, now=NOW + 2)

    assert outcome.final_status == "CAPTURED"
    assert outcome.decision_mode == "NO_LLM_REQUIRED_RECOVERY"
    assert not any(call[0] == "authorize_order" for call in paypal.calls)
    assert len([call for call in paypal.calls if call[0] == "capture_authorization"]) == 1


def test_flagged_pre_capture_crash_recovers_only_after_durable_p2_approval():
    order_id = "ORDER-FLAGGED-PRECAPTURE-RECOVERY"
    state_engine = VelocityStateEngine()
    deadlock = BuyRefundDeadlockDetector()
    state_engine.check_and_record_order(
        order_id=order_id, amount=AMOUNT, currency=CURRENCY, payer_id=PAYER,
        intent="AUTHORIZE", now=NOW,
    )
    assert state_engine.set_order_auto_capture_eligibility(order_id, True, is_flagged=True)
    assert state_engine.mark_order_authorized(order_id, "AUTH-PRECAPTURE-FLAGGED", status="ANALYZING_HOLD", now=NOW + 1)
    assert state_engine.update_order_resolution(
        order_id, "ANALYZING_HOLD", now=NOW + 2, pillar2_classification="LEGITIMATE_REPEAT_BUYER",
    )
    remote = make_approved_order(order_id)
    remote["status"] = "COMPLETED"
    remote["purchase_units"][0]["payments"] = {
        "authorizations": [{"id": "AUTH-PRECAPTURE-FLAGGED", "status": "CREATED"}]
    }
    paypal = FakePayPalClient(remote)
    client, _, _, _ = make_settlement(remote, state_engine=state_engine, deadlock=deadlock, paypal=paypal)

    outcome = client.settle_approved_order(order_id, now=NOW + 3)

    assert outcome.final_status == "CAPTURED"
    assert outcome.decision_mode == "DECISION_ASSISTED_RECOVERY"
    assert not any(call[0] == "authorize_order" for call in paypal.calls)
    assert len([call for call in paypal.calls if call[0] == "capture_authorization"]) == 1


def test_flagged_pre_capture_checkpoint_without_p2_approval_does_not_recover():
    order_id = "ORDER-FLAGGED-NO-P2-RECOVERY"
    state_engine = VelocityStateEngine()
    deadlock = BuyRefundDeadlockDetector()
    state_engine.check_and_record_order(
        order_id=order_id, amount=AMOUNT, currency=CURRENCY, payer_id=PAYER,
        intent="AUTHORIZE", now=NOW,
    )
    assert state_engine.set_order_auto_capture_eligibility(order_id, True, is_flagged=True)
    assert state_engine.mark_order_authorized(order_id, "AUTH-NO-P2-RECOVERY", status="ANALYZING_HOLD", now=NOW + 1)
    remote = make_approved_order(order_id)
    remote["status"] = "COMPLETED"
    remote["purchase_units"][0]["payments"] = {
        "authorizations": [{"id": "AUTH-NO-P2-RECOVERY", "status": "CREATED"}]
    }
    paypal = FakePayPalClient(remote)
    client, _, _, _ = make_settlement(remote, state_engine=state_engine, deadlock=deadlock, paypal=paypal)

    outcome = client.settle_approved_order(order_id, now=NOW + 2)

    assert outcome.final_status == "ANALYZING_HOLD"
    assert not any(call[0] == "capture_authorization" for call in paypal.calls)
    assert not any(call[0] == "authorize_order" for call in paypal.calls)


def seed_successful_orphaned_authorize(client, order_id: str, authorization_id: str):
    client._operations[f"authorize:{order_id}"] = PaymentOperationRecord(
        operation_id=f"authorize:{order_id}",
        operation_type="AUTHORIZE",
        order_id=order_id,
        authorization_id=authorization_id,
        paypal_request_id=f"authorize-{order_id}",
        payload_json="{}",
        status="SUCCEEDED",
        provider_status="CREATED",
        updated_at=NOW,
    )


def test_completed_order_with_orphaned_successful_authorize_recovers_clean_capture():
    order_id = "ORDER-ORPHANED-AUTH-CLEAN"
    authorization_id = "AUTH-ORPHANED-CLEAN"
    state_engine = VelocityStateEngine()
    deadlock = BuyRefundDeadlockDetector()
    state_engine.check_and_record_order(
        order_id=order_id, amount=AMOUNT, currency=CURRENCY, payer_id=PAYER,
        intent="AUTHORIZE", now=NOW,
    )
    remote = make_approved_order(order_id)
    remote["status"] = "COMPLETED"
    remote["purchase_units"][0]["payments"] = {
        "authorizations": [{"id": authorization_id, "status": "CREATED"}]
    }
    paypal = FakePayPalClient(remote)
    client, _, _, _ = make_settlement(remote, state_engine=state_engine, deadlock=deadlock, paypal=paypal)
    seed_successful_orphaned_authorize(client, order_id, authorization_id)

    outcome = client.settle_approved_order(order_id, now=NOW + 2)

    assert outcome.final_status == "CAPTURED"
    assert outcome.authorization_id == authorization_id
    assert not any(call[0] == "authorize_order" for call in paypal.calls)
    assert len([call for call in paypal.calls if call[0] == "capture_authorization"]) == 1


def test_orphaned_authorize_for_flagged_order_recovers_hold_but_never_assumes_p2_approval():
    order_id = "ORDER-ORPHANED-AUTH-FLAGGED"
    authorization_id = "AUTH-ORPHANED-FLAGGED"
    state_engine = VelocityStateEngine()
    deadlock = BuyRefundDeadlockDetector()
    state_engine.check_and_record_order(
        order_id=order_id, amount=AMOUNT, currency=CURRENCY, payer_id=PAYER,
        intent="AUTHORIZE", now=NOW,
    )
    assert state_engine.set_order_auto_capture_eligibility(order_id, True, is_flagged=True)
    remote = make_approved_order(order_id)
    remote["status"] = "COMPLETED"
    remote["purchase_units"][0]["payments"] = {
        "authorizations": [{"id": authorization_id, "status": "CREATED"}]
    }
    paypal = FakePayPalClient(remote)
    client, _, _, _ = make_settlement(remote, state_engine=state_engine, deadlock=deadlock, paypal=paypal)
    seed_successful_orphaned_authorize(client, order_id, authorization_id)

    outcome = client.settle_approved_order(order_id, now=NOW + 2)

    assert outcome.final_status == "ANALYZING_HOLD"
    assert outcome.authorization_id == authorization_id
    assert outcome.capture_allowed is False
    assert not any(call[0] == "authorize_order" for call in paypal.calls)
    assert not any(call[0] == "capture_authorization" for call in paypal.calls)


def test_refund_oauth_failure_is_not_submitted_and_retries_same_request_id():
    client, mutex, paypal = prepared_refund_client()
    request_ids = []
    responses = [
        PayPalAuthError("OAuth token retrieval failed before POST", status_code=401),
        {"id": "REFUND-AFTER-OAUTH-RETRY", "status": "COMPLETED"},
    ]

    def refund_capture(*, capture_id, paypal_request_id, payload=None):
        response = responses.pop(0)
        if isinstance(response, Exception):
            raise response
        request_ids.append(paypal_request_id)
        return copy.deepcopy(response)

    paypal.refund_capture = refund_capture
    first = client.execute_guarded_refund(
        capture_id="CAPTURE-REFUND-1", order_id="ORDER-REFUND-1", operation_id="REFUND-OP-OAUTH-RETRY",
        amount="10.00", currency="USD", now=NOW + 4,
    )
    assert first.status == "NOT_SUBMITTED"
    assert first.operation is not None and first.operation.status == "NOT_SUBMITTED"
    first_request_id = first.operation.paypal_request_id

    second = client.execute_guarded_refund(
        capture_id="CAPTURE-REFUND-1", order_id="ORDER-REFUND-1", operation_id="REFUND-OP-OAUTH-RETRY",
        amount="10.00", currency="USD", now=NOW + 5,
    )
    assert second.status == "SUCCEEDED"
    assert second.operation is not None and second.operation.status == "SUCCEEDED"
    assert request_ids == [first_request_id]
    assert second.operation.paypal_request_id == first_request_id
    assert second.paypal_refund_id == "REFUND-AFTER-OAUTH-RETRY"
    assert any(call[0] == "get_refund" for call in paypal.calls) is False


def test_refund_provider_api_rejection_is_not_mislabeled_not_submitted():
    client, _, paypal = prepared_refund_client()
    calls = []

    def reject_refund(*, capture_id, paypal_request_id, payload=None):
        calls.append(paypal_request_id)
        raise PayPalAPIError("provider returned a deterministic rejection", status_code=422, issue="REFUND_NOT_ALLOWED")

    paypal.refund_capture = reject_refund
    outcome = client.execute_guarded_refund(
        capture_id="CAPTURE-REFUND-1", order_id="ORDER-REFUND-1", operation_id="REFUND-OP-API-REJECT",
        amount="10.00", currency="USD", now=NOW + 4,
    )
    assert outcome.status == "RECONCILIATION_REQUIRED"
    assert outcome.operation is not None and outcome.operation.status == "RECONCILIATION_REQUIRED"
    assert len(calls) == 1
