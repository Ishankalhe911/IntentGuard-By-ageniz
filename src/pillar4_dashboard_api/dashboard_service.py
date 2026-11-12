"""Pillar 4 Glass-Box Control Plane Service (`dashboard_service.py`).

Unifies Pillar 1 (`VelocityStateEngine`, `BuyRefundDeadlockDetector`, `WebhookRefundMutex`),
Pillar 2 (`CheckoutTriageOutput` telemetry), Pillar 3 (`SettlementClient`, `intent_rewriter`),
and Pillar 4 (`ChronicRefundLoopMonitor`, `WebSocketManager`) into an auditable merchant control
plane supporting:
1. Accurate Glass-Box Evidence Badges (resolving the 4-class enum display gap for first-time
   `single_seat_saas` policy holds, `missing_buyer_identity` holds, and distinguishing
   `CONFIRMED_SKU_REFUND_DEADLOCK` vs `SUSPECTED_AMOUNT_ONLY_REFUND_CORRELATION`).
2. Both directions of Held Order Resolution:
   - Direction A (Reject / Release Hold to Buyer): 1-Tap Void (`void_held_order`) and Scoped
     Incident Bulk Void (`bulk_void_incident`, which automatically skips AI-legitimate holds).
   - Direction B (Approve / Release Hold Into Sale): Guarded Merchant Approve & Capture
     (`approve_and_capture_held_order`), verifying live PayPal `GET /v2/payments/authorizations/{id}`
     is `CREATED`, enforcing full-amount capture and `validate_order_ready_for_capture(...,
     capture_mode="MANUAL_MERCHANT_OVERRIDE", allow_manual_override=True)`, and recording
     `manual_override_actor` + `manual_override_reason` in SQLite without weakening automated
     checkout's hard ceiling.
3. 24-Hour Chronic Refund-Loop Watchlist (`3+` buy+refund cycles in `24h`, including `>60m`
   delegated spacing) with 0ms hot-path checkout overhead.
"""
from __future__ import annotations

from dataclasses import asdict
import json
import sqlite3
import time
from typing import Any, Dict, List, Optional

from src.config.paypal_client import PayPalError
from src.pillar1_velocity_engine.deadlock_detector import BuyRefundDeadlockDetector
from src.pillar1_velocity_engine.state_engine import (
    OrderRecord,
    VelocityStateEngine,
    validate_order_ready_for_capture,
)
from src.pillar1_velocity_engine.webhook_mutex import WebhookRefundMutex
from src.pillar3_capture_shield.intent_rewriter import (
    create_shielded_paypal_order,
    rewrite_order_payload,
)
from src.pillar3_capture_shield.settlement_client import (
    SettlementClient,
    estimate_paypal_fee_saved_usd,
    sanitize_dashboard_summary,
)
from src.pillar4_dashboard_api.chronic_refund_monitor import ChronicRefundLoopMonitor
from src.pillar4_dashboard_api.websocket_manager import WebSocketManager


def compute_glassbox_evidence_badge(order: OrderRecord) -> Dict[str, Any]:
    """Produce an accurate, non-misleading Glass-Box classification badge for the Merchant UI.

    Specifically prevents two UI misunderstandings flagged during audit:
    1. First-time `single_seat_saas` or `missing_buyer_identity` orders where P2 returned
       `LEGITIMATE_REPEAT_BUYER` (because the frozen 4-class enum has no first-purchase or
       missing-identity class) are badged by their authoritative `deterministic_hold_reason`.
    2. Post-refund deadlocks distinguish `CONFIRMED_SKU_REFUND_DEADLOCK` (complete cart/SKU)
       from `SUSPECTED_AMOUNT_ONLY_REFUND_CORRELATION` (missing SKU / incomplete cart).
    """
    det_reason = (order.deterministic_hold_reason or "").strip().upper()
    p2_class = (order.pillar2_classification or "").strip().upper()
    res_status = (order.resolution_status or "").strip().upper()

    if res_status == "CAPTURED":
        if order.manual_override_actor:
            return {
                "badge_code": "MERCHANT_APPROVED_CAPTURE",
                "display_title": "Captured via Merchant Manual Approval",
                "evidence_certainty": "MERCHANT_VERIFIED",
                "is_confirmed_fraud_or_deadlock": False,
                "explanation_note": (
                    f"Approved by '{order.manual_override_actor}': "
                    f"{order.manual_override_reason or 'Verified legitimate order'}"
                ),
            }
        if p2_class == "LEGITIMATE_REPEAT_BUYER":
            return {
                "badge_code": "AI_VERIFIED_REPEAT_CAPTURE",
                "display_title": "Legitimate Repeat Buyer (P1 Eligible + P2 Approved)",
                "evidence_certainty": "HIGH_CONFIDENCE",
                "is_confirmed_fraud_or_deadlock": False,
                "explanation_note": "Passed P1 eligibility and P2 confidence >= 0.85 threshold.",
            }
        return {
            "badge_code": "FAST_PATH_CLEAN_CAPTURE",
            "display_title": "Clean Checkout (0ms Fast-Path Capture)",
            "evidence_certainty": "DETERMINISTIC_CLEAN",
            "is_confirmed_fraud_or_deadlock": False,
            "explanation_note": "First purchase or distinct variant exchange; no LLM call needed.",
        }

    if det_reason == "CHRONIC_24H_REFUND_CYCLE_WATCHLIST":
        return {
            "badge_code": "CHRONIC_24H_REFUND_CYCLE_WATCHLIST",
            "display_title": "24h Chronic Refund-Loop Watchlist Hold (3+ Cycles)",
            "evidence_certainty": "DETERMINISTIC_WATCHLIST_POLICY",
            "is_confirmed_fraud_or_deadlock": True,
            "explanation_note": (
                "Held by merchant 24h Chronic Refund-Loop policy after >= 3 completed refunds "
                "across >= 3 orders in 24h. Merchant may 1-Tap Void or Approve & Capture."
            ),
        }

    if det_reason == "NON_STACKABLE_CATALOG_HARD_HOLD" or order.sku_category in (
        "single_seat_saas",
        "non_stackable_entitlement",
    ):
        return {
            "badge_code": "POLICY_HARD_HOLD_NON_STACKABLE",
            "display_title": f"Catalog Policy Hold ({order.sku_category})",
            "evidence_certainty": "DETERMINISTIC_POLICY_HOLD",
            "is_confirmed_fraud_or_deadlock": False,
            "explanation_note": (
                "Held by merchant catalog policy for non-stackable / single-seat entitlement. "
                "P2's 4-class enum lacks a 'FIRST_TIME_PURCHASE' label, so P1's policy hold is authoritative. "
                "Merchant may 1-Tap Approve & Capture or Void."
            ),
        }

    if det_reason == "IDENTITY_NOT_RELIABLE" or not order.has_reliable_identity:
        return {
            "badge_code": "MISSING_BUYER_IDENTITY_HOLD",
            "display_title": "Missing / Unverified Buyer Identity Hold",
            "evidence_certainty": "INCOMPLETE_IDENTITY_EVIDENCE",
            "is_confirmed_fraud_or_deadlock": False,
            "explanation_note": (
                "Held deterministically by Pillar 1 because reliable payer identity is missing. "
                "Do not treat P2's fallback class as proof of repeat-buyer identity."
            ),
        }

    if det_reason == "BUY_REFUND_DEADLOCK" or p2_class == "BUY_REFUND_DEADLOCK":
        if order.cart_fingerprint_complete or (order.sku and order.sku.strip().lower() != "untagged"):
            return {
                "badge_code": "CONFIRMED_SKU_REFUND_DEADLOCK",
                "display_title": "Confirmed Same-SKU Buy-Refund Deadlock (<60m)",
                "evidence_certainty": "CONFIRMED_EXACT_CART_OR_SKU",
                "is_confirmed_fraud_or_deadlock": True,
                "explanation_note": (
                    "Exact SKU/cart match against a verified COMPLETED refund within the 60-minute deadlock window."
                ),
            }
        return {
            "badge_code": "SUSPECTED_AMOUNT_ONLY_REFUND_CORRELATION",
            "display_title": "Suspected Amount-Only Refund Correlation (Conservative Hold)",
            "evidence_certainty": "SUSPECTED_CANDIDATE_NO_SKU",
            "is_confirmed_fraud_or_deadlock": False,
            "explanation_note": (
                "Same buyer and amount within the refund window, but SKU/cart fingerprint is incomplete. "
                "Held conservatively as a suspected correlation candidate, not a confirmed exact-item match."
            ),
        }

    if p2_class == "PROMPT_INJECTION":
        return {
            "badge_code": "ADVERSARIAL_PROMPT_INJECTION_HOLD",
            "display_title": "Adversarial Prompt Injection Intercepted",
            "evidence_certainty": "HIGH_RISK_ADVERSARIAL",
            "is_confirmed_fraud_or_deadlock": True,
            "explanation_note": "Untrusted checkout text attempted to manipulate system or classification rules.",
        }

    if p2_class == "AGENT_RETRY_LOOP":
        return {
            "badge_code": "AGENT_RETRY_VELOCITY_HOLD",
            "display_title": "Autonomous Agent Retry / Velocity Loop Hold",
            "evidence_certainty": "HIGH_CONFIDENCE_VELOCITY",
            "is_confirmed_fraud_or_deadlock": True,
            "explanation_note": "Repeated checkout within 15-minute velocity window consistent with an automated retry loop.",
        }

    return {
        "badge_code": det_reason or res_status or "HELD_FOR_MERCHANT_REVIEW",
        "display_title": f"Held for Merchant Review ({res_status})",
        "evidence_certainty": "DETERMINISTIC_FAIL_CLOSED",
        "is_confirmed_fraud_or_deadlock": False,
        "explanation_note": "Held safely in zero-fee AUTHORIZE pending merchant review.",
    }


class GlassBoxDashboardService:
    """High-level Pillar 4 orchestrator for the Merchant Glass-Box Dashboard & API."""

    def __init__(
        self,
        *,
        state_engine: VelocityStateEngine,
        deadlock_detector: BuyRefundDeadlockDetector,
        webhook_mutex: WebhookRefundMutex,
        settlement_client: SettlementClient,
        chronic_monitor: Optional[ChronicRefundLoopMonitor] = None,
        ws_manager: Optional[WebSocketManager] = None,
    ) -> None:
        self.state_engine = state_engine
        self.deadlock_detector = deadlock_detector
        self.webhook_mutex = webhook_mutex
        self.settlement_client = settlement_client
        self.chronic_monitor = chronic_monitor or ChronicRefundLoopMonitor(
            state_engine=state_engine,
            deadlock_detector=deadlock_detector,
        )
        self.ws_manager = ws_manager or WebSocketManager()
        self._dashboard_order_ledger: Dict[str, OrderRecord] = {}
        self._sync_order_ledger()

    def _sync_order_ledger(self) -> Dict[str, OrderRecord]:
        """Preserve terminal orders (including VOIDED holds) in SQLite so Chrome sees the full ledger across processes."""
        db_path = getattr(self.state_engine, "db_path", None)
        with self.state_engine._lock:
            if db_path:
                try:
                    self.state_engine._load_persisted_orders()
                except Exception:
                    pass
                try:
                    self.deadlock_detector._load_persisted_refunds()
                except Exception:
                    pass
                try:
                    self.webhook_mutex._load_persisted_state()
                except Exception:
                    pass
                try:
                    with sqlite3.connect(db_path, timeout=10.0) as conn:
                        conn.execute(
                            """
                            CREATE TABLE IF NOT EXISTS dashboard_order_archive (
                                order_id TEXT PRIMARY KEY,
                                record_json TEXT NOT NULL,
                                updated_at REAL NOT NULL
                            )
                            """
                        )
                        rows = conn.execute("SELECT order_id, record_json FROM dashboard_order_archive").fetchall()
                        for oid, rjson in rows:
                            if oid not in self.state_engine._orders_by_id:
                                try:
                                    self._dashboard_order_ledger[oid] = OrderRecord(**json.loads(rjson))
                                except Exception:
                                    pass
                except Exception:
                    pass

            for oid, rec in self.state_engine._orders_by_id.items():
                self._dashboard_order_ledger[oid] = rec

            if db_path and self._dashboard_order_ledger:
                try:
                    now_ts = time.time()
                    with sqlite3.connect(db_path, timeout=10.0) as conn:
                        conn.executemany(
                            """
                            INSERT INTO dashboard_order_archive (order_id, record_json, updated_at)
                            VALUES (?, ?, ?)
                            ON CONFLICT(order_id) DO UPDATE SET
                                record_json = excluded.record_json,
                                updated_at = excluded.updated_at
                            """,
                            [
                                (oid, json.dumps(asdict(rec), default=str), now_ts)
                                for oid, rec in self._dashboard_order_ledger.items()
                            ],
                        )
                        conn.commit()
                except Exception:
                    pass
            self._sync_blocked_echoes_locked(db_path)
            return dict(self._dashboard_order_ledger)

    def _sync_blocked_echoes_locked(self, db_path: Optional[str]) -> list[Dict[str, Any]]:
        if not hasattr(self, "_blocked_echo_archive"):
            self._blocked_echo_archive: Dict[str, Dict[str, Any]] = {}
        for idx, e in enumerate(self.webhook_mutex.get_blocked_echoes()):
            ed = asdict(e) if hasattr(e, "__dataclass_fields__") else dict(e)
            key = f"{ed.get('order_id', '')}:{ed.get('capture_id', '')}:{ed.get('timestamp', idx)}"
            self._blocked_echo_archive[key] = ed
        if db_path:
            try:
                with sqlite3.connect(db_path, timeout=5.0) as conn:
                    conn.execute(
                        """
                        CREATE TABLE IF NOT EXISTS dashboard_blocked_echoes_archive (
                            echo_key TEXT PRIMARY KEY,
                            echo_json TEXT NOT NULL
                        )
                        """
                    )
                    for k, v in self._blocked_echo_archive.items():
                        conn.execute(
                            "INSERT OR REPLACE INTO dashboard_blocked_echoes_archive (echo_key, echo_json) VALUES (?, ?)",
                            (k, json.dumps(v, default=str)),
                        )
                    conn.commit()
                    for k, ejson in conn.execute("SELECT echo_key, echo_json FROM dashboard_blocked_echoes_archive").fetchall():
                        self._blocked_echo_archive.setdefault(k, json.loads(ejson))
            except Exception:
                pass
        return list(self._blocked_echo_archive.values())

    def get_persisted_blocked_echoes(self, *, order_id: Optional[str] = None) -> list[Dict[str, Any]]:
        db_path = getattr(self.state_engine, "db_path", None)
        with self.state_engine._lock:
            items = self._sync_blocked_echoes_locked(db_path)
        if order_id:
            target = order_id.strip()
            items = [e for e in items if e.get("order_id") == target]
        return items

    def get_order_record(self, order_id: str) -> Optional[OrderRecord]:
        rec = self.state_engine.get_order(order_id)
        if rec is not None:
            self._dashboard_order_ledger[rec.order_id] = rec
            return rec
        return self._dashboard_order_ledger.get((order_id or "").strip())

    def serialize_order(self, order: OrderRecord, *, now: Optional[float] = None) -> Dict[str, Any]:
        """Serialize an OrderRecord with sanitized text fields, Glass-Box badges, and 24h watchlist status."""
        current_time = float(now) if now is not None else time.time()
        badge = compute_glassbox_evidence_badge(order)
        fee_at_stake = estimate_paypal_fee_saved_usd(order.amount, order.currency)
        fee_saved = (
            fee_at_stake
            if order.resolution_status in ("AUTHORIZED_HOLD", "VOIDED", "NEEDS_ATTENTION", "ANALYZING_HOLD")
            else 0.0
        )
        chronic_alert = (
            self.chronic_monitor.evaluate_buyer_24h_cycle(order.payer_id, now=current_time)
            if order.payer_id
            else None
        )
        voidable = (
            order.resolution_status == "AUTHORIZED_HOLD"
            and order.pillar2_classification != "LEGITIMATE_REPEAT_BUYER"
            and bool(order.authorization_id)
        )
        can_merchant_approve_capture = (
            order.resolution_status in ("AUTHORIZED_HOLD", "NEEDS_ATTENTION", "ANALYZING_HOLD")
            and bool(order.authorization_id)
            and not order.capture_id
        )
        return {
            "order_id": order.order_id,
            "incident_id": order.incident_id,
            "authorization_id": order.authorization_id,
            "capture_id": order.capture_id,
            "resolution_status": order.resolution_status,
            "amount": order.amount,
            "currency": order.currency,
            "payer_id": order.payer_id,
            "payer_email": order.payer_email,
            "sku": sanitize_dashboard_summary(order.sku or "untagged")[:120],
            "sku_category": order.sku_category,
            "item_name": sanitize_dashboard_summary(order.item_name or "")[:200],
            "description": sanitize_dashboard_summary(order.description or "")[:300],
            "note_to_payer": sanitize_dashboard_summary(order.note_to_payer or "")[:300]
            if order.note_to_payer
            else None,
            "cart_fingerprint_complete": order.cart_fingerprint_complete,
            "identity_strength": order.identity_strength,
            "has_reliable_identity": order.has_reliable_identity,
            "is_flagged": order.is_flagged,
            "can_auto_capture_if_llm_approves": order.can_auto_capture_if_llm_approves,
            "decision_mode": badge.get("decision_mode") or (
                "NO_LLM_REQUIRED"
                if (not order.is_flagged and order.can_auto_capture_if_llm_approves)
                else ("DECISION_ASSISTED" if order.can_auto_capture_if_llm_approves else "EXPLANATION_ONLY")
            ),
            "pillar2_classification": order.pillar2_classification,
            "pillar2_confidence": getattr(order, "pillar2_confidence", None),
            "pillar2_recommended_action": (
                "ALLOW_CAPTURE"
                if (order.resolution_status == "CAPTURED" and order.pillar2_classification == "LEGITIMATE_REPEAT_BUYER")
                else ("HOLD_AUTHORIZE" if order.pillar2_classification else None)
            ),
            "pillar2_merchant_summary": badge.get("explanation_note"),
            "deterministic_hold_reason": order.deterministic_hold_reason,
            "manual_override_actor": order.manual_override_actor,
            "manual_override_reason": order.manual_override_reason,
            "glassbox_badge": badge,
            "estimated_fee_saved_usd": fee_saved,
            "paypal_fee_at_stake_usd": fee_at_stake,
            "actions_available": {
                "can_void_hold": bool(order.authorization_id)
                and order.resolution_status in ("AUTHORIZED_HOLD", "NEEDS_ATTENTION", "ANALYZING_HOLD"),
                "eligible_for_bulk_void": voidable,
                "can_merchant_approve_capture": can_merchant_approve_capture,
                "can_guarded_refund": order.resolution_status == "CAPTURED" and bool(order.capture_id),
            },
            "chronic_24h_refund_watchlist": chronic_alert.to_dict() if chronic_alert else None,
            "timestamp": order.timestamp,
            "status_updated_at": order.status_updated_at,
        }

    def get_dashboard_summary(self, *, now: Optional[float] = None) -> Dict[str, Any]:
        """Return real-time KPIs, fee-savings totals, outcome breakdowns, and active watchlists."""
        current_time = float(now) if now is not None else time.time()
        self.chronic_monitor.sync_from_pillars(now=current_time)
        all_orders = list(self._sync_order_ledger().values())

        captured = [o for o in all_orders if o.resolution_status == "CAPTURED"]
        held = [o for o in all_orders if o.resolution_status == "AUTHORIZED_HOLD"]
        needs_attention = [o for o in all_orders if o.resolution_status == "NEEDS_ATTENTION"]
        voided = [o for o in all_orders if o.resolution_status == "VOIDED"]
        analyzing = [o for o in all_orders if o.resolution_status == "ANALYZING_HOLD"]

        voided_fee_saved = round(
            sum(estimate_paypal_fee_saved_usd(o.amount, o.currency) for o in voided), 2
        )
        protected_on_hold_fee = round(
            sum(
                estimate_paypal_fee_saved_usd(o.amount, o.currency)
                for o in (held + needs_attention + analyzing)
            ),
            2,
        )
        blocked_echoes = self.get_persisted_blocked_echoes()
        watchlist_alerts = self.chronic_monitor.get_all_watchlist_alerts(now=current_time)

        return {
            "timestamp_epoch": current_time,
            "totals": {
                "total_orders": len(all_orders),
                "captured_count": len(captured),
                "authorized_hold_count": len(held),
                "needs_attention_count": len(needs_attention),
                "voided_count": len(voided),
                "analyzing_hold_count": len(analyzing),
                "blocked_webhook_echo_count": len(blocked_echoes),
                "chronic_24h_watchlist_count": len(watchlist_alerts),
            },
            "financial_protection": {
                "realized_fee_saved_on_voids_usd": voided_fee_saved,
                "active_fee_protected_on_holds_usd": protected_on_hold_fee,
                "total_fee_shielded_usd": round(voided_fee_saved + protected_on_hold_fee, 2),
                "chronic_24h_refund_fee_bleed_usd": round(
                    sum(a.cumulative_fee_bleed_usd for a in watchlist_alerts), 2
                ),
            },
            "active_websocket_clients": self.ws_manager.active_connection_count,
        }

    def list_orders(
        self,
        *,
        status: Optional[str] = None,
        incident_id: Optional[str] = None,
        limit: int = 100,
        now: Optional[float] = None,
    ) -> List[Dict[str, Any]]:
        current_time = float(now) if now is not None else time.time()
        orders = list(self._sync_order_ledger().values())
        if status:
            target = status.strip().upper()
            orders = [o for o in orders if o.resolution_status == target]
        if incident_id:
            target_inc = incident_id.strip()
            orders = [o for o in orders if o.incident_id == target_inc]
        orders.sort(key=lambda o: o.timestamp, reverse=True)
        return [self.serialize_order(o, now=current_time) for o in orders[: max(1, int(limit))]]

    def list_active_holds(
        self,
        *,
        incident_id: Optional[str] = None,
        voidable_only: bool = False,
        now: Optional[float] = None,
    ) -> List[Dict[str, Any]]:
        current_time = float(now) if now is not None else time.time()
        self._sync_order_ledger()
        holds = self.state_engine.get_active_holds(
            incident_id=incident_id, voidable_only=voidable_only
        )
        holds.sort(key=lambda o: o.timestamp, reverse=True)
        return [self.serialize_order(o, now=current_time) for o in holds]

    # ------------------------------------------------------------------
    # Checkout & Settlement Entrypoints (With Live WebSocket Broadcast)
    # ------------------------------------------------------------------
    def create_shielded_order(
        self,
        raw_order_payload: Dict[str, Any],
        *,
        checkout_attempt_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        rewritten, remote = create_shielded_paypal_order(
            self.settlement_client.paypal_client,
            raw_order_payload,
            self.state_engine,
            checkout_attempt_id=checkout_attempt_id,
        )
        order_id = str(remote.get("id") or "").strip()
        self.ws_manager.record_event(
            event_type="ORDER_CREATED_AUTHORIZE_SHIELDED",
            severity="INFO",
            order_id=order_id or None,
            headline=f"Order {order_id or 'NEW'} rewritten to AUTHORIZE (original intent={rewritten.original_intent}).",
            payload={
                "order_id": order_id,
                "original_intent": rewritten.original_intent,
                "rewritten_intent": getattr(rewritten, "effective_intent", getattr(rewritten, "rewritten_intent", "AUTHORIZE")),
                "amount": getattr(rewritten, "normalized_amount", getattr(rewritten, "amount", "0.00")),
                "currency": rewritten.currency,
            },
        )
        return {
            "order_id": order_id,
            "original_intent": rewritten.original_intent,
            "rewritten_intent": getattr(rewritten, "effective_intent", getattr(rewritten, "rewritten_intent", "AUTHORIZE")),
            "paypal_response": remote,
        }

    def settle_order(
        self,
        order_id: str,
        *,
        note_to_payer: Optional[str] = None,
        product_family_id: Optional[str] = None,
        customer_id: Optional[str] = None,
        session_id: Optional[str] = None,
        now: Optional[float] = None,
    ) -> Dict[str, Any]:
        current_time = float(now) if now is not None else time.time()
        clean_oid = (order_id or "").strip()
        remote_payer_id: Optional[str] = None
        remote_order_dict: Optional[Dict[str, Any]] = None
        try:
            remote_order_dict = self.settlement_client.paypal_client.get_order(clean_oid)
            if isinstance(remote_order_dict, dict):
                payer_obj = remote_order_dict.get("payer")
                if isinstance(payer_obj, dict):
                    remote_payer_id = str(payer_obj.get("payer_id") or "").strip() or None
        except Exception:
            remote_payer_id = None

        if remote_payer_id and self.chronic_monitor.is_buyer_auto_hold_enabled(remote_payer_id) and isinstance(remote_order_dict, dict):
            from src.pillar1_velocity_engine.deadlock_detector import (
                evaluate_approved_paypal_order,
                validate_mvp_order_shape,
            )
            from src.pillar3_capture_shield.settlement_client import SettlementOutcome
            validate_mvp_order_shape(remote_order_dict)
            p1_res = evaluate_approved_paypal_order(
                state_engine=self.state_engine,
                deadlock_detector=self.deadlock_detector,
                paypal_order=remote_order_dict,
                note_to_payer=note_to_payer,
                product_family_id=product_family_id,
                customer_id=customer_id,
                session_id=session_id,
                now=current_time,
            )
            auth_id, auth_status, auth_req_id, auth_reconcile_req, auth_err = (
                self.settlement_client._authorize_with_reconciliation(clean_oid, now=current_time)
            )
            hold_state = "AUTHORIZED_HOLD" if (auth_id and not auth_reconcile_req and auth_status == "CREATED") else "NEEDS_ATTENTION"
            if auth_id:
                self.state_engine.mark_order_authorized(
                    order_id=clean_oid,
                    authorization_id=auth_id,
                    status=hold_state,
                    now=current_time,
                )
            summary_msg = (
                "Held by merchant 24h Chronic Buy-Refund Watchlist policy (3+ completed refunds in 24h). "
                "Authorization is held in CREATED state awaiting manual merchant review."
            )
            self.state_engine.update_order_resolution(
                clean_oid,
                hold_state,
                now=current_time,
                pillar2_classification=None,
                deterministic_hold_reason="CHRONIC_24H_REFUND_CYCLE_WATCHLIST",
            )
            rec_for_fee = self.state_engine.get_order(clean_oid)
            fee_saved = estimate_paypal_fee_saved_usd(
                rec_for_fee.amount if rec_for_fee else "0.00",
                rec_for_fee.currency if rec_for_fee else "USD",
            )
            outcome = SettlementOutcome(
                order_id=clean_oid,
                authorization_id=auth_id,
                capture_id=None,
                final_status=hold_state,
                decision_mode="EXPLANATION_ONLY",
                capture_allowed=False,
                deterministic_override_applied=True,
                incident_id=p1_res.incident_id,
                pillar1_result=p1_res,
                pillar2_verdict=None,
                merchant_summary=summary_msg,
                estimated_fee_saved_usd=fee_saved,
                authorize_request_id=auth_req_id,
                reconciliation_required=auth_reconcile_req,
                error_reason=auth_err,
            )
        else:
            outcome = self.settlement_client.settle_approved_order(
                order_id,
                note_to_payer=note_to_payer,
                product_family_id=product_family_id,
                customer_id=customer_id,
                session_id=session_id,
                now=current_time,
            )
        order_rec = self.get_order_record(order_id)
        self._sync_order_ledger()
        chronic_alert = None
        if order_rec is not None:
            self.chronic_monitor.ingest_order(order_rec, now=current_time)
            if order_rec.payer_id:
                chronic_alert = self.chronic_monitor.evaluate_buyer_24h_cycle(
                    order_rec.payer_id, now=current_time
                )

        severity = "SUCCESS" if outcome.final_status == "CAPTURED" else "WARNING"
        self.ws_manager.record_event(
            event_type=f"ORDER_SETTLED_{outcome.final_status}",
            severity=severity,
            order_id=outcome.order_id,
            incident_id=outcome.incident_id,
            headline=f"Order {outcome.order_id} settled -> {outcome.final_status} ({outcome.decision_mode}): {outcome.merchant_summary}",
            payload={
                "order_id": outcome.order_id,
                "final_status": outcome.final_status,
                "decision_mode": outcome.decision_mode,
                "capture_allowed": outcome.capture_allowed,
                "estimated_fee_saved_usd": outcome.estimated_fee_saved_usd,
                "chronic_24h_watchlist_flagged": chronic_alert is not None,
            },
            now=current_time,
        )
        return {
            "order_id": outcome.order_id,
            "authorization_id": outcome.authorization_id,
            "capture_id": outcome.capture_id,
            "final_status": outcome.final_status,
            "decision_mode": outcome.decision_mode,
            "capture_allowed": outcome.capture_allowed,
            "deterministic_override_applied": outcome.deterministic_override_applied,
            "incident_id": outcome.incident_id,
            "merchant_summary": outcome.merchant_summary,
            "estimated_fee_saved_usd": outcome.estimated_fee_saved_usd,
            "error_reason": outcome.error_reason,
            "order_detail": self.serialize_order(order_rec, now=current_time) if order_rec else None,
            "chronic_24h_refund_watchlist": chronic_alert.to_dict() if chronic_alert else None,
        }

    # ------------------------------------------------------------------
    # Direction A: Reject & Release Hold Back to Buyer (1-Tap Void & Bulk Void)
    # ------------------------------------------------------------------
    def void_held_order(
        self,
        authorization_id: str,
        *,
        merchant_actor: str = "merchant_admin",
        reason: str = "Merchant voided held authorization from Glass-Box Dashboard",
        now: Optional[float] = None,
    ) -> Dict[str, Any]:
        current_time = float(now) if now is not None else time.time()
        self._sync_order_ledger()
        outcome = self.settlement_client.void_authorization(
            authorization_id,
            merchant_actor=merchant_actor,
            reason=reason,
            now=current_time,
        )
        self.ws_manager.record_event(
            event_type="HOLD_VOIDED_BY_MERCHANT",
            severity="SUCCESS",
            order_id=outcome.order_id,
            incident_id=outcome.incident_id,
            headline=(
                f"Authorization {outcome.authorization_id} (order {outcome.order_id}) VOIDED by "
                f"{outcome.merchant_actor}; saved ${outcome.estimated_fee_saved_usd:.2f} in non-refundable fees."
            ),
            payload={
                "order_id": outcome.order_id,
                "authorization_id": outcome.authorization_id,
                "status": outcome.status,
                "estimated_fee_saved_usd": outcome.estimated_fee_saved_usd,
                "merchant_actor": outcome.merchant_actor,
                "reason": outcome.reason,
            },
            now=current_time,
        )
        order_rec = self.get_order_record(outcome.order_id)
        self._sync_order_ledger()
        return {
            "order_id": outcome.order_id,
            "authorization_id": outcome.authorization_id,
            "status": outcome.status,
            "incident_id": outcome.incident_id,
            "estimated_fee_saved_usd": outcome.estimated_fee_saved_usd,
            "merchant_actor": outcome.merchant_actor,
            "reason": outcome.reason,
            "order_detail": self.serialize_order(order_rec, now=current_time) if order_rec else None,
        }

    def bulk_void_incident(
        self,
        incident_id: str,
        *,
        merchant_actor: str = "merchant_admin",
        reason: str = "Scoped bulk void of incident holds from Glass-Box Dashboard",
        now: Optional[float] = None,
    ) -> Dict[str, Any]:
        current_time = float(now) if now is not None else time.time()
        self._sync_order_ledger()
        outcome = self.settlement_client.bulk_void_incident_holds(
            incident_id,
            merchant_actor=merchant_actor,
            reason=reason,
            now=current_time,
        )
        self._sync_order_ledger()
        raw_voided = getattr(outcome, "voided_order_ids", None)
        if raw_voided is None:
            voided_ids = [
                getattr(v, "order_id", str(v))
                for v in getattr(outcome, "voided_orders", [])
            ]
        else:
            voided_ids = list(raw_voided)
        skipped_ids = list(
            getattr(
                outcome,
                "skipped_legitimate_order_ids",
                getattr(outcome, "skipped_order_ids", []),
            )
        )
        actor_val = getattr(outcome, "merchant_actor", merchant_actor)
        self.ws_manager.record_event(
            event_type="INCIDENT_BULK_VOID_COMPLETED",
            severity="SUCCESS",
            incident_id=outcome.incident_id,
            headline=(
                f"Bulk Void on incident {outcome.incident_id}: voided {len(voided_ids)} holds "
                f"(skipped {len(skipped_ids)} AI-legitimate holds), "
                f"saved ${outcome.total_estimated_fee_saved_usd:.2f}."
            ),
            payload={
                "incident_id": outcome.incident_id,
                "voided_order_ids": voided_ids,
                "skipped_legitimate_order_ids": skipped_ids,
                "failed_orders": outcome.failed_orders,
                "total_estimated_fee_saved_usd": outcome.total_estimated_fee_saved_usd,
            },
            now=current_time,
        )
        return {
            "incident_id": outcome.incident_id,
            "voided_order_ids": voided_ids,
            "skipped_legitimate_order_ids": skipped_ids,
            "failed_orders": outcome.failed_orders,
            "total_estimated_fee_saved_usd": outcome.total_estimated_fee_saved_usd,
            "merchant_actor": actor_val,
        }

    # ------------------------------------------------------------------
    # Direction B: Approve & Release Hold Into Completed Sale (Guarded Admin Capture)
    # ------------------------------------------------------------------
    def approve_and_capture_held_order(
        self,
        authorization_id: str,
        *,
        merchant_actor: str,
        override_reason: str,
        now: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Allow an authenticated merchant admin to approve and capture a held authorization.

        This uses P1's `validate_order_ready_for_capture(..., capture_mode='MANUAL_MERCHANT_OVERRIDE',
        allow_manual_override=True)` and verifies live PayPal `GET /v2/payments/authorizations/{id}`
        status == 'CREATED' before capturing the exact full order amount, while leaving
        `SettlementClient.manual_capture_authorization()` raising `PermissionError` by default
        so automated checkout callers can never bypass P1/P2.
        """
        current_time = float(now) if now is not None else time.time()
        clean_auth = (authorization_id or "").strip()
        clean_actor = sanitize_dashboard_summary((merchant_actor or "").strip())[:120]
        clean_reason = sanitize_dashboard_summary((override_reason or "").strip())[:300]
        if not clean_auth:
            raise ValueError("authorization_id is required.")
        if not clean_actor:
            raise PermissionError("merchant_actor is required to approve and capture a held order.")
        if not clean_reason:
            raise PermissionError("override_reason is required to approve and capture a held order.")

        self._sync_order_ledger()
        order_rec = self.state_engine.get_order_by_auth_id(clean_auth)
        if order_rec is None:
            raise ValueError(f"No order found for authorization_id '{clean_auth}'.")

        order_lock = self.settlement_client._get_order_lock(order_rec.order_id)
        with order_lock:
            order_rec = self.state_engine.get_order(order_rec.order_id) or order_rec
            if order_rec.resolution_status == "CAPTURED" and order_rec.capture_id:
                return {
                    "order_id": order_rec.order_id,
                    "authorization_id": clean_auth,
                    "capture_id": order_rec.capture_id,
                    "final_status": "CAPTURED",
                    "merchant_actor": order_rec.manual_override_actor or clean_actor,
                    "override_reason": order_rec.manual_override_reason or clean_reason,
                    "idempotent_replay": True,
                    "order_detail": self.serialize_order(order_rec, now=current_time),
                }

            live_auth = self.settlement_client.paypal_client.get_authorization(clean_auth)
            live_auth_id = str(live_auth.get("id") or "").strip()
            live_auth_status = str(live_auth.get("status") or "").strip().upper()
            if live_auth_id != clean_auth:
                raise ValueError(
                    f"PayPal authorization ID mismatch: expected '{clean_auth}', got '{live_auth_id}'."
                )

            ready, validation_code = validate_order_ready_for_capture(
                order=order_rec,
                decision_allows_capture=True,
                capture_mode="MANUAL_MERCHANT_OVERRIDE",
                paypal_auth_status=live_auth_status,
                merchant_actor=clean_actor,
                override_reason=clean_reason,
                paypal_auth_status_verified=True,
                allow_manual_override=True,
                allow_partial_captures=False,
            )
            if not ready:
                raise PermissionError(
                    f"Merchant manual capture rejected by deterministic validator: {validation_code}"
                )

            payload = {
                "amount": {
                    "currency_code": order_rec.currency,
                    "value": order_rec.amount,
                },
                "final_capture": True,
            }
            logical_op_id, default_req_id = self.settlement_client._build_capture_operation_ids(
                authorization_id=clean_auth,
                operation_key="full",
                payload=payload,
            )
            op = self.settlement_client._get_or_create_operation(
                operation_id=logical_op_id,
                operation_type="CAPTURE",
                order_id=order_rec.order_id,
                authorization_id=clean_auth,
                default_paypal_request_id=default_req_id,
                payload=payload,
                now=current_time,
            )

            if not self.state_engine.update_order_resolution(
                order_rec.order_id,
                "AUTO_CAPTURING",
                now=current_time,
                manual_override_actor=clean_actor,
                manual_override_reason=clean_reason,
            ):
                raise RuntimeError(
                    f"Order '{order_rec.order_id}' could not transition to capturing state."
                )

            try:
                response = self.settlement_client.paypal_client.capture_authorization(
                    authorization_id=clean_auth,
                    paypal_request_id=op.paypal_request_id,
                    payload=payload,
                )
            except PayPalError as exc:
                self.settlement_client._update_operation_status(
                    logical_op_id,
                    "RECONCILIATION_REQUIRED" if getattr(exc, "ambiguous", False) else "FAILED",
                    error_detail=sanitize_dashboard_summary(str(exc)),
                    now=current_time,
                )
                self.state_engine.update_order_resolution(
                    order_rec.order_id, "NEEDS_ATTENTION", now=current_time
                )
                raise

            capture_id = str(response.get("id") or "").strip()
            capture_status = str(response.get("status") or "").strip().upper()
            if not capture_id or capture_status not in ("COMPLETED", "PENDING"):
                self.settlement_client._update_operation_status(
                    logical_op_id,
                    "RECONCILIATION_REQUIRED",
                    capture_id=capture_id or None,
                    provider_status=capture_status or None,
                    error_detail="Ambiguous manual capture response",
                    now=current_time,
                )
                self.state_engine.update_order_resolution(
                    order_rec.order_id, "NEEDS_ATTENTION", now=current_time
                )
                raise RuntimeError("PayPal capture response lacked a valid capture_id or status.")

            target_resolution = "CAPTURED" if capture_status == "COMPLETED" else "NEEDS_ATTENTION"
            self.settlement_client._update_operation_status(
                logical_op_id,
                "SUCCEEDED",
                capture_id=capture_id,
                provider_status=capture_status,
                now=current_time,
            )
            self.settlement_client._register_completed_capture(
                order_id=order_rec.order_id,
                authorization_id=clean_auth,
                capture_id=capture_id,
                resolution_status=target_resolution,
                now=current_time,
            )
            self.state_engine.update_order_resolution(
                order_rec.order_id,
                target_resolution,
                now=current_time,
                manual_override_actor=clean_actor,
                manual_override_reason=clean_reason,
            )
            updated_order = self.state_engine.get_order(order_rec.order_id) or order_rec
            self._dashboard_order_ledger[updated_order.order_id] = updated_order
            self._sync_order_ledger()

        self.ws_manager.record_event(
            event_type="HOLD_APPROVED_AND_CAPTURED_BY_MERCHANT",
            severity="SUCCESS",
            order_id=updated_order.order_id,
            incident_id=updated_order.incident_id,
            headline=(
                f"Held order {updated_order.order_id} approved and captured ({capture_id}) "
                f"by {clean_actor}: {clean_reason}"
            ),
            payload={
                "order_id": updated_order.order_id,
                "authorization_id": clean_auth,
                "capture_id": capture_id,
                "final_status": target_resolution,
                "merchant_actor": clean_actor,
                "override_reason": clean_reason,
            },
            now=current_time,
        )
        return {
            "order_id": updated_order.order_id,
            "authorization_id": clean_auth,
            "capture_id": capture_id,
            "final_status": target_resolution,
            "merchant_actor": clean_actor,
            "override_reason": clean_reason,
            "idempotent_replay": False,
            "order_detail": self.serialize_order(updated_order, now=current_time),
        }

    # ------------------------------------------------------------------
    # Guarded Outbound Refund & Stuck-Hold Reconciliation
    # ------------------------------------------------------------------
    def execute_guarded_refund(
        self,
        *,
        order_id: Optional[str] = None,
        capture_id: Optional[str] = None,
        amount: Optional[str] = None,
        currency: Optional[str] = None,
        reason: str = "Merchant initiated guarded refund from Glass-Box Dashboard",
        caller_source: str = "MERCHANT_DASHBOARD",
        now: Optional[float] = None,
    ) -> Dict[str, Any]:
        current_time = float(now) if now is not None else time.time()
        res = self.settlement_client.execute_guarded_refund(
            order_id=order_id,
            capture_id=capture_id,
            amount=amount,
            currency=currency,
            reason=reason,
            caller_source=caller_source,
            now=current_time,
        )
        ev_type = (
            "WEBHOOK_ECHO_REFUND_BLOCKED"
            if res.status == "BLOCKED_WEBHOOK_ECHO"
            else f"GUARDED_REFUND_{res.status}"
        )
        self.ws_manager.record_event(
            event_type=ev_type,
            severity="WARNING" if res.status == "BLOCKED_WEBHOOK_ECHO" else "INFO",
            order_id=order_id,
            headline=f"Guarded refund outcome={res.status}: {res.message}",
            payload={
                "order_id": order_id,
                "capture_id": capture_id,
                "status": res.status,
                "paypal_refund_id": res.paypal_refund_id,
                "message": res.message,
            },
            now=current_time,
        )
        return {
            "executed": getattr(res, "executed", res.status == "SUCCEEDED"),
            "status": res.status,
            "message": res.message,
            "paypal_refund_id": res.paypal_refund_id,
            "operation_id": res.operation.operation_id if res.operation else None,
        }

    def run_reconciliation_sweep(
        self, *, older_than_seconds: float = 60.0, now: Optional[float] = None
    ) -> Dict[str, Any]:
        current_time = float(now) if now is not None else time.time()
        report = self.settlement_client.reconcile_stuck_holds(
            older_than_seconds=older_than_seconds,
            now=current_time,
        )
        reconciled_captured = list(
            getattr(report, "reconciled_captured", getattr(report, "resolved_captured_order_ids", []))
        )
        reconciled_held = list(
            getattr(report, "reconciled_authorized_hold", getattr(report, "resumed_settlement_order_ids", []))
        )
        reconciled_voided = list(
            getattr(report, "reconciled_voided", getattr(report, "resolved_voided_order_ids", []))
        )
        flagged_attention = list(
            getattr(report, "flagged_needs_attention", getattr(report, "escalated_needs_attention_order_ids", []))
        )
        errors_val = getattr(report, "errors", getattr(report, "errors_by_order_id", {}))
        self.ws_manager.record_event(
            event_type="RECONCILIATION_SWEEP_COMPLETED",
            severity="INFO",
            headline=(
                f"Reconciled {len(report.checked_order_ids)} stuck holds: "
                f"captured={len(reconciled_captured)}, "
                f"held={len(reconciled_held)}, "
                f"voided={len(reconciled_voided)}."
            ),
            payload={
                "checked_order_ids": report.checked_order_ids,
                "reconciled_captured": reconciled_captured,
                "reconciled_authorized_hold": reconciled_held,
                "reconciled_voided": reconciled_voided,
                "flagged_needs_attention": flagged_attention,
            },
            now=current_time,
        )
        return {
            "checked_order_ids": report.checked_order_ids,
            "reconciled_captured": reconciled_captured,
            "reconciled_authorized_hold": reconciled_held,
            "reconciled_voided": reconciled_voided,
            "flagged_needs_attention": flagged_attention,
            "errors": errors_val,
        }