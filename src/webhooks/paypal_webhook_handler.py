"""Verified PayPal Webhook Ingestion Handler (`PAYMENT.CAPTURE.REFUNDED`) for IntentGuard.

Enforces the locked Pillar 1 + Pillar 3 + Pillar 4 webhook contract:
1. Cryptographic sender authentication via `paypal_client.verify_webhook_signature(...)`
   (`POST /v1/notifications/verify-webhook-signature`) BEFORE claiming `event_id` in the
   idempotency ledger, preventing unauthenticated callers from spoofing refunds or poisoning
   `webhook_event_ledger`.
2. Idempotent event claiming via `state_engine.claim_webhook_event(event_id)` before processing.
3. Authoritative refund verification via `paypal_client.get_refund(refund_id)` when enabled,
   never trusting unverified caller timestamps.
4. Strict timestamp discipline: if PayPal's refund resource lacks a parsable `create_time`,
   `refund_event_time` remains `None` and `timestamp_resolved=False` (webhook receipt time is
   NEVER substituted to fabricate a 60-minute deadlock).
5. Atomic registration in `deadlock_detector.record_refund(...)` and echo-lock activation in
   `webhook_mutex.set_webhook_refund_lock(...)`.
6. Automatic feed into Pillar 4's 24-Hour Chronic Refund-Loop Watchlist (`3+ in 24h`) and
   real-time WebSocket broadcast to the Merchant Glass-Box Dashboard.
"""
from __future__ import annotations

import logging
import os
import time
from dataclasses import asdict, dataclass
from typing import Any, Dict, Optional

from src.pillar1_velocity_engine.deadlock_detector import (
    BuyRefundDeadlockDetector,
    extract_capture_id_from_webhook,
    extract_refund_timestamps_from_webhook,
    parse_paypal_timestamp,
)
from src.pillar1_velocity_engine.state_engine import VelocityStateEngine
from src.pillar1_velocity_engine.webhook_mutex import WebhookRefundMutex
from src.pillar3_capture_shield.settlement_client import sanitize_dashboard_summary

LOGGER = logging.getLogger("intentguard.webhooks.paypal")

SUPPORTED_REFUND_EVENT_TYPES = frozenset(
    {
        "PAYMENT.CAPTURE.REFUNDED",
        "PAYMENT.SALE.REFUNDED",
    }
)

REQUIRED_PAYPAL_SIGNATURE_HEADERS = (
    "paypal-auth-algo",
    "paypal-cert-url",
    "paypal-transmission-id",
    "paypal-transmission-sig",
    "paypal-transmission-time",
)


@dataclass
class WebhookProcessingResult:
    http_status: int
    status: str
    event_id: str
    event_type: str
    refund_id: Optional[str] = None
    capture_id: Optional[str] = None
    order_id: Optional[str] = None
    timestamp_resolved: Optional[bool] = None
    webhook_mutex_locked: bool = False
    signature_verified: bool = False
    chronic_24h_alert: Optional[Dict[str, Any]] = None
    message: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class PayPalWebhookHandler:
    """Adapter and HTTP handler for incoming PayPal refund webhooks."""

    def __init__(
        self,
        *,
        state_engine: VelocityStateEngine,
        deadlock_detector: BuyRefundDeadlockDetector,
        webhook_mutex: WebhookRefundMutex,
        paypal_client: Optional[Any] = None,
        chronic_monitor: Optional[Any] = None,
        ws_manager: Optional[Any] = None,
        verify_with_paypal_get: bool = True,
        verify_webhook_signature: Optional[bool] = None,
        webhook_id: Optional[str] = None,
    ) -> None:
        self.state_engine = state_engine
        self.deadlock_detector = deadlock_detector
        self.webhook_mutex = webhook_mutex
        self.paypal_client = paypal_client
        self.chronic_monitor = chronic_monitor
        self.ws_manager = ws_manager
        self.verify_with_paypal_get = bool(verify_with_paypal_get)
        resolved_wh_id = (
            webhook_id if webhook_id is not None else os.getenv("PAYPAL_WEBHOOK_ID") or ""
        ).strip()
        if resolved_wh_id.upper().startswith("YOUR_"):
            resolved_wh_id = ""
        self.webhook_id: Optional[str] = resolved_wh_id or None
        if verify_webhook_signature is None:
            # Automatically enforce cryptographic signature verification whenever PAYPAL_WEBHOOK_ID is configured
            self.verify_webhook_signature = bool(self.webhook_id)
        else:
            self.verify_webhook_signature = bool(verify_webhook_signature)

    def _authenticate_webhook_signature(
        self,
        payload: Dict[str, Any],
        headers: Optional[Dict[str, str]],
        *,
        event_id: str,
        event_type: str,
    ) -> Optional[WebhookProcessingResult]:
        """Verify PayPal's cryptographic webhook signature BEFORE claiming `event_id`."""
        norm_headers = {
            str(k).strip().lower(): str(v).strip()
            for k, v in (headers or {}).items()
            if k is not None and v is not None
        }
        has_any_sig_header = any(h in norm_headers for h in REQUIRED_PAYPAL_SIGNATURE_HEADERS)
        if not self.verify_webhook_signature and not has_any_sig_header:
            return None

        missing = [h for h in REQUIRED_PAYPAL_SIGNATURE_HEADERS if not norm_headers.get(h)]
        effective_webhook_id = self.webhook_id or ""  # Strictly server-configured PAYPAL_WEBHOOK_ID; never trust caller header
        if not effective_webhook_id:
            missing.append("PAYPAL_WEBHOOK_ID")
        if missing:
            return WebhookProcessingResult(
                http_status=401,
                status="REJECTED_MISSING_SIGNATURE_HEADERS",
                event_id=event_id,
                event_type=event_type,
                signature_verified=False,
                message=f"Missing required PayPal webhook signature fields: {', '.join(missing)}",
            )

        if self.paypal_client is None or not hasattr(self.paypal_client, "verify_webhook_signature"):
            return WebhookProcessingResult(
                http_status=503,
                status="REJECTED_SIGNATURE_VERIFIER_UNAVAILABLE",
                event_id=event_id,
                event_type=event_type,
                signature_verified=False,
                message="PayPal client does not support verify_webhook_signature.",
            )

        try:
            verified = bool(
                self.paypal_client.verify_webhook_signature(
                    auth_algo=norm_headers["paypal-auth-algo"],
                    cert_url=norm_headers["paypal-cert-url"],
                    transmission_id=norm_headers["paypal-transmission-id"],
                    transmission_sig=norm_headers["paypal-transmission-sig"],
                    transmission_time=norm_headers["paypal-transmission-time"],
                    webhook_id=effective_webhook_id,
                    webhook_event=payload,
                )
            )
        except Exception as exc:
            LOGGER.warning("PayPal webhook signature verification call failed for %s: %s", event_id, exc)
            return WebhookProcessingResult(
                http_status=401,
                status="REJECTED_INVALID_WEBHOOK_SIGNATURE",
                event_id=event_id,
                event_type=event_type,
                signature_verified=False,
                message=f"PayPal webhook signature verification failed: {sanitize_dashboard_summary(str(exc))[:180]}",
            )

        if not verified:
            return WebhookProcessingResult(
                http_status=401,
                status="REJECTED_INVALID_WEBHOOK_SIGNATURE",
                event_id=event_id,
                event_type=event_type,
                signature_verified=False,
                message="PayPal verify-webhook-signature returned FAILURE.",
            )
        return None

    def handle_webhook_payload(
        self,
        payload: Dict[str, Any],
        *,
        headers: Optional[Dict[str, str]] = None,
        now: Optional[float] = None,
        internal_trusted_caller: bool = False,
    ) -> WebhookProcessingResult:
        current_time = float(now) if now is not None else time.time()
        if not isinstance(payload, dict):
            raise ValueError("Webhook payload must be a JSON object.")

        event_id = str(payload.get("id") or "").strip()
        event_type = str(payload.get("event_type") or "").strip().upper()
        if not event_id:
            raise ValueError("PayPal webhook payload is missing required 'id' field.")
        if not event_type:
            raise ValueError("PayPal webhook payload is missing required 'event_type' field.")

        # Step 1: Authenticate webhook signature BEFORE claiming `event_id` in the ledger
        auth_failure = None if internal_trusted_caller else self._authenticate_webhook_signature(
            payload,
            headers,
            event_id=event_id,
            event_type=event_type,
        )
        if auth_failure is not None:
            if self.ws_manager is not None:
                self.ws_manager.record_event(
                    event_type="WEBHOOK_SIGNATURE_REJECTED",
                    severity="CRITICAL",
                    headline=f"Rejected unauthenticated webhook {event_id} ({auth_failure.status}).",
                    payload=auth_failure.to_dict(),
                    now=current_time,
                )
            return auth_failure

        norm_headers = {
            str(k).strip().lower(): str(v).strip()
            for k, v in (headers or {}).items()
            if k is not None and v is not None
        }
        sig_was_verified = bool(
            internal_trusted_caller
            or self.verify_webhook_signature
            or any(h in norm_headers for h in REQUIRED_PAYPAL_SIGNATURE_HEADERS)
        )

        if event_type not in SUPPORTED_REFUND_EVENT_TYPES:
            return WebhookProcessingResult(
                http_status=200,
                status="IGNORED_UNSUPPORTED_EVENT_TYPE",
                event_id=event_id,
                event_type=event_type,
                signature_verified=sig_was_verified,
                message=f"Event type '{event_type}' is not a refund event; ignored cleanly.",
            )

        # Step 2: Claim event_id idempotently (only after authenticity check passes)
        claim = self.state_engine.claim_webhook_event(event_id, now=current_time)
        claim_status = getattr(claim, "status", None)
        if claim is False or claim_status == "DUPLICATE_PROCESSED":
            return WebhookProcessingResult(
                http_status=200,
                status="DUPLICATE_PROCESSED",
                event_id=event_id,
                event_type=event_type,
                signature_verified=sig_was_verified,
                message="Webhook event was already processed or claimed idempotently.",
            )
        if claim_status == "IN_FLIGHT_DUPLICATE":
            return WebhookProcessingResult(
                http_status=202,
                status="IN_FLIGHT_DUPLICATE",
                event_id=event_id,
                event_type=event_type,
                signature_verified=sig_was_verified,
                message="Webhook event is currently being processed by an active worker.",
            )

        try:
            resource = payload.get("resource")
            if not isinstance(resource, dict):
                raise ValueError("Webhook payload is missing 'resource' object.")

            refund_id = str(resource.get("id") or "").strip()
            if not refund_id:
                raise ValueError("Refund webhook resource is missing required 'id' (refund_id).")

            capture_id = extract_capture_id_from_webhook(payload)
            if not capture_id:
                raise ValueError(
                    f"Could not extract parent capture_id from refund webhook '{event_id}'."
                )

            # Resolve linked local order via capture_id
            linked_order = self.state_engine.get_order_by_capture_id(capture_id)
            if linked_order is None:
                raise ValueError(
                    f"Capture '{capture_id}' is not registered to any known local order."
                )

            # Authoritative GET /v2/payments/refunds/{refund_id} when client is available
            authoritative_resource = resource
            if self.verify_with_paypal_get and self.paypal_client is not None:
                get_refund_fn = getattr(self.paypal_client, "get_refund", None)
                if callable(get_refund_fn):
                    authoritative_resource = get_refund_fn(refund_id)

            raw_status = str(authoritative_resource.get("status") or "").strip().upper()
            if not raw_status:
                raise ValueError(
                    f"Refund resource '{refund_id}' is missing explicit 'status' field."
                )

            amount_obj = authoritative_resource.get("amount") or resource.get("amount") or {}
            refund_amount = str(amount_obj.get("value") or linked_order.amount).strip()
            refund_currency = (
                str(amount_obj.get("currency_code") or linked_order.currency).strip().upper()
            )

            # Extract create_time strictly from authoritative resource without falling back
            # to webhook receipt time (Scenario 12 invariant).
            raw_create_time = authoritative_resource.get("create_time")
            resolved_event_time = (
                parse_paypal_timestamp(raw_create_time) if raw_create_time else None
            )
            if resolved_event_time is None and not self.verify_with_paypal_get:
                resource_create_ts, _ = extract_refund_timestamps_from_webhook(payload)
                resolved_event_time = resource_create_ts

            timestamp_resolved = resolved_event_time is not None

            refund_rec = self.deadlock_detector.record_refund(
                refund_id=refund_id,
                order_id=linked_order.order_id,
                capture_id=capture_id,
                payer_id=linked_order.payer_id,
                payer_email=linked_order.payer_email,
                shipping_address_hash=linked_order.shipping_address_hash,
                custom_id=linked_order.custom_id,
                customer_id=linked_order.customer_id,
                session_id=linked_order.session_id,
                sku=linked_order.sku,
                amount=refund_amount,
                original_order_amount=linked_order.amount,
                currency=refund_currency,
                item_name=linked_order.item_name,
                description=linked_order.description,
                refund_status=raw_status,
                refund_source="PAYPAL_WEBHOOK",
                refund_event_time=resolved_event_time,
                webhook_received_at=current_time,
                timestamp_resolved=timestamp_resolved,
                state_engine=self.state_engine,
                now=current_time,
            )

            mutex_locked = False
            if raw_status in ("COMPLETED", "PENDING"):
                self.webhook_mutex.set_webhook_refund_lock(
                    webhook_event_id=event_id,
                    order_id=linked_order.order_id,
                    capture_id=capture_id,
                    state_engine=self.state_engine,
                    now=current_time,
                )
                mutex_locked = True

            self.state_engine.mark_webhook_processed(event_id, now=current_time)

            chronic_alert_dict: Optional[Dict[str, Any]] = None
            if self.chronic_monitor is not None:
                self.chronic_monitor.ingest_refund(refund_rec, now=current_time)
                if linked_order.payer_id:
                    alert = self.chronic_monitor.evaluate_buyer_24h_cycle(
                        linked_order.payer_id, now=current_time
                    )
                    if alert is not None:
                        chronic_alert_dict = alert.to_dict()

            if self.ws_manager is not None:
                self.ws_manager.record_event(
                    event_type="WEBHOOK_REFUND_INGESTED",
                    severity="WARNING" if raw_status == "COMPLETED" else "INFO",
                    order_id=linked_order.order_id,
                    incident_id=linked_order.incident_id,
                    headline=(
                        f"PayPal refund {refund_id} ({raw_status}) ingested for order {linked_order.order_id}; "
                        f"echo mutex locked={mutex_locked}, timestamp_resolved={timestamp_resolved}, "
                        f"signature_verified={sig_was_verified}."
                    ),
                    payload={
                        "event_id": event_id,
                        "refund_id": refund_id,
                        "capture_id": capture_id,
                        "order_id": linked_order.order_id,
                        "refund_status": raw_status,
                        "amount": refund_amount,
                        "currency": refund_currency,
                        "timestamp_resolved": timestamp_resolved,
                        "webhook_mutex_locked": mutex_locked,
                        "signature_verified": sig_was_verified,
                    },
                    now=current_time,
                )
                if chronic_alert_dict is not None:
                    self.ws_manager.record_event(
                        event_type="CHRONIC_24H_REFUND_LOOP_FLAGGED",
                        severity="CRITICAL",
                        order_id=linked_order.order_id,
                        incident_id=linked_order.incident_id,
                        headline=(
                            f"24h Chronic Refund Loop Watchlist triggered for buyer {linked_order.payer_id}: "
                            f"{chronic_alert_dict['completed_refund_count_24h']} refunds in 24h "
                            f"(est. fee bleed ${chronic_alert_dict['cumulative_fee_bleed_usd']:.2f})."
                        ),
                        payload=chronic_alert_dict,
                        now=current_time,
                    )

            return WebhookProcessingResult(
                http_status=200,
                status="PROCESSED",
                event_id=event_id,
                event_type=event_type,
                refund_id=refund_id,
                capture_id=capture_id,
                order_id=linked_order.order_id,
                timestamp_resolved=timestamp_resolved,
                webhook_mutex_locked=mutex_locked,
                signature_verified=sig_was_verified,
                chronic_24h_alert=chronic_alert_dict,
                message="Refund webhook verified, recorded in P1 ledger, and locked in WebhookRefundMutex.",
            )
        except Exception as exc:
            # Release the in-flight claim so legitimate retries are not permanently blocked.
            self.state_engine.unmark_webhook_event(event_id)
            LOGGER.warning(
                "Webhook processing failed for event_id=%s: %s",
                event_id,
                sanitize_dashboard_summary(str(exc)),
            )
            raise