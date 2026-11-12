"""24-Hour Chronic Buy-Refund Cycle Watchlist & Slow-Roll Loop Detector for Pillar 4.

Addresses the delegated / slow-roll refund loop pattern:
- An autonomous agent or buyer delegates purchases spaced > 60 minutes apart (e.g. every 70-90m)
  so each individual repurchase falls outside Pillar 1's 60-minute acute deadlock window and
  15-minute velocity window.
- Cycles 1 and 2 (> 60m spacing) remain on the 0ms NO_LLM_REQUIRED fast path so normal buyer
  conversion and checkout speed are completely untouched.
- When the same buyer/identity accumulates >= `chronic_refund_threshold` (default: 3) completed
  refunds AND >= `chronic_order_threshold` (default: 3) orders within a rolling 24-hour window
  (`window_seconds = 86400`), this monitor deterministically flags the buyer and order 100%
  for manual merchant review (`CHRONIC_24H_REFUND_CYCLE_WATCHLIST`), computing the exact
  cumulative non-refundable PayPal fee bleed (`sum(3.49% + $0.49)`).
"""
from __future__ import annotations

import sqlite3
import threading
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Set

from src.pillar1_velocity_engine.deadlock_detector import BuyRefundDeadlockDetector, RefundRecord
from src.pillar1_velocity_engine.state_engine import OrderRecord, VelocityStateEngine
from src.pillar3_capture_shield.settlement_client import (
    estimate_paypal_fee_saved_usd,
    sanitize_dashboard_summary,
)

DEFAULT_CHRONIC_WINDOW_SECONDS = 86400  # 24 hours
DEFAULT_CHRONIC_REFUND_THRESHOLD = 3    # 3+ completed refunds in 24h
DEFAULT_CHRONIC_ORDER_THRESHOLD = 3     # 3+ orders in 24h
ACUTE_DEADLOCK_WINDOW_SECONDS = 3600    # 60 minutes


@dataclass
class ChronicRefundCycleAlert:
    alert_id: str
    payer_id: str
    sku_or_item: str
    window_hours: int
    completed_refund_count_24h: int
    order_count_24h: int
    long_gap_rebuy_count_24h: int  # Rebuys spaced > 60m after a refund inside 24h
    cumulative_fee_bleed_usd: float
    latest_order_id: Optional[str]
    latest_order_status: Optional[str]
    refund_ids_24h: List[str] = field(default_factory=list)
    order_ids_24h: List[str] = field(default_factory=list)
    spacing_gaps_minutes: List[float] = field(default_factory=list)
    auto_hold_enabled_for_buyer: bool = False
    review_status: str = "FLAGGED_FOR_MERCHANT_REVIEW"  # "FLAGGED_FOR_MERCHANT_REVIEW" | "ACKNOWLEDGED" | "AUTO_HOLD_ENFORCED"
    merchant_note: str = ""
    flagged_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ChronicRefundLoopMonitor:
    """Zero-checkout-latency 24-hour rolling buy-refund cycle monitor for Pillar 4."""

    def __init__(
        self,
        *,
        state_engine: VelocityStateEngine,
        deadlock_detector: BuyRefundDeadlockDetector,
        window_seconds: int = DEFAULT_CHRONIC_WINDOW_SECONDS,
        refund_threshold: int = DEFAULT_CHRONIC_REFUND_THRESHOLD,
        order_threshold: int = DEFAULT_CHRONIC_ORDER_THRESHOLD,
    ) -> None:
        if window_seconds < ACUTE_DEADLOCK_WINDOW_SECONDS:
            raise ValueError("window_seconds must be >= 3600 (60 minutes)")
        if refund_threshold < 2 or order_threshold < 2:
            raise ValueError("refund_threshold and order_threshold must be >= 2")
        self.state_engine = state_engine
        self.deadlock_detector = deadlock_detector
        self.window_seconds = int(window_seconds)
        self.refund_threshold = int(refund_threshold)
        self.order_threshold = int(order_threshold)
        self._lock = threading.RLock()
        # Persistent 24h archive of verified completed refunds so even if P1 prunes its
        # in-memory 60m acute deadlock index, Pillar 4 retains the 24h rolling history.
        self._refund_archive_24h: Dict[str, RefundRecord] = {}
        self._order_archive_24h: Dict[str, OrderRecord] = {}
        self._auto_hold_buyers: Set[str] = set()
        self._acknowledged_buyers: Dict[str, str] = {}

    def _prune_24h_archive_locked(self, now: float) -> None:
        cutoff = now - self.window_seconds
        expired_refunds = [
            rid
            for rid, rec in self._refund_archive_24h.items()
            if (rec.refund_event_time or rec.webhook_received_at or 0.0) < cutoff
        ]
        for rid in expired_refunds:
            self._refund_archive_24h.pop(rid, None)

        expired_orders = [
            oid
            for oid, rec in self._order_archive_24h.items()
            if rec.timestamp < cutoff
        ]
        for oid in expired_orders:
            self._order_archive_24h.pop(oid, None)

    def sync_from_pillars(self, *, now: Optional[float] = None) -> None:
        """ Pull current in-memory + SQLite orders and refunds into the 24h rolling archive."""
        current_time = float(now) if now is not None else time.time()
        cutoff = current_time - self.window_seconds

        with self.state_engine._lock:
            orders_snapshot = list(self.state_engine._orders_by_id.values())
        with self.deadlock_detector._lock:
            refunds_snapshot = list(self.deadlock_detector._refunds_by_id.values())

        db_path = getattr(self.deadlock_detector, "db_path", None) or getattr(
            self.state_engine, "db_path", None
        )

        with self._lock:
            for o in orders_snapshot:
                if o.timestamp >= cutoff:
                    self._order_archive_24h[o.order_id] = o
            for r in refunds_snapshot:
                ev_time = r.refund_event_time or r.webhook_received_at or current_time
                if ev_time >= cutoff:
                    self._refund_archive_24h[r.refund_id] = r

            if db_path:
                try:
                    with sqlite3.connect(db_path, timeout=5.0) as conn:
                        conn.row_factory = sqlite3.Row
                        try:
                            rows = conn.execute(
                                "SELECT refund_id, order_id, capture_id, payer_id, sku, amount, currency, "
                                "item_name, refund_status, refund_event_time, webhook_received_at, timestamp_resolved "
                                "FROM refund_events WHERE COALESCE(refund_event_time, webhook_received_at, 0) >= ?",
                                (cutoff,),
                            ).fetchall()
                            for row in rows:
                                rid = str(row["refund_id"])
                                if rid not in self._refund_archive_24h:
                                    self._refund_archive_24h[rid] = RefundRecord(
                                        refund_id=rid,
                                        order_id=str(row["order_id"]),
                                        capture_id=str(row["capture_id"]),
                                        payer_id=row["payer_id"],
                                        payer_email=None,
                                        shipping_address_hash=None,
                                        custom_id=None,
                                        sku=row["sku"],
                                        cart_fingerprint=None,
                                        amount=str(row["amount"]),
                                        original_order_amount=str(row["amount"]),
                                        currency=str(row["currency"]),
                                        item_name=str(row["item_name"] or ""),
                                        description="",
                                        refund_status=str(row["refund_status"] or "COMPLETED"),
                                        refund_source="SQLITE_ARCHIVE",
                                        refund_event_time=(
                                            float(row["refund_event_time"])
                                            if row["refund_event_time"] is not None
                                            else None
                                        ),
                                        webhook_received_at=float(
                                            row["webhook_received_at"] or current_time
                                        ),
                                        timestamp_resolved=bool(row["timestamp_resolved"]),
                                    )
                        except sqlite3.OperationalError:
                            pass
                except sqlite3.Error:
                    pass

            self._prune_24h_archive_locked(current_time)

    def ingest_order(self, order: OrderRecord, *, now: Optional[float] = None) -> None:
        current_time = float(now) if now is not None else float(order.timestamp or time.time())
        with self._lock:
            self._order_archive_24h[order.order_id] = order
            self._prune_24h_archive_locked(current_time)

    def ingest_refund(self, refund: RefundRecord, *, now: Optional[float] = None) -> None:
        current_time = float(now) if now is not None else time.time()
        with self._lock:
            self._refund_archive_24h[refund.refund_id] = refund
            self._prune_24h_archive_locked(current_time)

    def is_buyer_auto_hold_enabled(self, payer_id: Optional[str]) -> bool:
        clean_payer = (payer_id or "").strip()
        if not clean_payer:
            return False
        with self._lock:
            return clean_payer in self._auto_hold_buyers

    def set_buyer_auto_hold_policy(
        self, payer_id: str, *, enabled: bool, merchant_note: str = ""
    ) -> Dict[str, Any]:
        clean_payer = (payer_id or "").strip()
        if not clean_payer:
            raise ValueError("payer_id is required")
        with self._lock:
            if enabled:
                self._auto_hold_buyers.add(clean_payer)
            else:
                self._auto_hold_buyers.discard(clean_payer)
            if merchant_note:
                self._acknowledged_buyers[clean_payer] = sanitize_dashboard_summary(merchant_note)[:240]
        return {
            "payer_id": clean_payer,
            "auto_hold_enabled": enabled,
            "merchant_note": self._acknowledged_buyers.get(clean_payer, ""),
        }

    def acknowledge_buyer_alert(self, payer_id: str, *, merchant_note: str = "") -> Dict[str, Any]:
        clean_payer = (payer_id or "").strip()
        if not clean_payer:
            raise ValueError("payer_id is required")
        with self._lock:
            self._acknowledged_buyers[clean_payer] = sanitize_dashboard_summary(merchant_note or "Reviewed by merchant admin")[:240]
        return {
            "payer_id": clean_payer,
            "review_status": "ACKNOWLEDGED",
            "merchant_note": self._acknowledged_buyers[clean_payer],
        }

    def evaluate_buyer_24h_cycle(
        self, payer_id: str, *, now: Optional[float] = None
    ) -> Optional[ChronicRefundCycleAlert]:
        """Evaluate a specific buyer for 3+ buy+refund cycles (including >60m spacing) in 24h."""
        clean_payer = (payer_id or "").strip()
        if not clean_payer:
            return None
        current_time = float(now) if now is not None else time.time()
        self.sync_from_pillars(now=current_time)
        with self._lock:
            return self._evaluate_buyer_locked(clean_payer, current_time)

    def get_all_watchlist_alerts(self, *, now: Optional[float] = None) -> List[ChronicRefundCycleAlert]:
        """Return all buyers meeting the 3+ in 24h chronic refund-loop threshold."""
        current_time = float(now) if now is not None else time.time()
        self.sync_from_pillars(now=current_time)
        alerts: List[ChronicRefundCycleAlert] = []
        with self._lock:
            payer_ids = {
                r.payer_id
                for r in self._refund_archive_24h.values()
                if r.payer_id and r.refund_status == "COMPLETED" and r.timestamp_resolved
            }
            for pid in sorted(payer_ids):
                alert = self._evaluate_buyer_locked(pid, current_time)
                if alert is not None:
                    alerts.append(alert)
        alerts.sort(key=lambda a: (a.completed_refund_count_24h, a.cumulative_fee_bleed_usd), reverse=True)
        return alerts

    def _evaluate_buyer_locked(
        self, payer_id: str, current_time: float
    ) -> Optional[ChronicRefundCycleAlert]:
        cutoff = current_time - self.window_seconds
        buyer_refunds = sorted(
            [
                r
                for r in self._refund_archive_24h.values()
                if r.payer_id == payer_id
                and r.refund_status == "COMPLETED"
                and r.timestamp_resolved
                and r.refund_event_time is not None
                and r.refund_event_time >= cutoff
            ],
            key=lambda r: float(r.refund_event_time or 0.0),
        )
        if len(buyer_refunds) < self.refund_threshold:
            return None

        buyer_orders = sorted(
            [
                o
                for o in self._order_archive_24h.values()
                if o.payer_id == payer_id and o.timestamp >= cutoff
            ],
            key=lambda o: o.timestamp,
        )
        # Even if initial order records were pruned from velocity memory before sync, each
        # distinct order_id on verified refunds proves an order occurred in the 24h window.
        distinct_order_ids = sorted(
            {o.order_id for o in buyer_orders} | {r.order_id for r in buyer_refunds if r.order_id}
        )
        if len(distinct_order_ids) < self.order_threshold:
            return None

        # Calculate spacing gaps between each refund and the subsequent order/refund cycle
        spacing_gaps_min: List[float] = []
        long_gap_count = 0
        for idx, ref in enumerate(buyer_refunds):
            ref_ts = float(ref.refund_event_time or 0.0)
            next_orders = [o for o in buyer_orders if o.timestamp > ref_ts and o.order_id != ref.order_id]
            if next_orders:
                gap_sec = next_orders[0].timestamp - ref_ts
                spacing_gaps_min.append(round(gap_sec / 60.0, 1))
                if gap_sec >= ACUTE_DEADLOCK_WINDOW_SECONDS:
                    long_gap_count += 1
            elif idx + 1 < len(buyer_refunds):
                gap_sec = float(buyer_refunds[idx + 1].refund_event_time or 0.0) - ref_ts
                spacing_gaps_min.append(round(gap_sec / 60.0, 1))
                if gap_sec >= ACUTE_DEADLOCK_WINDOW_SECONDS:
                    long_gap_count += 1

        cumulative_fee = round(
            sum(estimate_paypal_fee_saved_usd(r.amount, r.currency) for r in buyer_refunds),
            2,
        )
        latest_order = buyer_orders[-1] if buyer_orders else None
        primary_sku = (
            (latest_order.sku or latest_order.item_name)
            if latest_order is not None
            else (buyer_refunds[-1].sku or buyer_refunds[-1].item_name or "untagged")
        )
        auto_hold = payer_id in self._auto_hold_buyers
        if auto_hold:
            rev_status = "AUTO_HOLD_ENFORCED"
        elif payer_id in self._acknowledged_buyers:
            rev_status = "ACKNOWLEDGED"
        else:
            rev_status = "FLAGGED_FOR_MERCHANT_REVIEW"

        return ChronicRefundCycleAlert(
            alert_id=f"CHRON-24H-{payer_id}",
            payer_id=payer_id,
            sku_or_item=str(primary_sku or "untagged"),
            window_hours=int(self.window_seconds // 3600),
            completed_refund_count_24h=len(buyer_refunds),
            order_count_24h=len(distinct_order_ids),
            long_gap_rebuy_count_24h=long_gap_count,
            cumulative_fee_bleed_usd=cumulative_fee,
            latest_order_id=latest_order.order_id if latest_order else buyer_refunds[-1].order_id,
            latest_order_status=latest_order.resolution_status if latest_order else "CAPTURED",
            refund_ids_24h=[r.refund_id for r in buyer_refunds],
            order_ids_24h=distinct_order_ids,
            spacing_gaps_minutes=spacing_gaps_min,
            auto_hold_enabled_for_buyer=auto_hold,
            review_status=rev_status,
            merchant_note=self._acknowledged_buyers.get(
                payer_id,
                (
                    f"Buyer completed {len(buyer_refunds)} refund cycles across {len(distinct_order_ids)} orders "
                    f"in 24h ({long_gap_count} spaced >60m apart); est. non-refundable fee bleed ${cumulative_fee:.2f}."
                ),
            ),
            flagged_at=current_time,
        )