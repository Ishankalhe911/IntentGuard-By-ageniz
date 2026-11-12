"""Persistent merchant registry, API-key lifecycle, dashboard sessions and request guards.

The registry is intentionally separate from P1-P3 payment decision state. It stores identity,
credential hashes and resource ownership only; it never changes payment/risk decisions.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import HTTPException, Request

MERCHANT_SESSION_COOKIE = "ig_merchant_session"
SESSION_TTL_SECONDS = 8 * 60 * 60


def _key_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _clean(value: Any) -> str:
    return str(value or "").strip()


@dataclass(frozen=True)
class MerchantIdentity:
    merchant_id: str
    merchant_name: str
    status: str = "ACTIVE"


class MerchantSecurityStore:
    """SQLite-backed merchant registry with hashed API keys and short-lived dashboard sessions."""

    def __init__(self, db_path: str) -> None:
        self.db_path = str(db_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._sessions: Dict[str, tuple[str, float]] = {}
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=15.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS ig_merchants (
                    merchant_id TEXT PRIMARY KEY,
                    merchant_name TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'ACTIVE',
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS ig_merchant_api_keys (
                    key_id TEXT PRIMARY KEY,
                    merchant_id TEXT NOT NULL REFERENCES ig_merchants(merchant_id),
                    key_hash TEXT NOT NULL UNIQUE,
                    label TEXT NOT NULL DEFAULT 'primary',
                    created_at REAL NOT NULL,
                    last_used_at REAL,
                    revoked_at REAL
                );
                CREATE INDEX IF NOT EXISTS idx_ig_api_keys_merchant
                    ON ig_merchant_api_keys(merchant_id, revoked_at);
                CREATE TABLE IF NOT EXISTS ig_merchant_sessions (
                    session_hash TEXT PRIMARY KEY,
                    merchant_id TEXT NOT NULL REFERENCES ig_merchants(merchant_id),
                    expires_at REAL NOT NULL,
                    created_at REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_ig_sessions_expiry ON ig_merchant_sessions(expires_at);
                CREATE TABLE IF NOT EXISTS ig_merchant_ws_tickets (
                    ticket_hash TEXT PRIMARY KEY,
                    merchant_id TEXT NOT NULL REFERENCES ig_merchants(merchant_id),
                    expires_at REAL NOT NULL,
                    consumed_at REAL
                );
                CREATE TABLE IF NOT EXISTS ig_merchant_resources (
                    merchant_id TEXT NOT NULL REFERENCES ig_merchants(merchant_id),
                    resource_type TEXT NOT NULL,
                    resource_id TEXT NOT NULL,
                    order_id TEXT,
                    incident_id TEXT,
                    payer_id TEXT,
                    created_at REAL NOT NULL,
                    PRIMARY KEY(resource_type, resource_id)
                );
                CREATE INDEX IF NOT EXISTS idx_ig_resources_merchant
                    ON ig_merchant_resources(merchant_id, resource_type);
                CREATE INDEX IF NOT EXISTS idx_ig_resources_order
                    ON ig_merchant_resources(merchant_id, order_id);
                CREATE INDEX IF NOT EXISTS idx_ig_resources_incident
                    ON ig_merchant_resources(merchant_id, incident_id);
                CREATE INDEX IF NOT EXISTS idx_ig_resources_payer
                    ON ig_merchant_resources(merchant_id, payer_id);
                """
            )
            conn.commit()

    def create_merchant(self, name: str) -> tuple[MerchantIdentity, str]:
        clean_name = _clean(name)
        if not clean_name or len(clean_name) > 120:
            raise ValueError("Merchant name must contain 1-120 characters.")
        merchant_id = "mrc_" + secrets.token_hex(10)
        api_key = "ig_live_" + secrets.token_urlsafe(32)
        now = time.time()
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO ig_merchants (merchant_id, merchant_name, status, created_at, updated_at) VALUES (?, ?, 'ACTIVE', ?, ?)",
                (merchant_id, clean_name, now, now),
            )
            conn.execute(
                "INSERT INTO ig_merchant_api_keys (key_id, merchant_id, key_hash, label, created_at) VALUES (?, ?, ?, 'primary', ?)",
                ("key_" + secrets.token_hex(8), merchant_id, _key_hash(api_key), now),
            )
            conn.commit()
        return MerchantIdentity(merchant_id, clean_name), api_key

    def bootstrap_legacy_merchant(self, api_key: Optional[str], name: str = "Legacy Demo Merchant") -> Optional[str]:
        """Compatibility bridge for existing single-merchant deployments using one env API key."""
        raw = _clean(api_key)
        if not raw:
            return None
        digest = _key_hash(raw)
        with self._connect() as conn:
            row = conn.execute(
                "SELECT m.merchant_id FROM ig_merchant_api_keys k JOIN ig_merchants m USING(merchant_id) "
                "WHERE k.key_hash=? AND k.revoked_at IS NULL AND m.status='ACTIVE'",
                (digest,),
            ).fetchone()
            if row:
                return str(row[0])
            existing = conn.execute("SELECT merchant_id FROM ig_merchants WHERE merchant_id='mrc_legacy_default'").fetchone()
            now = time.time()
            if not existing:
                conn.execute(
                    "INSERT INTO ig_merchants (merchant_id, merchant_name, status, created_at, updated_at) VALUES ('mrc_legacy_default', ?, 'ACTIVE', ?, ?)",
                    (name, now, now),
                )
            conn.execute(
                "INSERT INTO ig_merchant_api_keys (key_id, merchant_id, key_hash, label, created_at) VALUES (?, 'mrc_legacy_default', ?, 'legacy-env', ?)",
                ("key_" + secrets.token_hex(8), digest, now),
            )
            conn.commit()
        return "mrc_legacy_default"

    def authenticate_api_key(self, api_key: Optional[str]) -> Optional[MerchantIdentity]:
        raw = _clean(api_key)
        if not raw:
            return None
        digest = _key_hash(raw)
        with self._connect() as conn:
            row = conn.execute(
                "SELECT m.merchant_id, m.merchant_name, m.status, k.key_hash, k.key_id "
                "FROM ig_merchant_api_keys k JOIN ig_merchants m USING(merchant_id) "
                "WHERE k.key_hash=? AND k.revoked_at IS NULL LIMIT 1",
                (digest,),
            ).fetchone()
            if not row or not hmac.compare_digest(digest, str(row[3])) or row[2] != "ACTIVE":
                return None
            conn.execute("UPDATE ig_merchant_api_keys SET last_used_at=? WHERE key_id=?", (time.time(), row[4]))
            conn.commit()
            return MerchantIdentity(str(row[0]), str(row[1]), str(row[2]))

    def create_session(self, merchant_id: str) -> str:
        token = secrets.token_urlsafe(36)
        now = time.time()
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO ig_merchant_sessions (session_hash, merchant_id, expires_at, created_at) VALUES (?, ?, ?, ?)",
                (_key_hash(token), merchant_id, now + SESSION_TTL_SECONDS, now),
            )
            conn.execute("DELETE FROM ig_merchant_sessions WHERE expires_at <= ?", (now,))
            conn.commit()
        return token

    def resolve_session(self, token: Optional[str]) -> Optional[MerchantIdentity]:
        raw = _clean(token)
        if not raw:
            return None
        now = time.time()
        with self._connect() as conn:
            row = conn.execute(
                "SELECT m.merchant_id, m.merchant_name, m.status FROM ig_merchant_sessions s "
                "JOIN ig_merchants m USING(merchant_id) WHERE s.session_hash=? AND s.expires_at>?",
                (_key_hash(raw), now),
            ).fetchone()
            conn.execute("DELETE FROM ig_merchant_sessions WHERE expires_at <= ?", (now,))
            conn.commit()
        if not row or row[2] != "ACTIVE":
            return None
        return MerchantIdentity(str(row[0]), str(row[1]), str(row[2]))

    def delete_session(self, token: Optional[str]) -> None:
        raw = _clean(token)
        if not raw:
            return
        with self._connect() as conn:
            conn.execute("DELETE FROM ig_merchant_sessions WHERE session_hash=?", (_key_hash(raw),))
            conn.commit()

    def issue_ws_ticket(self, merchant_id: str, ttl_seconds: int = 60) -> str:
        ticket = secrets.token_urlsafe(24)
        now = time.time()
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO ig_merchant_ws_tickets (ticket_hash, merchant_id, expires_at) VALUES (?, ?, ?)",
                (_key_hash(ticket), merchant_id, now + max(10, min(int(ttl_seconds), 120))),
            )
            conn.execute("DELETE FROM ig_merchant_ws_tickets WHERE expires_at <= ? OR consumed_at IS NOT NULL", (now,))
            conn.commit()
        return ticket

    def consume_ws_ticket(self, ticket: Optional[str]) -> Optional[MerchantIdentity]:
        raw = _clean(ticket)
        if not raw:
            return None
        now = time.time()
        with self._connect() as conn:
            # Serialize ticket consumption so concurrent handshakes cannot both reuse it.
            conn.execute("BEGIN IMMEDIATE")
            t_row = conn.execute(
                "SELECT merchant_id FROM ig_merchant_ws_tickets WHERE ticket_hash=? AND expires_at>? AND consumed_at IS NULL",
                (_key_hash(raw), now),
            ).fetchone()
            if not t_row:
                conn.rollback()
                return None
            if str(t_row[0]) == "__admin__":
                row = ("__admin__", "Platform Admin", "ACTIVE")
            else:
                row = conn.execute(
                    "SELECT m.merchant_id, m.merchant_name, m.status FROM ig_merchants m WHERE m.merchant_id=?",
                    (str(t_row[0]),),
                ).fetchone()
            if not row:
                conn.rollback()
                return None
            changed = conn.execute(
                "UPDATE ig_merchant_ws_tickets SET consumed_at=? WHERE ticket_hash=? AND consumed_at IS NULL AND expires_at>?",
                (now, _key_hash(raw), now),
            ).rowcount
            conn.commit()
        if changed != 1 or row[2] != "ACTIVE":
            return None
        return MerchantIdentity(str(row[0]), str(row[1]), str(row[2]))

    def rotate_merchant_key(self, merchant_id: str) -> Optional[str]:
        """Atomically revoke all current merchant keys and issue one replacement."""
        now = time.time()
        api_key = "ig_live_" + secrets.token_urlsafe(32)
        with self._connect() as conn:
            merchant = conn.execute(
                "SELECT status FROM ig_merchants WHERE merchant_id=?", (merchant_id,)
            ).fetchone()
            if not merchant or merchant[0] != "ACTIVE":
                return None
            conn.execute(
                "UPDATE ig_merchant_api_keys SET revoked_at=? WHERE merchant_id=? AND revoked_at IS NULL",
                (now, merchant_id),
            )
            conn.execute("DELETE FROM ig_merchant_sessions WHERE merchant_id=?", (merchant_id,))
            conn.execute(
                "INSERT INTO ig_merchant_api_keys (key_id, merchant_id, key_hash, label, created_at) VALUES (?, ?, ?, 'rotated', ?)",
                ("key_" + secrets.token_hex(8), merchant_id, _key_hash(api_key), now),
            )
            conn.commit()
        return api_key

    def revoke_merchant_keys(self, merchant_id: str) -> int:
        with self._connect() as conn:
            cur = conn.execute(
                "UPDATE ig_merchant_api_keys SET revoked_at=? WHERE merchant_id=? AND revoked_at IS NULL",
                (time.time(), merchant_id),
            )
            conn.execute("DELETE FROM ig_merchant_sessions WHERE merchant_id=?", (merchant_id,))
            conn.commit()
            return int(cur.rowcount)

    def set_merchant_status(self, merchant_id: str, status: str) -> bool:
        target = status.upper()
        if target not in {"ACTIVE", "SUSPENDED"}:
            raise ValueError("Status must be ACTIVE or SUSPENDED.")
        with self._connect() as conn:
            cur = conn.execute(
                "UPDATE ig_merchants SET status=?, updated_at=? WHERE merchant_id=?",
                (target, time.time(), merchant_id),
            )
            if target == "SUSPENDED":
                conn.execute("DELETE FROM ig_merchant_sessions WHERE merchant_id=?", (merchant_id,))
            conn.commit()
            return cur.rowcount > 0

    def active_merchant_count(self) -> int:
        with self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) FROM ig_merchants WHERE status='ACTIVE'").fetchone()
        return int(row[0] or 0)

    def list_merchants(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT m.merchant_id, m.merchant_name, m.status, m.created_at, m.updated_at, "
                "(SELECT COUNT(*) FROM ig_merchant_api_keys k WHERE k.merchant_id=m.merchant_id AND k.revoked_at IS NULL) AS active_key_count "
                "FROM ig_merchants m ORDER BY m.created_at DESC"
            ).fetchall()
        return [dict(row) for row in rows]

    def get_merchant(self, merchant_id: str) -> Optional[dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT merchant_id, merchant_name, status, created_at, updated_at FROM ig_merchants WHERE merchant_id=?",
                (merchant_id,),
            ).fetchone()
        return dict(row) if row else None

    def claim_order(
        self,
        merchant_id: str,
        order_id: str,
        *,
        authorization_id: Optional[str] = None,
        capture_id: Optional[str] = None,
        incident_id: Optional[str] = None,
        payer_id: Optional[str] = None,
    ) -> None:
        order = _clean(order_id)
        if not order:
            return
        now = time.time()
        resources = [("order", order, order)]
        if authorization_id:
            resources.append(("authorization", _clean(authorization_id), order))
        if capture_id:
            resources.append(("capture", _clean(capture_id), order))
        if incident_id:
            # A single P1 incident can span merchants in the current shared engine.
            # Keep the ownership row tenant-scoped; action handlers separately reject
            # bulk operations when the incident contains another merchant's order.
            resources.append(("incident", f"{merchant_id}::{_clean(incident_id)}", order))
        if payer_id:
            # Buyer IDs may legitimately recur across unrelated merchant accounts.
            resources.append(("payer", f"{merchant_id}::{_clean(payer_id)}", order))
        with self._connect() as conn:
            for resource_type, resource_id, order_ref in resources:
                if not resource_id:
                    continue
                row = conn.execute(
                    "SELECT merchant_id FROM ig_merchant_resources WHERE resource_type=? AND resource_id=?",
                    (resource_type, resource_id),
                ).fetchone()
                if row and row[0] != merchant_id:
                    raise PermissionError("Resource is already assigned to another merchant.")
                conn.execute(
                    "INSERT INTO ig_merchant_resources (merchant_id, resource_type, resource_id, order_id, incident_id, payer_id, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(resource_type, resource_id) DO UPDATE SET "
                    "order_id=excluded.order_id, incident_id=COALESCE(excluded.incident_id, ig_merchant_resources.incident_id), "
                    "payer_id=COALESCE(excluded.payer_id, ig_merchant_resources.payer_id)",
                    (merchant_id, resource_type, resource_id, order_ref, incident_id, payer_id, now),
                )
            conn.commit()

    def adopt_unassigned_order_for_sole_merchant(self, merchant_id: str, order_record: Any) -> bool:
        """Compatibility for a single-merchant demo whose orders were seeded outside the SDK.

        It is disabled as soon as a second active merchant exists, preventing cross-tenant adoption.
        """
        if not getattr(order_record, "order_id", None):
            return False
        with self._connect() as conn:
            active_count = conn.execute("SELECT COUNT(*) FROM ig_merchants WHERE status='ACTIVE'").fetchone()[0]
            existing = conn.execute(
                "SELECT merchant_id FROM ig_merchant_resources WHERE resource_type='order' AND resource_id=?",
                (str(order_record.order_id),),
            ).fetchone()
        if int(active_count or 0) != 1 or existing:
            return False
        self.claim_order(
            merchant_id, str(order_record.order_id),
            authorization_id=getattr(order_record, "authorization_id", None),
            capture_id=getattr(order_record, "capture_id", None),
            incident_id=getattr(order_record, "incident_id", None),
            payer_id=getattr(order_record, "payer_id", None),
        )
        return True

    def owns(self, merchant_id: str, resource_type: str, resource_id: str) -> bool:
        normalized_id = f"{merchant_id}::{_clean(resource_id)}" if resource_type in {"payer", "incident"} else _clean(resource_id)
        with self._connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM ig_merchant_resources WHERE merchant_id=? AND resource_type=? AND resource_id=?",
                (merchant_id, resource_type, normalized_id),
            ).fetchone()
        return bool(row)

    def assert_owner(self, merchant_id: str, resource_type: str, resource_id: str) -> None:
        if not self.owns(merchant_id, resource_type, resource_id):
            # 404 avoids confirming another merchant's resource exists.
            raise HTTPException(status_code=404, detail=f"{resource_type.title()} not found.")

    def order_ids(self, merchant_id: str) -> set[str]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT resource_id FROM ig_merchant_resources WHERE merchant_id=? AND resource_type='order'",
                (merchant_id,),
            ).fetchall()
        return {str(row[0]) for row in rows}

    def resource_ids(self, merchant_id: str, resource_type: str) -> set[str]:
        with self._connect() as conn:
            if resource_type == "payer":
                rows = conn.execute(
                    "SELECT DISTINCT payer_id FROM ig_merchant_resources WHERE merchant_id=? AND payer_id IS NOT NULL",
                    (merchant_id,),
                ).fetchall()
            elif resource_type == "incident":
                rows = conn.execute(
                    "SELECT DISTINCT incident_id FROM ig_merchant_resources WHERE merchant_id=? AND incident_id IS NOT NULL",
                    (merchant_id,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT resource_id FROM ig_merchant_resources WHERE merchant_id=? AND resource_type=?",
                    (merchant_id, resource_type),
                ).fetchall()
        return {str(row[0]) for row in rows if row[0]}

    def incident_order_ids(self, merchant_id: str, incident_id: str) -> set[str]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT order_id FROM ig_merchant_resources WHERE merchant_id=? AND resource_type='order' AND incident_id=?",
                (merchant_id, incident_id),
            ).fetchall()
        return {str(row[0]) for row in rows if row[0]}


def configured_admin_key(explicit_key: Optional[str] = None) -> Optional[str]:
    value = explicit_key if explicit_key is not None else (os.getenv("INTENTGUARD_ADMIN_API_KEY") or os.getenv("X_ADMIN_KEY"))
    value = _clean(value)
    return value if value and not value.upper().startswith("YOUR_") else None


def admin_identity(request: Request, x_admin_key: Optional[str] = None) -> bool:
    expected = configured_admin_key(getattr(request.app.state, "admin_api_key", None))
    if not expected:
        raise HTTPException(status_code=503, detail="Admin authentication is not configured.")
    if not x_admin_key or not hmac.compare_digest(x_admin_key.encode(), expected.encode()):
        raise HTTPException(status_code=401 if not x_admin_key else 403, detail="Invalid admin credentials.")
    return True


def merchant_api_identity(request: Request, x_merchant_key: Optional[str] = None) -> MerchantIdentity:
    store: MerchantSecurityStore = request.app.state.merchant_security
    identity = store.authenticate_api_key(x_merchant_key)
    if not identity:
        raise HTTPException(status_code=401, detail="Missing or invalid merchant API key.")
    return identity


def merchant_session_identity(request: Request) -> MerchantIdentity:
    store: MerchantSecurityStore = request.app.state.merchant_security
    identity = store.resolve_session(request.cookies.get(MERCHANT_SESSION_COOKIE))
    if not identity:
        raise HTTPException(status_code=401, detail="Merchant login required.")
    return identity


class TenantSecurityMiddleware:
    """Fail-closed security boundary for protected HTTP routes."""
    def __init__(self, app, *, enforce: bool, admin_key: Optional[str], store: MerchantSecurityStore):
        self.app = app
        self.enforce = enforce
        self.admin_key = admin_key
        self.store = store

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or not self.enforce:
            await self.app(scope, receive, send)
            return
        from starlette.requests import Request as StarletteRequest
        request = StarletteRequest(scope, receive=receive)
        path = request.url.path
        method = request.method.upper()
        merchant_paths = path.startswith("/api/v1/mcp/")
        dashboard_api = path.startswith("/api/v1/dashboard/")
        admin_dashboard_api = path.startswith("/api/v1/admin/")
        is_login = path == "/api/v1/merchant/session" and method == "POST"
        is_logout = path == "/api/v1/merchant/session" and method == "DELETE"
        admin_only_dashboard = any(
            marker in path
            for marker in ("/demo/", "/sandbox/", "/simulator/", "/catalog/", "/reconcile")
        )
        status = None
        detail = None
        headers = {k.decode("latin1").lower(): v.decode("latin1") for k, v in scope.get("headers", [])}
        if admin_dashboard_api or (dashboard_api and admin_only_dashboard):
            expected = configured_admin_key(self.admin_key)
            candidate = headers.get("x-admin-key", "")
            if not expected:
                status, detail = 503, "Admin authentication is not configured."
            elif not candidate:
                status, detail = 401, "Missing X-Admin-Key header."
            elif not hmac.compare_digest(candidate.encode(), expected.encode()):
                status, detail = 403, "Invalid admin credentials."
        elif merchant_paths:
            candidate = headers.get("x-merchant-key", "")
            identity = self.store.authenticate_api_key(candidate)
            if not identity:
                status, detail = 401, "Missing or invalid merchant API key."
            else:
                scope.setdefault("state", {})["merchant_id"] = identity.merchant_id
                scope["state"]["merchant_name"] = identity.merchant_name
        elif dashboard_api and not is_login and not is_logout and not admin_only_dashboard:
            identity = self.store.resolve_session(request.cookies.get(MERCHANT_SESSION_COOKIE))
            if identity:
                scope.setdefault("state", {})["merchant_id"] = identity.merchant_id
                scope["state"]["merchant_name"] = identity.merchant_name
            else:
                expected_admin = configured_admin_key(self.admin_key)
                cand_admin = headers.get("x-admin-key", "").strip()
                if not cand_admin:
                    auth_h = headers.get("authorization", "").strip()
                    if auth_h.lower().startswith("bearer "):
                        cand_admin = auth_h[7:].strip()
                if expected_admin and cand_admin and hmac.compare_digest(cand_admin.encode(), expected_admin.encode()):
                    scope.setdefault("state", {})["is_platform_admin"] = True
                elif cand_admin:
                    status, detail = 403, "Invalid admin credentials."
                else:
                    status, detail = 401, "Merchant login required." 
        elif dashboard_api and (is_login or is_logout):
            # Session establishment is the one dashboard API that accepts an API key.
            pass
        if status:
            from starlette.responses import JSONResponse
            response = JSONResponse({"detail": detail}, status_code=status, headers={"Cache-Control": "no-store"})
            await response(scope, receive, send)
            return
        await self.app(scope, receive, send)


def install_security_middleware(app, *, store: MerchantSecurityStore, admin_key: Optional[str], enforce: bool) -> None:
    app.add_middleware(TenantSecurityMiddleware, enforce=enforce, admin_key=admin_key, store=store)