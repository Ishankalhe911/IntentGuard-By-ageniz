"""
Phase 3 (File 1/3): PayPal Sandbox OAuth2 & Orders/Payments v2 REST Client
Location: src/config/paypal_client.py

Complete Audited Implementation (including Round 2 Hardening):
- OAuth2 Client Credentials (`POST /v1/oauth2/token`) against PayPal Sandbox
  (`https://api-m.sandbox.paypal.com`), caching the Bearer token until `expires_in - 60s`
  and auto-refreshing on `HTTP 401`.
- Strict parsed-hostname allow-list URL guard (`urllib.parse.urlparse(resolved_url)` requiring
  `scheme == "https"` and `hostname in SANDBOX_ALLOWED_HOSTS` when `allow_live_paypal=False`,
  preventing substring bypasses like `https://evil.com/sandbox.paypal.com`).
- Distinguishes OAuth2 token-fetch failures (`PayPalAuthError`, raised before any mutating
  order/payment call is sent) from mutating request network/5xx ambiguities (`PayPalAmbiguousNetworkError`).
- Reuses a persistent `httpx.Client` connection pool across calls (with `.close()` and context-manager
  support) and provides `call_async()` via `asyncio.to_thread` so async FastAPI handlers never block
  the event loop.
- Extracts specific PayPal issue codes from `details[0]["issue"]` (such as `CANNOT_MODIFY_INTENT`,
  `AUTHORIZATION_ALREADY_CAPTURED`, `AUTHORIZATION_ALREADY_VOIDED`) onto `PayPalAPIError.issue`.
- Includes `verify_webhook_signature()` (`POST /v1/notifications/verify-webhook-signature`).
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import os
import threading
import time
from typing import Any, Callable, Dict, FrozenSet, List, Optional
from urllib.parse import urlparse

import httpx


DEFAULT_PAYPAL_SANDBOX_BASE_URL = "https://api-m.sandbox.paypal.com"
DEFAULT_HTTP_TIMEOUT_SECONDS = 15.0
TOKEN_EXPIRY_SAFETY_MARGIN_SECONDS = 60.0

SANDBOX_ALLOWED_HOSTS: FrozenSet[str] = frozenset({
    "api-m.sandbox.paypal.com",
    "api.sandbox.paypal.com",
})

LIVE_ALLOWED_HOSTS: FrozenSet[str] = frozenset({
    "api-m.paypal.com",
    "api.paypal.com",
})


class PayPalError(Exception):
    """Base exception for PayPal client errors."""


class PayPalAuthError(PayPalError):
    """
    Raised when OAuth2 token acquisition (`POST /v1/oauth2/token`) fails due to transport
    errors, 5xx responses, or invalid credentials BEFORE any mutating order/payment request
    is transmitted to PayPal.
    """

    def __init__(
        self,
        message: str,
        status_code: Optional[int] = None,
        error_name: Optional[str] = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.error_name = error_name


class PayPalAPIError(PayPalError):
    """
    Deterministic HTTP 4xx / 422 rejection from PayPal.
    Exposes both top-level `error_name` (e.g. `UNPROCESSABLE_ENTITY`) and specific
    `issue` / `issues` extracted from `details[].issue` (e.g. `AUTHORIZATION_ALREADY_VOIDED`).
    """

    def __init__(
        self,
        message: str,
        status_code: int,
        error_name: Optional[str] = None,
        issue: Optional[str] = None,
        issues: Optional[List[str]] = None,
        debug_id: Optional[str] = None,
        details: Optional[Any] = None,
        response_body: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.error_name = error_name
        self.issue = issue
        self.issues = issues or ([issue] if issue else [])
        self.debug_id = debug_id
        self.details = details
        self.response_body = response_body or {}


class PayPalAmbiguousNetworkError(PayPalError):
    """
    Raised when any `httpx.TransportError` (timeout, network drop, or server disconnect
    without a response) or HTTP 5xx / 429 occurs during a mutating PayPal call, leaving
    the remote execution state ambiguous until reconciled.
    """

    def __init__(
        self,
        message: str,
        status_code: Optional[int] = None,
        paypal_request_id: Optional[str] = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.paypal_request_id = paypal_request_id


@dataclass
class CachedOAuthToken:
    access_token: str
    expires_at: float
    scope: str = ""


class PayPalSandboxClient:
    """
    Thread-safe PayPal REST API client with persistent connection pooling, specific
    `details[].issue` extraction, `httpx.TransportError` classification, strict hostname
    validation, `verify_webhook_signature()`, and `call_async()` threadpool offloading.
    """

    def __init__(
        self,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        base_url: Optional[str] = None,
        timeout_seconds: float = DEFAULT_HTTP_TIMEOUT_SECONDS,
        http_client: Optional[httpx.Client] = None,
        allow_live_paypal: bool = False,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.client_id = (client_id or os.getenv("PAYPAL_CLIENT_ID") or "").strip()
        self.client_secret = (client_secret or os.getenv("PAYPAL_CLIENT_SECRET") or "").strip()
        resolved_url = (
            base_url
            or os.getenv("PAYPAL_BASE_URL")
            or DEFAULT_PAYPAL_SANDBOX_BASE_URL
        ).strip().rstrip("/")

        parsed = urlparse(resolved_url)
        hostname = (parsed.hostname or "").lower()
        allowed_hosts = (
            (SANDBOX_ALLOWED_HOSTS | LIVE_ALLOWED_HOSTS)
            if allow_live_paypal
            else SANDBOX_ALLOWED_HOSTS
        )
        if parsed.scheme != "https" or hostname not in allowed_hosts:
            raise ValueError(
                f"PayPal endpoint '{resolved_url}' (hostname='{hostname}') is blocked by URL safety guard. "
                f"Allowed hosts: {sorted(allowed_hosts)} over https."
            )

        self.base_url = resolved_url
        self.timeout_seconds = timeout_seconds
        self.allow_live_paypal = allow_live_paypal
        self._external_client = http_client
        self._managed_client: Optional[httpx.Client] = None
        self._clock = clock
        self._lock = threading.RLock()
        self._cached_token: Optional[CachedOAuthToken] = None

    def _get_http_client(self) -> httpx.Client:
        if self._external_client is not None:
            return self._external_client
        with self._lock:
            if self._managed_client is None or self._managed_client.is_closed:
                self._managed_client = httpx.Client(
                    base_url=self.base_url,
                    timeout=self.timeout_seconds,
                )
            return self._managed_client

    def close(self) -> None:
        with self._lock:
            if self._managed_client is not None and not self._managed_client.is_closed:
                self._managed_client.close()
            self._managed_client = None

    def __enter__(self) -> "PayPalSandboxClient":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    async def call_async(self, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        """Runs a synchronous PayPal client method in a worker thread so async routes never block."""
        return await asyncio.to_thread(fn, *args, **kwargs)

    @staticmethod
    def _extract_issues(details: Any) -> List[str]:
        issues: List[str] = []
        if isinstance(details, list):
            for item in details:
                if isinstance(item, dict) and item.get("issue"):
                    code = str(item["issue"]).strip()
                    if code and code not in issues:
                        issues.append(code)
        return issues

    def get_access_token(self, force_refresh: bool = False) -> str:
        """
        Returns a valid OAuth2 Bearer token, fetching a fresh one from
        `POST /v1/oauth2/token` when missing, expired, or `force_refresh=True`.
        Raises `PayPalAuthError` on OAuth transport/5xx failures so callers know no
        mutating payment request was sent.
        """
        now = self._clock()
        with self._lock:
            if (
                not force_refresh
                and self._cached_token is not None
                and now < (self._cached_token.expires_at - TOKEN_EXPIRY_SAFETY_MARGIN_SECONDS)
            ):
                return self._cached_token.access_token

            if not self.client_id or not self.client_secret:
                raise PayPalAuthError(
                    "PAYPAL_CLIENT_ID and PAYPAL_CLIENT_SECRET are required for OAuth2 authentication.",
                    status_code=401,
                    error_name="MISSING_CREDENTIALS",
                )

            client = self._get_http_client()
            try:
                resp = client.post(
                    f"{self.base_url}/v1/oauth2/token",
                    auth=(self.client_id, self.client_secret),
                    data={"grant_type": "client_credentials"},
                    headers={"Accept": "application/json", "Accept-Language": "en_US"},
                )
            except httpx.TransportError as exc:
                raise PayPalAuthError(
                    f"Transport failure while requesting PayPal OAuth2 token: {exc}",
                    error_name="OAUTH_TRANSPORT_ERROR",
                ) from exc

            if resp.status_code >= 500 or resp.status_code == 429:
                raise PayPalAuthError(
                    f"PayPal OAuth2 endpoint returned transient HTTP {resp.status_code}.",
                    status_code=resp.status_code,
                    error_name="OAUTH_TRANSIENT_HTTP_ERROR",
                )

            body = self._safe_json(resp)
            if resp.status_code >= 400:
                err_code = str(body.get("error") or "OAUTH_FAILED")
                raise PayPalAPIError(
                    f"PayPal OAuth2 authentication failed (HTTP {resp.status_code}): "
                    f"{body.get('error_description') or err_code}",
                    status_code=resp.status_code,
                    error_name=err_code,
                    issue=err_code,
                    response_body=body,
                )

            token = str(body.get("access_token") or "").strip()
            if not token:
                raise PayPalAuthError(
                    "PayPal OAuth2 response did not contain an access_token.",
                    status_code=500,
                    error_name="EMPTY_ACCESS_TOKEN",
                )
            expires_in = float(body.get("expires_in") or 32400.0)
            self._cached_token = CachedOAuthToken(
                access_token=token,
                expires_at=now + expires_in,
                scope=str(body.get("scope") or ""),
            )
            return token

    @staticmethod
    def _safe_json(resp: httpx.Response) -> Dict[str, Any]:
        if not resp.content:
            return {}
        try:
            data = resp.json()
            return data if isinstance(data, dict) else {"data": data}
        except Exception:
            return {"raw_text": resp.text}

    def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: Optional[Dict[str, Any]] = None,
        paypal_request_id: Optional[str] = None,
        prefer_representation: bool = True,
    ) -> Dict[str, Any]:
        url = f"{self.base_url}/{path.lstrip('/')}"
        token = self.get_access_token(force_refresh=False)

        for attempt in range(2):
            headers: Dict[str, str] = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            }
            if prefer_representation:
                headers["Prefer"] = "return=representation"
            if paypal_request_id and paypal_request_id.strip():
                headers["PayPal-Request-Id"] = paypal_request_id.strip()

            client = self._get_http_client()
            try:
                resp = client.request(
                    method=method.upper(),
                    url=url,
                    json=json_body,
                    headers=headers,
                )
            except httpx.TransportError as exc:
                raise PayPalAmbiguousNetworkError(
                    f"Ambiguous transport error on {method.upper()} {path}: {exc}",
                    paypal_request_id=paypal_request_id,
                ) from exc

            if resp.status_code == 401 and attempt == 0:
                token = self.get_access_token(force_refresh=True)
                continue

            if resp.status_code == 204:
                return {"http_status": 204}

            body = self._safe_json(resp)
            if resp.status_code >= 500 or resp.status_code == 429:
                raise PayPalAmbiguousNetworkError(
                    f"PayPal returned transient HTTP {resp.status_code} on {method.upper()} {path}",
                    status_code=resp.status_code,
                    paypal_request_id=paypal_request_id,
                )

            if resp.status_code >= 400:
                top_name = str(body.get("name") or body.get("error") or "PAYPAL_API_ERROR")
                details = body.get("details")
                issues = self._extract_issues(details)
                primary_issue = issues[0] if issues else None
                effective_name = primary_issue or top_name
                debug_id = str(body.get("debug_id") or "") or None
                msg = str(body.get("message") or resp.text or effective_name)
                if primary_issue and primary_issue not in msg:
                    msg = f"{primary_issue}: {msg}"
                raise PayPalAPIError(
                    f"PayPal API error on {method.upper()} {path} (HTTP {resp.status_code} {effective_name}): {msg}",
                    status_code=resp.status_code,
                    error_name=effective_name,
                    issue=primary_issue,
                    issues=issues,
                    debug_id=debug_id,
                    details=details,
                    response_body=body,
                )

            return body

        raise PayPalAPIError(
            f"Unauthorized after token refresh on {method.upper()} {path}",
            status_code=401,
            error_name="UNAUTHORIZED",
            issue="UNAUTHORIZED",
        )

    # ------------------------------------------------------------------
    # Orders v2 Endpoints
    # ------------------------------------------------------------------
    def create_order(
        self,
        order_payload: Dict[str, Any],
        paypal_request_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        return self._request(
            "POST",
            "/v2/checkout/orders",
            json_body=order_payload,
            paypal_request_id=paypal_request_id,
        )

    def get_order(self, order_id: str) -> Dict[str, Any]:
        clean_id = (order_id or "").strip()
        if not clean_id:
            raise ValueError("order_id is required.")
        return self._request("GET", f"/v2/checkout/orders/{clean_id}")

    def authorize_order(
        self,
        order_id: str,
        paypal_request_id: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        clean_id = (order_id or "").strip()
        clean_req_id = (paypal_request_id or "").strip()
        if not clean_id:
            raise ValueError("order_id is required.")
        if not clean_req_id:
            raise ValueError("paypal_request_id is required for authorize_order idempotency.")
        return self._request(
            "POST",
            f"/v2/checkout/orders/{clean_id}/authorize",
            json_body=payload if payload is not None else {},
            paypal_request_id=clean_req_id,
        )

    # ------------------------------------------------------------------
    # Payments v2 Endpoints (Authorizations, Captures, Void, Refund)
    # ------------------------------------------------------------------
    def get_authorization(self, authorization_id: str) -> Dict[str, Any]:
        clean_auth = (authorization_id or "").strip()
        if not clean_auth:
            raise ValueError("authorization_id is required.")
        return self._request("GET", f"/v2/payments/authorizations/{clean_auth}")

    def capture_authorization(
        self,
        authorization_id: str,
        paypal_request_id: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        clean_auth = (authorization_id or "").strip()
        clean_req_id = (paypal_request_id or "").strip()
        if not clean_auth:
            raise ValueError("authorization_id is required.")
        if not clean_req_id:
            raise ValueError("paypal_request_id is required for capture_authorization idempotency.")
        return self._request(
            "POST",
            f"/v2/payments/authorizations/{clean_auth}/capture",
            json_body=payload if payload is not None else {},
            paypal_request_id=clean_req_id,
        )

    def void_authorization(
        self,
        authorization_id: str,
        paypal_request_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        clean_auth = (authorization_id or "").strip()
        if not clean_auth:
            raise ValueError("authorization_id is required.")
        res = self._request(
            "POST",
            f"/v2/payments/authorizations/{clean_auth}/void",
            json_body=None,
            paypal_request_id=paypal_request_id,
            prefer_representation=False,
        )
        return {
            "authorization_id": clean_auth,
            "status": "VOIDED",
            "http_status": res.get("http_status", 204),
        }

    def refund_capture(
        self,
        capture_id: str,
        paypal_request_id: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        clean_cap = (capture_id or "").strip()
        clean_req_id = (paypal_request_id or "").strip()
        if not clean_cap:
            raise ValueError("capture_id is required.")
        if not clean_req_id:
            raise ValueError("paypal_request_id is required for refund_capture idempotency.")
        return self._request(
            "POST",
            f"/v2/payments/captures/{clean_cap}/refund",
            json_body=payload if payload is not None else {},
            paypal_request_id=clean_req_id,
        )

    def get_refund(self, refund_id: str) -> Dict[str, Any]:
        clean_refund = (refund_id or "").strip()
        if not clean_refund:
            raise ValueError("refund_id is required.")
        return self._request("GET", f"/v2/payments/refunds/{clean_refund}")

    def verify_webhook_signature(
        self,
        *,
        auth_algo: str,
        cert_url: str,
        transmission_id: str,
        transmission_sig: str,
        transmission_time: str,
        webhook_id: str,
        webhook_event: Dict[str, Any],
    ) -> bool:
        """
        Verifies an inbound PayPal webhook signature via
        `POST /v1/notifications/verify-webhook-signature`.
        """
        payload = {
            "auth_algo": auth_algo,
            "cert_url": cert_url,
            "transmission_id": transmission_id,
            "transmission_sig": transmission_sig,
            "transmission_time": transmission_time,
            "webhook_id": webhook_id,
            "webhook_event": webhook_event,
        }
        resp = self._request(
            "POST",
            "/v1/notifications/verify-webhook-signature",
            json_body=payload,
            prefer_representation=False,
        )
        return str(resp.get("verification_status") or "").strip().upper() == "SUCCESS"