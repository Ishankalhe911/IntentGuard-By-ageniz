"""Provider error normalization and bounded failover policy."""
from __future__ import annotations
from enum import Enum
from typing import Any


class ProviderErrorKind(str, Enum):
    QUOTA = "QUOTA"
    RATE_LIMIT = "RATE_LIMIT"
    TEMPORARY = "TEMPORARY"
    TIMEOUT = "TIMEOUT"
    AUTH = "AUTH"
    INVALID_REQUEST = "INVALID_REQUEST"
    MALFORMED_OUTPUT = "MALFORMED_OUTPUT"
    REFUSAL = "REFUSAL"
    INTERNAL = "INTERNAL"


FALLBACK_ELIGIBLE = {
    ProviderErrorKind.QUOTA,
    ProviderErrorKind.RATE_LIMIT,
    ProviderErrorKind.TEMPORARY,
    ProviderErrorKind.TIMEOUT,
    ProviderErrorKind.AUTH,
}


class ProviderCallError(RuntimeError):
    def __init__(self, provider: str, kind: ProviderErrorKind, message: str, *, status_code: int | None = None):
        super().__init__(message)
        self.provider = provider
        self.kind = kind
        self.status_code = status_code

    @property
    def fallback_eligible(self) -> bool:
        return self.kind in FALLBACK_ELIGIBLE


class ProviderConfigurationError(ProviderCallError):
    def __init__(self, provider: str, message: str):
        super().__init__(provider, ProviderErrorKind.AUTH, message)


class ProviderOutputError(ProviderCallError):
    def __init__(self, provider: str, message: str, *, refusal: bool = False):
        super().__init__(provider, ProviderErrorKind.REFUSAL if refusal else ProviderErrorKind.MALFORMED_OUTPUT, message)


class ProviderDeadlineExceeded(ProviderCallError):
    def __init__(self, provider: str, message: str = "provider_deadline_exhausted"):
        super().__init__(provider, ProviderErrorKind.TIMEOUT, message)



def classify_provider_exception(provider: str, exc: Exception) -> ProviderCallError:
    """Map known SDK/network failures without retrying arbitrary application/schema errors."""
    name = type(exc).__name__.lower()
    message = str(exc)[:300]
    lower = message.lower()

    status = getattr(exc, "status_code", None) or getattr(exc, "code", None)
    try:
        status_int = int(status) if status is not None else None
    except (TypeError, ValueError):
        status_int = None

    # 1. Timeout
    if "timeout" in name or "timeout" in lower or isinstance(exc, TimeoutError):
        return ProviderCallError(
            provider, ProviderErrorKind.TIMEOUT, message,
            status_code=status_int,
        )

    # 2. Explicit quota exhaustion must precede generic 403 authentication.
    quota_terms = (
        "quota",
        "insufficient_quota",
        "resource_exhausted",
        "billing hard limit",
        "spend cap",
    )
    if any(term in lower for term in quota_terms):
        return ProviderCallError(
            provider, ProviderErrorKind.QUOTA, message,
            status_code=status_int,
        )

    # 3. Rate limiting
    if (
        status_int == 429
        or "rate_limit" in lower
        or "too many requests" in lower
    ):
        return ProviderCallError(
            provider, ProviderErrorKind.RATE_LIMIT, message,
            status_code=status_int or 429,
        )

    # 4. Authentication / permission failures
    if (
        status_int in (401, 403)
        or "authentication" in name
        or "permissiondenied" in lower
        or "api key" in lower
    ):
        return ProviderCallError(
            provider, ProviderErrorKind.AUTH, message,
            status_code=status_int,
        )

    # 5. Invalid requests and schemas
    if (
        status_int in (400, 404, 422)
        or "invalid argument" in lower
        or "invalid schema" in lower
    ):
        return ProviderCallError(
            provider, ProviderErrorKind.INVALID_REQUEST, message,
            status_code=status_int,
        )

    # 6. Temporary provider/network failures
    if (
        status_int in (408, 409, 500, 502, 503, 504)
        or any(x in name for x in ("connectionerror", "apierror"))
    ):
        return ProviderCallError(
            provider, ProviderErrorKind.TEMPORARY, message,
            status_code=status_int,
        )

    return ProviderCallError(
        provider, ProviderErrorKind.INTERNAL, message,
        status_code=status_int,
    )
