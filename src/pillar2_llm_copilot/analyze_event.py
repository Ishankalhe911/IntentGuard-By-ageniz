"""Synchronous P3 callback entrypoint for one checkout event."""
from __future__ import annotations

from functools import lru_cache
from threading import Lock
from typing import Any, Dict, Optional

from .provider_router import ProviderRouter
from .settings import P2Settings


_router_lock = Lock()


def build_default_router(settings: Optional[P2Settings] = None) -> ProviderRouter:
    cfg = settings or P2Settings.from_env()
    cfg.validate_configuration()
    providers: Dict[str, object] = {}
    # Lazy imports keep unit tests and deployments without one SDK importable.
    if cfg.primary_provider == "gemini" or cfg.fallback_provider == "gemini":
        from .providers.gemini_provider import GeminiProvider
        providers["gemini"] = GeminiProvider(api_key=cfg.gemini_api_key or "", model=cfg.gemini_model or "")
    if cfg.primary_provider == "openai" or cfg.fallback_provider == "openai":
        from .providers.openai_provider import OpenAIProvider
        providers["openai"] = OpenAIProvider(api_key=cfg.openai_api_key or "", model=cfg.openai_model or "")
    return ProviderRouter(cfg, providers)


@lru_cache(maxsize=1)
def _cached_default_router() -> ProviderRouter:
    return build_default_router(P2Settings.from_env())


def reset_default_router() -> None:
    """Test/process-management hook for changed environment configuration."""
    with _router_lock:
        _cached_default_router.cache_clear()


def analyze_event(context: Any) -> Dict[str, Any]:
    """Drop-in sync callback for `SettlementClient(llm_triage_callback=analyze_event)`."""
    router = _cached_default_router()
    output = router.analyze(context)
    # Return the exact four-field contract expected by P3. P3 injects fee_saved_usd itself.
    return output.model_dump(mode="json")


def make_triage_callback(*, settings: P2Settings, providers: Dict[str, object]):
    """Dependency-injected callback factory for application wiring and integration tests."""
    router = ProviderRouter(settings, providers)

    def callback(context: Any) -> Dict[str, Any]:
        return router.analyze(context).model_dump(mode="json")

    return callback
