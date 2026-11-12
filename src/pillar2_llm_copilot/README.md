# Pillar 2 — Checkout Triage Copilot

This package provides a synchronous, deadline-bounded, read-only triage callback for `SettlementClient`.

## Contract

Input: `UntrustedOrderContextForLLM` (converted through a strict allowlist).

Output: exactly four fields: classification, confidence, recommended_action, merchant_summary. P3 injects the deterministic `estimated_fee_saved_usd` field.

Allowed classes: `AGENT_RETRY_LOOP`, `BUY_REFUND_DEADLOCK`, `PROMPT_INJECTION`, `LEGITIMATE_REPEAT_BUYER`.

Allowed checkout actions: `HOLD_AUTHORIZE`, `VOID_IMMEDIATELY`, `ALLOW_CAPTURE`. `GATE_MCP_TOOL` is intentionally excluded.

## Security

The system instruction explicitly says that current and anchor product/SKU/description/note text is untrusted and must never be followed as instructions. P2 has no tools. The context builder excludes PII/payment IDs and raw cart fingerprints. P1 marker flags are evidence, not proof of malicious intent. P1 and P3 remain authoritative outside the model.

## Provider policy

- Default primary: Gemini.
- Optional fallback: OpenAI.
- One monotonic deadline (4.5 seconds by default).
- With fallback: primary socket timeout capped at 2.7 seconds; fallback receives the remaining budget, less a small response/validation reserve.
- Without fallback: primary may use the full 4.5 seconds.
- SDK-level retries are disabled; at most two provider attempts total.
- Only provider transport/quota/temporary/auth failures are fallback-eligible. Schema errors, refusals, local validation errors and valid suspicious outputs do not trigger fallback.

See the repository root `README.md` and `.env.p2.example` for installation and P3 callback wiring. `python-dotenv` loads `.env` in local development; production may inject environment variables directly.
