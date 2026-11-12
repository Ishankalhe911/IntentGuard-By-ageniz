"""NovaCloud AI & SaaS Merchant Storefront (`demo_store/store_app.py` on port 8001).

Demonstrates a clean separation of concerns:
- Contains zero internal fraud/velocity/LLM code and holds no PayPal or Gemini secrets.
- Communicates with the IntentGuard Firewall (`:8000`) strictly via `IntentGuardMerchantSDK` (`X-Merchant-Key`).
- Supports both catalog products AND fully customizable single/multi-order checkouts (custom SKU, amount,
  quantity, category, variant family, buyer note, buyer identity, shipping address, and `checkout_attempt_id`).
- Also mounts the Interactive Buyer-Side AI Agent Prompt Console at `/agent` (`GET /agent`, `POST /api/agent/parse`,
  `POST /api/agent/execute`, and `POST /api/checkout/settle/{order_id}`) so you can demo Actor 1 (Buyer AI Agent)
  and Actor 2 (NovaCloud Storefront) seamlessly on `:8001`.
"""
from __future__ import annotations

from decimal import Decimal, ROUND_HALF_UP
import os
from pathlib import Path
import threading
from typing import Any, Dict, List, Optional
import uuid

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

try:
    from .buyer_agent import (
        BUYER_AGENT_HTML,
        AgentExecuteRequest,
        AgentPromptParseRequest,
        parse_buyer_prompt_with_optional_gemini,
    )
except ImportError:
    from demo_store.buyer_agent import (
        BUYER_AGENT_HTML,
        AgentExecuteRequest,
        AgentPromptParseRequest,
        parse_buyer_prompt_with_optional_gemini,
    )
from src.sdk.intentguard_sdk import IntentGuardError, IntentGuardMerchantSDK


def _load_dotenv_if_present() -> None:
    for candidate in (Path.cwd() / ".env", Path(__file__).resolve().parents[1] / ".env"):
        if candidate.is_file():
            for raw_line in candidate.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = raw_line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                key = k.strip().lstrip("\ufeff")
                val = v.strip().strip('"').strip("'")
                if key and key not in os.environ:
                    os.environ[key] = val
            break


_load_dotenv_if_present()

PRODUCTS: Dict[str, Dict[str, Optional[str]]] = {
    "SKU-GPU-CREDITS": {
        "name": "Cloud GPU Credits Pack",
        "amount": "5.00",
        "category": None,
        "family_id": None,
        "description": "Stackable compute credits pack (0ms Fast-Path on 1st buy; P2 AI Co-Pilot on repeat).",
    },
    "SKU-PRO-LICENSE": {
        "name": "Single-Seat Pro License",
        "amount": "19.00",
        "category": "single_seat_saas",
        "family_id": None,
        "description": "Non-stackable single-seat SaaS entitlement (P1 policy hard hold for merchant review).",
    },
    "SKU-TEAM-SEAT": {
        "name": "Team Seat Add-On",
        "amount": "7.50",
        "category": None,
        "family_id": None,
        "description": "Team seat expansion (test Buy -> Guarded Refund -> Rebuy Deadlock).",
    },
    "SKU-HARDWARE-TOKEN": {
        "name": "Hardware Security Token (Red)",
        "amount": "12.00",
        "category": None,
        "family_id": "HW-TOKEN-FAMILY",
        "description": "Hardware 2FA key — Red variant (in HW-TOKEN-FAMILY).",
    },
    "SKU-HARDWARE-TOKEN-GREEN": {
        "name": "Hardware Security Token (Green)",
        "amount": "12.00",
        "category": None,
        "family_id": "HW-TOKEN-FAMILY",
        "description": "Hardware 2FA key — Green variant (0ms variant-exchange fast path).",
    },
}


class CheckoutRequest(BaseModel):
    sku: str = Field(..., min_length=1, max_length=120)
    item_name: Optional[str] = None
    amount: Optional[str] = None
    quantity: int = Field(default=1, ge=1, le=1000)
    currency: str = Field(default="USD", min_length=3, max_length=3)
    sku_category: Optional[str] = None
    product_family_id: Optional[str] = None
    buyer_note: Optional[str] = None
    customer_id: Optional[str] = None
    session_id: Optional[str] = None
    checkout_attempt_id: Optional[str] = None
    force_local_sim: bool = False


class SimulateApprovalBody(BaseModel):
    payer_id: str = Field(default="SIM-BUYER-001", min_length=1, max_length=120)
    payer_email: Optional[str] = "simulated-buyer@example.test"
    shipping_address: Optional[Dict[str, str]] = None


class RefundRequest(BaseModel):
    reason: str = Field(default="Buyer requested refund", max_length=300)
    amount: Optional[str] = None
    currency: Optional[str] = None


STOREFRONT_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>NovaCloud — AI & SaaS Products</title>
  <link href="https://fonts.googleapis.com/css2?family=Syne:wght@400;600;700;800&family=Inter:wght@300;400;500;600&display=swap" rel="stylesheet"/>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    :root {
      --bg0: #06040f;
      --bg1: #0d0920;
      --bg2: #110d2b;
      --glass: rgba(255,255,255,0.055);
      --glass-border: rgba(255,255,255,0.10);
      --glass-hover: rgba(255,255,255,0.09);
      --text: #f0eeff;
      --text-2: rgba(240,238,255,0.55);
      --text-3: rgba(240,238,255,0.3);
      --violet: #8b5cf6;
      --violet-bright: #a78bfa;
      --violet-glow: rgba(139,92,246,0.35);
      --cyan: #22d3ee;
      --cyan-glow: rgba(34,211,238,0.2);
      --ok: #34d399;
      --warn: #fbbf24;
      --danger: #f87171;
      --mono: "SF Mono", "Cascadia Code", Consolas, monospace;
      --sans: "Inter", sans-serif;
      --display: "Syne", sans-serif;
      --r: 16px;
      --r-sm: 10px;
    }

    html, body { min-height: 100vh; }

    body {
      font-family: var(--sans);
      background: var(--bg0);
      color: var(--text);
      font-size: 14px;
      line-height: 1.6;
      -webkit-font-smoothing: antialiased;
      overflow-x: hidden;
    }

    /* ── MESH BACKGROUND ── */
    .mesh {
      position: fixed;
      inset: 0;
      z-index: 0;
      pointer-events: none;
      overflow: hidden;
    }
    .mesh-blob {
      position: absolute;
      border-radius: 50%;
      filter: blur(100px);
      opacity: 0.55;
    }
    .mesh-blob-1 { width: 700px; height: 700px; background: radial-gradient(circle, #4c1d95 0%, transparent 70%); top: -200px; left: -200px; }
    .mesh-blob-2 { width: 500px; height: 500px; background: radial-gradient(circle, #0e7490 0%, transparent 70%); top: 10%; right: -100px; }
    .mesh-blob-3 { width: 400px; height: 400px; background: radial-gradient(circle, #5b21b6 0%, transparent 70%); bottom: 20%; left: 30%; }

    /* ── NAV ── */
    nav {
      position: sticky;
      top: 0;
      z-index: 100;
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 0 32px;
      height: 60px;
      background: rgba(6,4,15,0.7);
      backdrop-filter: blur(20px);
      -webkit-backdrop-filter: blur(20px);
      border-bottom: 1px solid var(--glass-border);
    }
    .nav-brand {
      display: flex;
      align-items: center;
      gap: 10px;
      text-decoration: none;
    }
    .brand-mark {
      width: 32px; height: 32px;
      background: linear-gradient(135deg, #7c3aed, #2563eb);
      border-radius: 9px;
      display: grid; place-items: center;
      font-family: var(--display);
      font-weight: 800;
      font-size: 15px;
      color: white;
    }
    .brand-word {
      font-family: var(--display);
      font-weight: 700;
      font-size: 17px;
      color: var(--text);
      letter-spacing: -0.3px;
    }
    .nav-links { display: flex; align-items: center; gap: 6px; }
    .nav-link {
      padding: 7px 14px;
      border-radius: 8px;
      font-size: 13px;
      font-weight: 500;
      color: var(--text-2);
      text-decoration: none;
      border: 1px solid transparent;
      transition: all 0.18s;
    }
    .nav-link:hover { background: var(--glass); border-color: var(--glass-border); color: var(--text); }
    .nav-link.cta {
      background: linear-gradient(135deg, #7c3aed, #2563eb);
      color: white;
      font-weight: 600;
      border: 1px solid rgba(255,255,255,0.15);
    }
    .nav-link.cta:hover { opacity: 0.9; }

    /* ── HERO ── */
    .hero {
      position: relative;
      z-index: 1;
      text-align: center;
      padding: 72px 24px 60px;
    }
    .hero-eyebrow {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      background: var(--glass);
      border: 1px solid var(--glass-border);
      backdrop-filter: blur(12px);
      border-radius: 100px;
      padding: 6px 16px;
      font-size: 12px;
      font-weight: 500;
      color: var(--violet-bright);
      margin-bottom: 24px;
    }
    .hero-eyebrow-dot {
      width: 6px; height: 6px;
      background: var(--violet-bright);
      border-radius: 50%;
      animation: blink 2.5s ease-in-out infinite;
    }
    @keyframes blink { 0%,100%{opacity:1} 50%{opacity:0.3} }
    .hero h1 {
      font-family: var(--display);
      font-size: clamp(32px, 5vw, 52px);
      font-weight: 800;
      line-height: 1.1;
      letter-spacing: -1.5px;
      color: var(--text);
      margin-bottom: 16px;
    }
    .hero h1 span {
      background: linear-gradient(90deg, #a78bfa, #67e8f9);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
    }
    .hero-sub {
      font-size: 16px;
      color: var(--text-2);
      font-weight: 300;
      max-width: 500px;
      margin: 0 auto;
    }

    /* ── MAIN LAYOUT ── */
    .main {
      position: relative;
      z-index: 1;
      max-width: 1200px;
      margin: 0 auto;
      padding: 0 24px 80px;
      display: grid;
      grid-template-columns: 1fr 380px;
      gap: 24px;
      align-items: start;
    }
    @media (max-width: 1000px) { .main { grid-template-columns: 1fr; } }

    /* ── GLASS CARD ── */
    .glass-card {
      background: var(--glass);
      border: 1px solid var(--glass-border);
      border-radius: var(--r);
      backdrop-filter: blur(16px);
      -webkit-backdrop-filter: blur(16px);
      margin-bottom: 20px;
      overflow: hidden;
    }
    .glass-card-header {
      padding: 16px 20px;
      border-bottom: 1px solid var(--glass-border);
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
    .glass-card-title {
      font-family: var(--display);
      font-weight: 600;
      font-size: 14px;
      color: var(--text);
    }
    .glass-card-body { padding: 20px; }

    /* ── PRODUCT GRID ── */
    .prod-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 12px;
    }
    @media (max-width: 600px) { .prod-grid { grid-template-columns: 1fr; } }

    .prod-card {
      background: var(--glass);
      border: 1px solid var(--glass-border);
      border-radius: var(--r-sm);
      padding: 16px;
      cursor: pointer;
      transition: background 0.18s, border-color 0.18s, transform 0.18s;
      position: relative;
      overflow: hidden;
    }
    .prod-card::before {
      content: '';
      position: absolute;
      inset: 0;
      background: linear-gradient(135deg, rgba(139,92,246,0.08) 0%, transparent 60%);
      opacity: 0;
      transition: opacity 0.2s;
    }
    .prod-card:hover { background: var(--glass-hover); transform: translateY(-2px); }
    .prod-card:hover::before { opacity: 1; }
    .prod-card.selected {
      border-color: var(--violet);
      background: rgba(139,92,246,0.12);
    }
    .prod-card.selected::before { opacity: 1; }
    .prod-card-top {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 12px;
    }
    .prod-icon-wrap {
      width: 40px; height: 40px;
      border-radius: 10px;
      display: grid;
      place-items: center;
      font-size: 20px;
    }
    .prod-price {
      font-family: var(--mono);
      font-size: 15px;
      font-weight: 600;
      color: var(--violet-bright);
    }
    .prod-name {
      font-weight: 600;
      font-size: 13.5px;
      color: var(--text);
      margin-bottom: 4px;
      line-height: 1.3;
    }
    .prod-desc {
      font-size: 11.5px;
      color: var(--text-2);
      line-height: 1.5;
    }
    .prod-check {
      position: absolute;
      top: 10px; right: 10px;
      width: 20px; height: 20px;
      background: var(--violet);
      border-radius: 50%;
      display: none;
      place-items: center;
      font-size: 11px;
      color: white;
    }
    .prod-card.selected .prod-check { display: grid; }

    /* ── FORM ── */
    .form-row { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 12px; }
    @media (max-width: 540px) { .form-row { grid-template-columns: 1fr; } }
    .form-group { display: flex; flex-direction: column; gap: 5px; }
    .form-label { font-size: 11.5px; font-weight: 500; color: var(--text-2); }

    input, select, textarea {
      font-family: var(--sans);
      background: rgba(255,255,255,0.05);
      color: var(--text);
      border: 1px solid var(--glass-border);
      border-radius: 8px;
      padding: 9px 12px;
      font-size: 13px;
      outline: none;
      transition: border-color 0.15s, background 0.15s;
      width: 100%;
    }
    input:focus, select:focus, textarea:focus {
      border-color: var(--violet);
      background: rgba(139,92,246,0.08);
    }
    input::placeholder { color: var(--text-3); }
    select { cursor: pointer; }
    select option { background: #1a1030; }

    /* ── BUTTONS ── */
    .btn {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 7px;
      padding: 10px 18px;
      border-radius: 9px;
      font-family: var(--sans);
      font-size: 13.5px;
      font-weight: 600;
      cursor: pointer;
      border: 1px solid transparent;
      transition: all 0.18s;
      white-space: nowrap;
      line-height: 1;
    }
    .btn-primary {
      background: linear-gradient(135deg, #7c3aed, #2563eb);
      color: white;
      border-color: rgba(255,255,255,0.15);
      box-shadow: 0 4px 20px rgba(124,58,237,0.35);
    }
    .btn-primary:hover { opacity: 0.88; transform: translateY(-1px); box-shadow: 0 6px 24px rgba(124,58,237,0.45); }
    .btn-glass {
      background: var(--glass);
      color: var(--text-2);
      border-color: var(--glass-border);
    }
    .btn-glass:hover { background: var(--glass-hover); color: var(--text); }
    .btn-danger-glass {
      background: rgba(248,113,113,0.1);
      color: var(--danger);
      border-color: rgba(248,113,113,0.25);
    }
    .btn-danger-glass:hover { background: rgba(248,113,113,0.18); }
    .btn-sm { padding: 7px 13px; font-size: 12px; }
    .btn-row { display: flex; gap: 8px; flex-wrap: wrap; }

    /* ── STATUS BADGE ── */
    .badge {
      display: inline-flex;
      align-items: center;
      gap: 5px;
      padding: 3px 10px;
      border-radius: 100px;
      font-size: 11px;
      font-weight: 600;
    }
    .badge-ok { background: rgba(52,211,153,0.12); color: var(--ok); border: 1px solid rgba(52,211,153,0.25); }
    .badge-warn { background: rgba(251,191,36,0.12); color: var(--warn); border: 1px solid rgba(251,191,36,0.25); }
    .badge-danger { background: rgba(248,113,113,0.12); color: var(--danger); border: 1px solid rgba(248,113,113,0.25); }
    .badge-info { background: rgba(167,139,250,0.12); color: var(--violet-bright); border: 1px solid rgba(167,139,250,0.25); }

    /* ── ORDER PANEL ── */
    .order-row { display: flex; gap: 8px; margin-bottom: 12px; }
    .order-row input { flex: 1; }

    /* ── OUTPUT BOX ── */
    .output-box {
      background: rgba(0,0,0,0.4);
      border: 1px solid rgba(255,255,255,0.07);
      border-radius: 10px;
      padding: 14px;
      font-family: var(--mono);
      font-size: 11px;
      line-height: 1.7;
      color: rgba(240,238,255,0.5);
      overflow-x: auto;
      white-space: pre-wrap;
      word-break: break-word;
      min-height: 70px;
      max-height: 300px;
      overflow-y: auto;
    }

    /* ── APPROVAL ── */
    .approval-wrap { margin-bottom: 14px; }
    .approval-inner {
      background: rgba(251,191,36,0.07);
      border: 1px solid rgba(251,191,36,0.25);
      border-radius: 10px;
      padding: 14px 16px;
    }
    .approval-title { font-weight: 600; font-size: 13px; color: var(--warn); margin-bottom: 8px; }
    .approval-btn {
      display: inline-flex; align-items: center; gap: 7px;
      background: rgba(251,191,36,0.15);
      border: 1px solid rgba(251,191,36,0.4);
      color: var(--warn);
      padding: 8px 15px; border-radius: 8px;
      font-size: 13px; font-weight: 600;
      text-decoration: none; margin-top: 10px;
    }
    .approval-btn:hover { background: rgba(251,191,36,0.22); }

    /* ── FOOTER ── */
    footer {
      position: relative; z-index: 1;
      border-top: 1px solid var(--glass-border);
      padding: 20px 32px;
      text-align: center;
      font-size: 12px;
      color: var(--text-3);
      background: rgba(6,4,15,0.6);
      backdrop-filter: blur(12px);
    }
    .shield-pill {
      display: inline-flex; align-items: center; gap: 7px;
      background: var(--glass);
      border: 1px solid var(--glass-border);
      border-radius: 100px;
      padding: 5px 14px;
      color: var(--text-2);
    }
    .shield-dot { width: 7px; height: 7px; border-radius: 50%; background: var(--ok); }
  </style>
</head>
<body>

<!-- Mesh background -->
<div class="mesh">
  <div class="mesh-blob mesh-blob-1"></div>
  <div class="mesh-blob mesh-blob-2"></div>
  <div class="mesh-blob mesh-blob-3"></div>
</div>

<!-- NAV -->
<nav>
  <a class="nav-brand" href="/">
    <div class="brand-mark">N</div>
    <span class="brand-word">NovaCloud</span>
  </a>
  <div class="nav-links">
    <a class="nav-link" href="/agent" target="_blank">AI Agent Console</a>
    <a class="nav-link cta" href="https://intentguard-by-ageniz-v37n.onrender.com/" target="_blank">Merchant Dashboard</a>
  </div>
</nav>

<!-- HERO -->
<div class="hero">
  <div class="hero-eyebrow">
    <span class="hero-eyebrow-dot"></span>
    Cloud infrastructure, delivered instantly
  </div>
  <h1>AI & SaaS<br><span>Products for Builders</span></h1>
  <p class="hero-sub">GPU credits, software licenses, and hardware security — protected by PayPal Agentic Shield.</p>
</div>

<!-- MAIN -->
<div class="main">
  <div>
    <!-- Products -->
    <div class="glass-card">
      <div class="glass-card-header">
        <span class="glass-card-title">Products</span>
        <span id="order-status-badge" class="badge badge-info">Nothing selected</span>
      </div>
      <div class="glass-card-body">
        <div class="prod-grid" id="catalog-cards"></div>
      </div>
    </div>

    <!-- Custom checkout -->
    <div class="glass-card">
      <div class="glass-card-header">
        <span class="glass-card-title">Checkout</span>
      </div>
      <div class="glass-card-body">
        <div class="form-row">
          <div class="form-group">
            <label class="form-label">SKU</label>
            <input id="f-sku" value="SKU-GPU-CREDITS"/>
          </div>
          <div class="form-group">
            <label class="form-label">Item Name</label>
            <input id="f-name" value="Cloud GPU Credits Pack"/>
          </div>
        </div>
        <div class="form-row">
          <div class="form-group">
            <label class="form-label">Unit Price (USD)</label>
            <input id="f-amount" value="5.00"/>
          </div>
          <div class="form-group">
            <label class="form-label">Quantity</label>
            <input id="f-qty" type="number" min="1" value="1"/>
          </div>
        </div>
        <div class="form-row">
          <div class="form-group">
            <label class="form-label">License Policy</label>
            <select id="f-category">
              <option value="">Stackable (Default)</option>
              <option value="single_seat_saas">Single-Seat SaaS</option>
              <option value="non_stackable_entitlement">Non-Stackable</option>
            </select>
          </div>
          <div class="form-group">
            <label class="form-label">Variant Family</label>
            <input id="f-family" placeholder="e.g. HW-TOKEN-FAMILY"/>
          </div>
        </div>
        <div class="form-row">
          <div class="form-group">
            <label class="form-label">Buyer ID (Simulation)</label>
            <input id="f-payer" value="BUYER-DEMO-001"/>
          </div>
          <div class="form-group">
            <label class="form-label">Attempt ID</label>
            <input id="f-attempt" placeholder="Auto-generated"/>
          </div>
        </div>
        <div class="form-group" style="margin-bottom:18px;">
          <label class="form-label">Buyer Note (Optional)</label>
          <input id="f-note" placeholder="e.g. For our staging cluster"/>
        </div>
        <div class="btn-row">
          <button class="btn btn-primary" onclick="startPayPalCheckout(false)">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><rect x="1" y="4" width="22" height="16" rx="2"/><line x1="1" y1="10" x2="23" y2="10"/></svg>
            Checkout via PayPal
          </button>
          <button class="btn btn-glass" onclick="startPayPalCheckout(true)">Quick Simulation</button>
          <button class="btn btn-glass btn-sm" onclick="generateNewAttemptId()">New Attempt ID</button>
        </div>
      </div>
    </div>
  </div>

  <!-- RIGHT: Order status -->
  <div>
    <div class="glass-card">
      <div class="glass-card-header">
        <span class="glass-card-title">Order Status</span>
      </div>
      <div class="glass-card-body">
        <div id="approval-wrap" class="approval-wrap"></div>
        <div class="order-row">
          <input id="active-order-id" placeholder="Order ID"/>
        </div>
        <div class="btn-row" style="margin-bottom:16px;">
          <button class="btn btn-glass btn-sm" onclick="settleApprovedOrder()">Settle</button>
          <button class="btn btn-glass btn-sm" onclick="pollOrderStatus()">Refresh</button>
          <button class="btn btn-danger-glass btn-sm" onclick="refundActiveOrder()">Refund</button>
        </div>
        <div class="output-box" id="output-box">Select a product to begin.</div>
      </div>
    </div>
  </div>
</div>

<!-- FOOTER -->
<footer>
  <div class="shield-pill">
    <span class="shield-dot"></span>
    Payments protected by PayPal Agentic Shield — real-time firewall for autonomous buyers
  </div>
</footer>

<script>
  const CATALOG = __CATALOG_JSON__;

  const PROD_META = {
    'SKU-GPU-CREDITS':        { icon: '⚡', bg: 'rgba(99,102,241,0.18)' },
    'SKU-PRO-LICENSE':        { icon: '🔑', bg: 'rgba(16,185,129,0.15)' },
    'SKU-TEAM-SEAT':          { icon: '👥', bg: 'rgba(139,92,246,0.18)' },
    'SKU-HARDWARE-TOKEN':     { icon: '🔴', bg: 'rgba(239,68,68,0.15)'  },
    'SKU-HARDWARE-TOKEN-GREEN':{ icon: '🟢', bg: 'rgba(16,185,129,0.15)' },
  };

  function esc(s) {
    return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }

  function selectProduct(sku) {
    const p = CATALOG[sku]; if (!p) return;
    document.getElementById('f-sku').value = sku;
    document.getElementById('f-name').value = p.name;
    document.getElementById('f-amount').value = p.amount;
    document.getElementById('f-category').value = p.category||'';
    document.getElementById('f-family').value = p.family_id||'';
    document.querySelectorAll('.prod-card').forEach(el=>el.classList.toggle('selected', el.dataset.sku===sku));
    document.getElementById('order-status-badge').textContent = p.name;
    document.getElementById('order-status-badge').className = 'badge badge-info';
  }

  function renderCatalog() {
    const box = document.getElementById('catalog-cards');
    box.innerHTML = Object.entries(CATALOG).map(([sku,p])=>{
      const m = PROD_META[sku]||{icon:'📦',bg:'rgba(255,255,255,0.08)'};
      const desc = (p.description||'').replace(/ \(.*?\)/g,'').replace(/\. P[12] .+/g,'.').replace(/P1 policy .+/g,'').trim();
      return `
      <div class="prod-card" data-sku="${esc(sku)}" onclick="selectProduct('${esc(sku)}')">
        <div class="prod-check">✓</div>
        <div class="prod-card-top">
          <div class="prod-icon-wrap" style="background:${m.bg}">${m.icon}</div>
          <div class="prod-price">$${p.amount}</div>
        </div>
        <div class="prod-name">${esc(p.name)}</div>
        <div class="prod-desc">${esc(desc)}</div>
      </div>`;
    }).join('');
    selectProduct('SKU-GPU-CREDITS');
  }

  function generateNewAttemptId() {
    document.getElementById('f-attempt').value='chk-'+Math.random().toString(16).slice(2,10)+'-'+Date.now();
  }

  function setBadge(text, type) {
    const b=document.getElementById('order-status-badge');
    b.textContent=text; b.className='badge badge-'+type;
  }

  async function startPayPalCheckout(localSim) {
    setBadge('Creating order…','info');
    const body={
      sku: document.getElementById('f-sku').value.trim(),
      item_name: document.getElementById('f-name').value.trim()||null,
      amount: document.getElementById('f-amount').value.trim()||null,
      quantity: parseInt(document.getElementById('f-qty').value||'1',10),
      sku_category: document.getElementById('f-category').value||null,
      product_family_id: document.getElementById('f-family').value.trim()||null,
      buyer_note: document.getElementById('f-note').value.trim()||null,
      customer_id: document.getElementById('f-payer').value.trim()||null,
      checkout_attempt_id: document.getElementById('f-attempt').value.trim()||null,
      force_local_sim: localSim,
    };
    const r=await fetch('/api/checkout',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    const d=await r.json();
    document.getElementById('output-box').textContent=JSON.stringify(d,null,2);
    if(!r.ok){setBadge('Error','danger');return;}
    const oid=d.order_id;
    document.getElementById('active-order-id').value=oid;
    if(localSim){
      const sim=await fetch('/api/checkout/simulate-approval/'+encodeURIComponent(oid),{
        method:'POST',headers:{'Content-Type':'application/json'},
        body:JSON.stringify({payer_id:document.getElementById('f-payer').value.trim(),payer_email:document.getElementById('f-payer').value.trim().toLowerCase()+'@example.test'}),
      });
      const sd=await sim.json();
      document.getElementById('output-box').textContent=JSON.stringify(sd,null,2);
      const fs=(sd.settlement||sd).final_status||'SETTLED';
      setBadge(fs, fs==='CAPTURED'?'ok':'warn');
      document.getElementById('approval-wrap').innerHTML='';
    } else if(d.approval_url){
      setBadge('Awaiting PayPal','warn');
      document.getElementById('approval-wrap').innerHTML=`
        <div class="approval-inner">
          <div class="approval-title">Complete payment on PayPal Sandbox</div>
          <div style="font-size:12.5px;color:var(--text-2);">Order <strong style="color:var(--text)">${esc(oid)}</strong> is ready. Approve it on PayPal, then click <strong style="color:var(--text)">Settle</strong>.</div>
          <a class="approval-btn" href="${esc(d.approval_url)}" target="_blank">Approve on PayPal Sandbox ↗</a>
        </div>`;
    }
  }

  async function settleApprovedOrder(){
    const oid=document.getElementById('active-order-id').value.trim(); if(!oid)return;
    setBadge('Settling…','info');
    const r=await fetch('/api/checkout/settle/'+encodeURIComponent(oid),{method:'POST'});
    const d=await r.json();
    document.getElementById('output-box').textContent=JSON.stringify(d,null,2);
    const fs=d.final_status||'SETTLED';
    setBadge(fs,fs==='CAPTURED'?'ok':'warn');
    document.getElementById('approval-wrap').innerHTML='';
  }

  async function pollOrderStatus(){
    const oid=document.getElementById('active-order-id').value.trim(); if(!oid)return;
    const r=await fetch('/api/orders/'+encodeURIComponent(oid));
    const d=await r.json();
    document.getElementById('output-box').textContent=JSON.stringify(d,null,2);
  }

  async function refundActiveOrder(){
    const oid=document.getElementById('active-order-id').value.trim(); if(!oid)return;
    setBadge('Refunding…','warn');
    const r=await fetch('/api/orders/'+encodeURIComponent(oid)+'/refund',{
      method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({reason:'Buyer requested refund'}),
    });
    const d=await r.json();
    document.getElementById('output-box').textContent=JSON.stringify(d,null,2);
    setBadge('Refund '+(d.status||'done'),d.status==='SUCCEEDED'?'ok':'warn');
  }

  renderCatalog();
</script>
</body>
</html>
"""


def create_store_app(sdk: Optional[IntentGuardMerchantSDK] = None) -> FastAPI:
    if sdk is None:
        sdk = IntentGuardMerchantSDK(
            os.getenv("INTENTGUARD_URL", "https://intentguard-by-ageniz-v37n.onrender.com/"),
            os.getenv("INTENTGUARD_MERCHANT_API_KEY"),
        )
    app = FastAPI(title="NovaCloud Merchant Store", version="0.3.0")
    app.state.intentguard = sdk
    app.state.pending_checkout_metadata: Dict[str, Dict[str, Any]] = {}
    app.state.settle_locks: Dict[str, threading.Lock] = {}

    @app.get("/", response_class=HTMLResponse)
    def storefront() -> HTMLResponse:
        import json as _json
        rendered = STOREFRONT_HTML.replace("__CATALOG_JSON__", _json.dumps(PRODUCTS))
        return HTMLResponse(rendered)

    @app.get("/agent", response_class=HTMLResponse)
    def buyer_agent_console() -> HTMLResponse:
        """Serves the Interactive Buyer-Side AI Agent Prompt Console on /agent."""
        return HTMLResponse(BUYER_AGENT_HTML.replace("__STORE_BASE_URL__", ""))

    @app.get("/.well-known/mcp.json")
    def mcp_discovery_manifest(request: Request) -> Dict[str, Any]:
        base = str(request.base_url).rstrip("/")
        return {
            "schema_version": "1.0",
            "store_id": "novacloud-ai-saas-store",
            "store_name": "NovaCloud AI & SaaS Merchant Storefront",
            "firewall_protected": True,
            "payment_rail": "PayPal Orders v2 (IntentGuard AUTHORIZE Circuit Breaker)",
            "catalog_endpoint": f"{base}/api/catalog",
            "tools": [
                {"name": "list_catalog", "method": "GET", "endpoint": f"{base}/api/catalog"},
                {"name": "create_checkout", "method": "POST", "endpoint": f"{base}/api/checkout"},
                {"name": "get_order_gate_status", "method": "GET", "endpoint": f"{base}/api/orders/{{order_id}}"},
                {"name": "refund_order", "method": "POST", "endpoint": f"{base}/api/orders/{{order_id}}/refund"},
            ],
        }

    @app.get("/api/catalog")
    def catalog() -> Dict[str, Any]:
        return {"products": [{"sku": sku, **product} for sku, product in PRODUCTS.items()]}

    def _create_checkout_internal(body: CheckoutRequest, base_url: str) -> Dict[str, Any]:
        clean_sku = body.sku.strip()
        catalog_entry = PRODUCTS.get(clean_sku)
        if catalog_entry is None:
            raise HTTPException(
                status_code=404,
                detail=f"Unknown SKU '{clean_sku}'. NovaCloud Storefront only sells catalog SKUs: {', '.join(PRODUCTS.keys())}",
            )

        unit_amount_str = str(body.amount if (body.amount and str(body.amount).strip()) else catalog_entry["amount"]).strip()
        item_name = str(body.item_name if (body.item_name and str(body.item_name).strip()) else (catalog_entry["name"] if catalog_entry else clean_sku)).strip()
        currency = (body.currency or "USD").strip().upper()
        qty = int(body.quantity or 1)
        unit_dec = Decimal(unit_amount_str).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
        total_str = str((unit_dec * Decimal(qty)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))
        unit_norm_str = str(unit_dec)

        eff_category = body.sku_category or (catalog_entry.get("category") if catalog_entry else None)
        eff_family = body.product_family_id or (catalog_entry.get("family_id") if catalog_entry else None)

        if eff_category and eff_category != "untagged":
            try:
                sdk.register_sku_category(sku=clean_sku, category=eff_category)
            except Exception:
                pass
        if eff_family:
            try:
                sdk.register_sku_family(sku=clean_sku, family_id=eff_family)
            except Exception:
                pass

        attempt_id = (body.checkout_attempt_id or str(uuid.uuid4())).strip()
        base = base_url.rstrip("/")
        payload: Dict[str, Any] = {
            "intent": "CAPTURE",
            "purchase_units": [
                {
                    "invoice_id": f"NC-{attempt_id[:24]}",
                    "amount": {
                        "currency_code": currency,
                        "value": total_str,
                        "breakdown": {"item_total": {"currency_code": currency, "value": total_str}},
                    },
                    "items": [
                        {
                            "name": item_name,
                            "sku": clean_sku,
                            "quantity": str(qty),
                            "unit_amount": {"currency_code": currency, "value": unit_norm_str},
                        }
                    ],
                    "description": item_name,
                }
            ],
            "application_context": {
                "return_url": f"{base}/checkout/return",
                "cancel_url": f"{base}/checkout/cancel",
            },
        }
        if body.force_local_sim:
            payload["_force_local_sim"] = True

        try:
            result = sdk.create_order(order_payload=payload, checkout_attempt_id=attempt_id)
        except IntentGuardError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc

        oid = result["order_id"]
        app.state.pending_checkout_metadata[oid] = {
            "sku": clean_sku,
            "item_name": item_name,
            "amount": total_str,
            "currency": currency,
            "buyer_note": body.buyer_note,
            "customer_id": body.customer_id,
            "session_id": body.session_id,
            "product_family_id": eff_family,
        }
        paypal = result.get("paypal_response") or {}
        approval_url = next(
            (
                l.get("href")
                for l in (paypal.get("links") or [])
                if str(l.get("rel", "")).lower() in {"approve", "payer-action"}
            ),
            None,
        )
        return {
            "order_id": oid,
            "checkout_attempt_id": attempt_id,
            "sku": clean_sku,
            "item_name": item_name,
            "amount": total_str,
            "currency": currency,
            "rewritten_intent": result.get("rewritten_intent"),
            "approval_url": approval_url,
            "status": "AWAITING_BUYER_APPROVAL",
        }

    @app.post("/api/checkout")
    def checkout(body: CheckoutRequest, request: Request) -> Dict[str, Any]:
        return _create_checkout_internal(body, str(request.base_url))

    @app.post("/api/checkout/simulate-approval/{order_id}")
    def simulate_buyer_approval(order_id: str, body: Optional[SimulateApprovalBody] = None) -> Dict[str, Any]:
        """Simulates buyer approval and settles the order when the firewall runs in local_simulation mode."""
        req_body = body or SimulateApprovalBody()
        meta = app.state.pending_checkout_metadata.get(order_id, {})
        eff_payer_id = (req_body.payer_id or meta.get("customer_id") or "SIM-BUYER-001").strip()
        eff_email = req_body.payer_email or f"{eff_payer_id.lower()}@example.test"
        try:
            approved = sdk.simulate_buyer_approval(
                order_id=order_id,
                payer_id=eff_payer_id,
                payer_email=eff_email,
                shipping_address=req_body.shipping_address,
            )
            settled = sdk.settle_order(
                order_id=order_id,
                note_to_payer=meta.get("buyer_note"),
                product_family_id=meta.get("product_family_id"),
                customer_id=meta.get("customer_id") or eff_payer_id,
                session_id=meta.get("session_id"),
            )
            return {"buyer_approval": approved, "settlement": settled}
        except IntentGuardError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc

    def _settle_order_once(order_id: str) -> Dict[str, Any]:
        clean_oid = (order_id or "").strip()
        lock = app.state.settle_locks.setdefault(clean_oid, threading.Lock())
        with lock:
            try:
                existing = sdk.get_gate_status(order_id=clean_oid)
                if existing.get("resolution_status") in {"CAPTURED", "AUTHORIZED_HOLD", "VOIDED", "REFUNDED"}:
                    return {
                        "order_id": clean_oid,
                        "final_status": existing.get("resolution_status"),
                        "decision_mode": "SETTLED_VIA_PAYPAL_RETURN",
                        "merchant_summary": existing.get("agent_directive"),
                        "authorization_id": existing.get("authorization_id"),
                        "capture_id": existing.get("capture_id"),
                        "mcp_gate": existing,
                    }
            except IntentGuardError:
                pass
            meta = app.state.pending_checkout_metadata.get(clean_oid, {})
            return sdk.settle_order(
                order_id=clean_oid,
                note_to_payer=meta.get("buyer_note"),
                product_family_id=meta.get("product_family_id"),
                customer_id=meta.get("customer_id"),
                session_id=meta.get("session_id"),
            )

    @app.post("/api/checkout/settle/{order_id}")
    def settle_approved_order_direct(order_id: str) -> Dict[str, Any]:
        """Settles an APPROVED PayPal Sandbox order directly (e.g. from the Buyer Agent Console)."""
        try:
            return _settle_order_once(order_id)
        except IntentGuardError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc

    @app.get("/checkout/return")
    def checkout_return(token: str, PayerID: Optional[str] = None) -> Dict[str, Any]:
        try:
            return _settle_order_once(token)
        except IntentGuardError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc

    @app.get("/checkout/cancel")
    def checkout_cancel() -> Dict[str, str]:
        return {"status": "BUYER_CANCELLED"}

    @app.get("/api/orders/{order_id}")
    def order_status(order_id: str) -> Dict[str, Any]:
        try:
            return sdk.get_gate_status(order_id=order_id)
        except IntentGuardError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc

    @app.post("/api/orders/{order_id}/refund")
    def refund(order_id: str, body: RefundRequest) -> Dict[str, Any]:
        try:
            return sdk.refund_order(
                order_id=order_id,
                reason=body.reason,
                amount=body.amount,
                currency=body.currency,
            )
        except IntentGuardError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc

    @app.post("/api/agent/parse")
    def agent_parse_prompt(body: AgentPromptParseRequest) -> Dict[str, Any]:
        discovered = [{"sku": sku, **product} for sku, product in PRODUCTS.items()]
        return parse_buyer_prompt_with_optional_gemini(
            body.prompt,
            gemini_api_key=body.gemini_api_key,
            discovered_catalog=discovered,
        )

    @app.post("/api/agent/execute")
    def agent_execute_plan(body: AgentExecuteRequest, request: Request) -> Dict[str, Any]:
        """Executes a Buyer Agent plan directly against the storefront's internal checkout/refund handlers."""
        trace: List[Dict[str, str]] = []
        outputs: List[Dict[str, Any]] = []
        active_order_id: Optional[str] = None
        approval_url: Optional[str] = None
        awaiting_paypal = False
        is_local_sim = body.execution_mode.strip().lower() in {"local_sim", "local_simulation", "sim"}
        base_url = str(request.base_url)

        if body.action.strip().upper() == "REJECT_OFF_CATALOG" or not body.sku or not str(body.sku).strip():
            return {
                "execution_mode": body.execution_mode,
                "active_order_id": None,
                "approval_url": None,
                "awaiting_paypal_approval": False,
                "trace": [{
                    "title": f"AGENT BLOCKED OFF-CATALOG ITEM: {body.sku}",
                    "detail": f"Item '{body.item_name or body.sku}' is not in NovaCloud Storefront's discovered /api/catalog.",
                    "tone": "danger",
                }],
                "results": [],
            }

        if body.refund_order_id and body.refund_order_id.strip():
            ref_oid = body.refund_order_id.strip()
            try:
                ref_data = sdk.refund_order(order_id=ref_oid, reason="Buyer AI Agent requested refund before rebuy")
                outputs.append({"step": "refund", "order_id": ref_oid, "response": ref_data})
                trace.append({
                    "title": f"REFUND EXECUTED ON {ref_oid} -> {ref_data.get('status')}",
                    "detail": f"PayPal Refund ID: {ref_data.get('paypal_refund_id') or 'N/A'} | 60m Buy-Refund Deadlock Detector armed.",
                    "tone": "ok" if ref_data.get("status") == "SUCCEEDED" else "danger",
                })
            except IntentGuardError as exc:
                trace.append({
                    "title": f"REFUND ERROR ON {ref_oid} ({exc.status_code})",
                    "detail": str(exc.detail),
                    "tone": "danger",
                })

        shared_attempt = (body.checkout_attempt_id or "").strip() or f"agent-{uuid.uuid4().hex[:10]}"
        total_orders = 1 if (not is_local_sim and body.count > 1) else max(1, body.count)

        for idx in range(1, total_orders + 1):
            attempt_id = (
                shared_attempt
                if (body.reuse_attempt_id or (idx == 1 and body.checkout_attempt_id))
                else f"agent-{idx}-{uuid.uuid4().hex[:10]}"
            )
            eff_note = body.buyer_note
            if total_orders > 1 and idx > 1 and not eff_note:
                eff_note = f"Automated retry #{idx - 1} after client checkout timeout"

            chk_data = _create_checkout_internal(
                CheckoutRequest(
                    sku=body.sku,
                    item_name=body.item_name,
                    amount=body.amount,
                    quantity=body.quantity,
                    sku_category=body.sku_category,
                    product_family_id=body.product_family_id,
                    buyer_note=eff_note,
                    customer_id=body.customer_id,
                    checkout_attempt_id=attempt_id,
                    force_local_sim=is_local_sim,
                ),
                base_url,
            )
            oid = chk_data["order_id"]
            active_order_id = oid
            approval_url = chk_data.get("approval_url")

            trace.append({
                "title": f"ORDER #{idx} CREATED VIA SDK: {oid} (Intent Rewritten -> {chk_data.get('rewritten_intent')})",
                "detail": f"SKU: {chk_data.get('sku')} | Amount: ${chk_data.get('amount')} {chk_data.get('currency')} | Attempt ID: {attempt_id}",
                "tone": "info",
            })

            if is_local_sim:
                sim_data = simulate_buyer_approval(
                    oid,
                    SimulateApprovalBody(
                        payer_id=body.customer_id,
                        payer_email=f"{body.customer_id.lower()}@example.test",
                    ),
                )
                settlement = sim_data.get("settlement") or {}
                final_status = settlement.get("final_status", "UNKNOWN")
                gate_data = sdk.get_gate_status(order_id=oid)
                outputs.append({"checkout": chk_data, "settlement": settlement, "mcp_gate": gate_data})
                trace.append({
                    "title": f"SETTLED {oid} -> {final_status} ({settlement.get('decision_mode')})",
                    "detail": f"Summary: {settlement.get('merchant_summary')}\nMCP Gate: {gate_data.get('mcp_gate_decision')} (agent_should_retry={gate_data.get('agent_should_retry')})",
                    "tone": "ok" if final_status == "CAPTURED" else "warn",
                })
            else:
                awaiting_paypal = True
                outputs.append({"checkout": chk_data})

        return {
            "execution_mode": "local_sim" if is_local_sim else "live_sandbox",
            "active_order_id": active_order_id,
            "approval_url": approval_url,
            "awaiting_paypal_approval": awaiting_paypal,
            "trace": trace,
            "results": outputs,
        }

    return app


app = create_store_app() if os.getenv("INTENTGUARD_MERCHANT_API_KEY") else None
