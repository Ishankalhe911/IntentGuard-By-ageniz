"""Admin merchant provisioning UI and merchant dashboard session endpoints."""
from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

from src.security.tenant_security import (
    MERCHANT_SESSION_COOKIE,
    MerchantSecurityStore,
    admin_identity,
    merchant_session_identity,
)


class CreateMerchantBody(BaseModel):
    merchant_name: str = Field(..., min_length=1, max_length=120)


def build_admin_portal_router() -> APIRouter:
    router = APIRouter(tags=["IntentGuard Platform Administration"])

    def require_admin(
        request: Request,
        x_admin_key: Optional[str] = Header(default=None, alias="X-Admin-Key"),
    ) -> bool:
        return admin_identity(request, x_admin_key)

    @router.get("/admin", response_class=HTMLResponse)
    def admin_portal() -> HTMLResponse:
        return HTMLResponse(ADMIN_HTML)

    @router.get("/api/v1/admin/merchants")
    def list_merchants(
        request: Request,
        _admin: bool = Depends(require_admin),
    ) -> Dict[str, Any]:
        store: MerchantSecurityStore = request.app.state.merchant_security
        return {"merchants": store.list_merchants()}

    @router.post("/api/v1/admin/merchants", status_code=201)
    def create_merchant(
        body: CreateMerchantBody,
        request: Request,
        _admin: bool = Depends(require_admin),
    ) -> Dict[str, Any]:
        store: MerchantSecurityStore = request.app.state.merchant_security
        try:
            identity, api_key = store.create_merchant(body.merchant_name)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return {
            "merchant": {
                "merchant_id": identity.merchant_id,
                "merchant_name": identity.merchant_name,
                "status": identity.status,
            },
            "api_key": api_key,
            "warning": "This API key is shown once. Copy it now and store it in the merchant's secret manager.",
        }

    @router.post("/api/v1/admin/merchants/{merchant_id}/rotate-key")
    def rotate_merchant_key(
        merchant_id: str,
        request: Request,
        _admin: bool = Depends(require_admin),
    ) -> Dict[str, Any]:
        store: MerchantSecurityStore = request.app.state.merchant_security
        key = store.rotate_merchant_key(merchant_id)
        if not key:
            raise HTTPException(status_code=404, detail="Active merchant not found.")
        return {"merchant_id": merchant_id, "api_key": key, "warning": "This API key is shown once."}

    @router.post("/api/v1/admin/merchants/{merchant_id}/revoke-keys")
    def revoke_merchant_keys(
        merchant_id: str,
        request: Request,
        _admin: bool = Depends(require_admin),
    ) -> Dict[str, Any]:
        store: MerchantSecurityStore = request.app.state.merchant_security
        if not store.get_merchant(merchant_id):
            raise HTTPException(status_code=404, detail="Merchant not found.")
        return {"merchant_id": merchant_id, "revoked_key_count": store.revoke_merchant_keys(merchant_id)}

    @router.post("/api/v1/admin/merchants/{merchant_id}/status")
    def set_merchant_status(
        merchant_id: str,
        body: Dict[str, str],
        request: Request,
        _admin: bool = Depends(require_admin),
    ) -> Dict[str, Any]:
        store: MerchantSecurityStore = request.app.state.merchant_security
        status = str(body.get("status") or "").upper()
        if status not in {"ACTIVE", "SUSPENDED"}:
            raise HTTPException(status_code=422, detail="Status must be ACTIVE or SUSPENDED.")
        if not store.set_merchant_status(merchant_id, status):
            raise HTTPException(status_code=404, detail="Merchant not found.")
        if status == "SUSPENDED":
            store.revoke_merchant_keys(merchant_id)
        return {"merchant_id": merchant_id, "status": status}

    return router


def build_merchant_session_router() -> APIRouter:
    router = APIRouter(tags=["IntentGuard Merchant Sessions"])

    @router.post("/api/v1/merchant/session")
    def create_merchant_session(request: Request) -> JSONResponse:
        store: MerchantSecurityStore = request.app.state.merchant_security
        identity = store.authenticate_api_key(request.headers.get("X-Merchant-Key"))
        if not identity:
            raise HTTPException(status_code=401, detail="Missing or invalid merchant API key.")
        token = store.create_session(identity.merchant_id)
        response = JSONResponse({
            "authenticated": True,
            "merchant": {"merchant_id": identity.merchant_id, "merchant_name": identity.merchant_name},
        })
        response.set_cookie(
            MERCHANT_SESSION_COOKIE,
            token,
            httponly=True,
            secure=(request.url.scheme == "https" or request.headers.get("x-forwarded-proto", "").split(",", 1)[0].strip().lower() == "https"),
            samesite="strict",
            max_age=8 * 60 * 60,
            path="/",
        )
        response.headers["Cache-Control"] = "no-store"
        return response

    @router.get("/api/v1/merchant/me")
    def current_merchant(identity=Depends(merchant_session_identity)) -> Dict[str, Any]:
        return {"merchant": {"merchant_id": identity.merchant_id, "merchant_name": identity.merchant_name}}


    @router.post("/api/v1/dashboard/ws-ticket")
    def issue_dashboard_ws_ticket(request: Request) -> Dict[str, Any]:
        store: MerchantSecurityStore = request.app.state.merchant_security
        if getattr(request.state, "is_platform_admin", False):
            ticket = store.issue_ws_ticket("__admin__")
            return {"ticket": ticket, "expires_in_seconds": 60}
        identity = merchant_session_identity(request)
        ticket = store.issue_ws_ticket(identity.merchant_id)
        return {"ticket": ticket, "expires_in_seconds": 60}

    @router.delete("/api/v1/merchant/session")
    def delete_merchant_session(request: Request) -> JSONResponse:
        request.app.state.merchant_security.delete_session(request.cookies.get(MERCHANT_SESSION_COOKIE))
        response = JSONResponse({"authenticated": False})
        response.delete_cookie(MERCHANT_SESSION_COOKIE, path="/", samesite="strict")
        return response

    return router


ADMIN_HTML = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>IntentGuard by Ageniz · Platform Admin</title>
<style>
:root{color-scheme:dark;--bg:#0b1220;--panel:#121c2d;--line:#26364d;--text:#e8eef7;--muted:#9aabc1;--blue:#54a8ff;--green:#55d69e;--red:#ff7777}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 Inter,ui-sans-serif,system-ui,sans-serif}header{padding:22px 5vw;border-bottom:1px solid var(--line);display:flex;justify-content:space-between;align-items:center;gap:18px;flex-wrap:wrap}h1{font-size:21px;margin:0}main{max-width:1100px;margin:34px auto;padding:0 22px}.panel{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:22px;margin-bottom:20px}label{display:block;color:var(--muted);font-size:13px;margin-bottom:7px}input{background:#0d1726;border:1px solid var(--line);border-radius:8px;color:var(--text);padding:11px 12px;width:100%;min-width:0}button{border:0;border-radius:8px;background:var(--blue);color:#06101d;padding:10px 15px;font-weight:700;cursor:pointer}button.secondary{background:#23334a;color:var(--text)}button.danger{background:#5b2830;color:#ffd9dc}.row{display:flex;gap:12px;align-items:end;flex-wrap:wrap}.field{flex:1;min-width:220px}.muted{color:var(--muted)}.status{font-size:13px;margin:12px 0}.success{color:var(--green)}.error{color:var(--red)}table{width:100%;border-collapse:collapse;margin-top:15px}th,td{text-align:left;padding:12px 9px;border-bottom:1px solid var(--line);font-size:13px;vertical-align:top}th{color:var(--muted);font-weight:600}.keybox{display:none;margin-top:15px;border:1px solid #477e70;background:#102a28;padding:15px;border-radius:10px;overflow-wrap:anywhere}.keybox code{display:block;margin:8px 0;font-size:13px}.actions{display:flex;gap:7px;flex-wrap:wrap}.pill{padding:3px 8px;border-radius:20px;background:#263b52;font-size:11px}.pill.suspended{background:#542b35;color:#ffb6bd}@media(max-width:700px){table{display:block;overflow:auto}}
</style></head><body>
<header><div><h1>IntentGuard</h1><div class="muted">by Ageniz · PayPal Merchant Firewall · Platform administration</div></div><div class="row" style="min-width:min(420px,100%)"><div class="field"><label for="admin-key">Platform admin key</label><input id="admin-key" type="password" autocomplete="current-password" placeholder="Enter INTENTGUARD_ADMIN_API_KEY"></div><button onclick="loadMerchants()">Connect</button></div></header>
<main><section class="panel"><h2>Create merchant</h2><p class="muted">Create an isolated merchant identity and issue its SDK/dashboard API key.</p><div class="row"><div class="field"><label for="merchant-name">Merchant / business name</label><input id="merchant-name" maxlength="120" placeholder="Example Store Pvt Ltd"></div><button onclick="createMerchant()">Create & generate key</button></div><div id="new-key" class="keybox"><strong>Copy this key now — it will not be shown again.</strong><code id="new-key-value"></code><button class="secondary" onclick="copyKey()">Copy key</button></div><div id="create-status" class="status"></div></section>
<section class="panel"><div class="row" style="justify-content:space-between;align-items:center"><div><h2>Merchants</h2><div class="muted">Only hashed API-key material is stored. Full keys are shown once at creation/rotation.</div></div><button class="secondary" onclick="loadMerchants()">Refresh</button></div><div id="merchant-list" class="muted">Connect using the platform admin key to load merchants.</div></section></main>
<script>
let adminKey='';const $=id=>document.getElementById(id);function msg(id,text,ok){$(id).textContent=text;$(id).className='status '+(ok?'success':'error')}
async function api(path,method='GET',body){const r=await fetch(path,{method,headers:{'X-Admin-Key':adminKey,'Content-Type':'application/json'},body:body?JSON.stringify(body):undefined,cache:'no-store'});const d=await r.json().catch(()=>({}));if(!r.ok)throw new Error(d.detail||`HTTP ${r.status}`);return d}
async function loadMerchants(){adminKey=$('admin-key').value.trim();if(!adminKey){msg('create-status','Enter the platform admin key.',false);return}try{const d=await api('/api/v1/admin/merchants');renderMerchants(d.merchants||[]);msg('create-status','Connected to IntentGuard by Ageniz admin API.',true)}catch(e){msg('create-status',e.message,false)}}
function renderMerchants(items){if(!items.length){$('merchant-list').textContent='No merchants registered yet.';return}const table=document.createElement('table');table.innerHTML='<thead><tr><th>Merchant</th><th>Status</th><th>Active keys</th><th>Created</th><th>Actions</th></tr></thead>';const tb=document.createElement('tbody');for(const m of items){const tr=document.createElement('tr');const name=document.createElement('td');name.textContent=m.merchant_name+' · '+m.merchant_id;const status=document.createElement('td');const pill=document.createElement('span');pill.className='pill '+(m.status==='ACTIVE'?'':'suspended');pill.textContent=m.status;status.append(pill);const count=document.createElement('td');count.textContent=String(m.active_key_count);const date=document.createElement('td');date.textContent=new Date(m.created_at*1000).toLocaleString();const act=document.createElement('td');act.className='actions';const rot=document.createElement('button');rot.className='secondary';rot.textContent='Rotate key';rot.onclick=()=>rotateKey(m.merchant_id);const suspend=document.createElement('button');suspend.className='danger';suspend.textContent=m.status==='ACTIVE'?'Suspend':'Reactivate';suspend.onclick=()=>setStatus(m.merchant_id,m.status==='ACTIVE'?'SUSPENDED':'ACTIVE');const revoke=document.createElement('button');revoke.className='danger';revoke.textContent='Revoke keys';revoke.onclick=()=>revokeKeys(m.merchant_id);act.append(rot,suspend,revoke);tr.append(name,status,count,date,act);tb.append(tr)}table.append(tb);$('merchant-list').replaceChildren(table)}
async function createMerchant(){try{const d=await api('/api/v1/admin/merchants','POST',{merchant_name:$('merchant-name').value});$('new-key-value').textContent=d.api_key;$('new-key').style.display='block';$('merchant-name').value='';msg('create-status','Merchant created. Save the key securely now.',true);await loadMerchants()}catch(e){msg('create-status',e.message,false)}}
async function rotateKey(id){if(!confirm('Revoke existing keys and issue a new key?'))return;try{const d=await api(`/api/v1/admin/merchants/${encodeURIComponent(id)}/rotate-key`,'POST');$('new-key-value').textContent=d.api_key;$('new-key').style.display='block';await loadMerchants()}catch(e){alert(e.message)}}
async function setStatus(id,status){try{await api(`/api/v1/admin/merchants/${encodeURIComponent(id)}/status`,'POST',{status});await loadMerchants()}catch(e){alert(e.message)}}
async function revokeKeys(id){if(!confirm('Revoke every active API key and disconnect existing dashboard sessions?'))return;try{await api(`/api/v1/admin/merchants/${encodeURIComponent(id)}/revoke-keys`,'POST');await loadMerchants()}catch(e){alert(e.message)}}
async function copyKey(){try{await navigator.clipboard.writeText($('new-key-value').textContent)}catch(_){alert('Clipboard unavailable; select and copy the key manually.')}}
</script></body></html>'''