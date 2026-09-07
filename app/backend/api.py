"""Authenticated loopback-first management API."""
from __future__ import annotations
import asyncio,hmac,os,time,secrets
from pathlib import Path
from fastapi import Depends,FastAPI,Header,HTTPException,WebSocket,WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from crypto.hybrid_crypto import get_crypto_status
from vpn.config import load_client_config
from vpn.runtime import VPNClient
TOKEN=os.environ.get("PQVPN_MANAGEMENT_TOKEN","")
ORIGINS=[x.strip() for x in os.environ.get("PQVPN_ALLOWED_ORIGINS","http://127.0.0.1:8000,http://localhost:8000").split(",") if x.strip()]
REMOTE = os.environ.get("PQVPN_REMOTE_MANAGEMENT") == "1"
if REMOTE and (len(TOKEN) < 43 or len(set(TOKEN)) < 12 or not os.environ.get("PQVPN_ALLOWED_ORIGINS")
               or not ORIGINS or any(not origin.startswith("https://") or "*" in origin for origin in ORIGINS)):
    raise ValueError("remote management requires a strong random token (32 random bytes), explicit HTTPS origins, and a TLS reverse proxy")
_tickets = {}
app=FastAPI(title="PQVPN Management API",version="2.0")
app.add_middleware(CORSMiddleware,allow_origins=ORIGINS,allow_credentials=True,allow_methods=["GET","POST"],allow_headers=["Authorization","Content-Type"])
frontend=Path(__file__).resolve().parent.parent/"frontend"
app.mount("/css",StaticFiles(directory=frontend/"css"),name="css");app.mount("/js",StaticFiles(directory=frontend/"js"),name="js")
service:VPNClient|None=None; state={"connection_state":"DISCONNECTED","error":"","connected_at":None}
def require_token(authorization:str|None=Header(default=None)):
    if not TOKEN:raise HTTPException(503,"management token is not configured")
    if not authorization or not authorization.startswith("Bearer ") or not hmac.compare_digest(authorization[7:],TOKEN):raise HTTPException(401,"invalid management bearer token")
@app.get("/",include_in_schema=False)
async def index():return FileResponse(frontend/"index.html")
@app.get("/api/v1/crypto/status",dependencies=[Depends(require_token)])
async def crypto():return get_crypto_status()
@app.get("/api/v1/vpn/servers",dependencies=[Depends(require_token)])
async def servers():
    cfg=load_client_config("config/client.toml")
    return {"servers":[{"id":"configured","name":"Configured server","host":cfg.server_host,"port":cfg.server_control_port}]}
@app.post("/api/v1/vpn/connect",dependencies=[Depends(require_token)])
async def connect(config:str="config/client.toml"):
    global service
    if (getattr(service,"state",state["connection_state"]) if service else state["connection_state"]) in {"CONNECTING","CONNECTED"}:raise HTTPException(409,"already connected")
    state["connection_state"]="CONNECTING"
    try:
        service=VPNClient(load_client_config(config));info=await asyncio.to_thread(service.connect);state.update(connection_state="CONNECTED",connected_at=time.monotonic(),error="");return {"status":"connected",**(await status())}
    except Exception as exc:state.update(connection_state="ERROR",error=str(exc));raise HTTPException(503,str(exc))
@app.post("/api/v1/vpn/disconnect",dependencies=[Depends(require_token)])
async def disconnect():
    global service
    if not service:raise HTTPException(409,"not connected")
    await asyncio.to_thread(service.disconnect);service=None;state.update(connection_state="DISCONNECTED",connected_at=None);return {"status":"disconnected"}
@app.post("/api/v1/vpn/rekey",dependencies=[Depends(require_token)])
async def rekey():
    if not service or not service.session:raise HTTPException(409,"not connected")
    try:
        await asyncio.to_thread(service.rekey)
        if not service.session:raise RuntimeError("session lost during rekey")
        return {"status":"rekeyed","epoch":service.session.epoch}
    except Exception as exc:raise HTTPException(503,"rekey failed; check VPN status") from exc
@app.get("/api/v1/vpn/status",dependencies=[Depends(require_token)])
async def status():
    session=getattr(service,"session",None)
    tunnel=getattr(service,"tunnel",{})
    quality=service.quality.snapshot().to_dict() if getattr(service,"quality",None) else {}
    crypto=get_crypto_status()
    live_state=getattr(service,"state",state["connection_state"])
    connected=live_state=="CONNECTED"
    tun=getattr(service,"tun",None)
    next_rekey=getattr(service,"next_rekey",None)
    return {"type":"telemetry","connection_state":live_state,
        "error":getattr(service,"error",state["error"]),
        "uptime_seconds":time.monotonic()-state["connected_at"] if connected and state["connected_at"] else 0,
        "client_vpn_ip":tunnel.get("client_vpn_ip") if connected else None,
        "epoch":session.epoch if session else None,
        "network":quality,"tun_mtu":tun.mtu if tun else None,
        "pqc_mode":crypto["pqc_mode"],"is_quantum_safe":crypto["is_quantum_safe"],
        "tun_mode":tun.mode.name if tun else None,
        "rekey_countdown":max(0,next_rekey-time.monotonic()) if connected and next_rekey else None}
@app.post("/api/v1/ws-ticket", dependencies=[Depends(require_token)])
async def websocket_ticket():
    now = time.monotonic()
    for ticket, deadline in list(_tickets.items()):
        if deadline <= now: del _tickets[ticket]
    if len(_tickets) >= 256: raise HTTPException(429, "too many pending websocket tickets")
    ticket = secrets.token_urlsafe(32)
    _tickets[ticket] = now + 30
    return {"ticket": ticket, "expires_in": 30}

@app.websocket("/ws/telemetry")
async def websocket(ws:WebSocket):
    supplied = ws.query_params.get("ticket", "")
    deadline = _tickets.pop(supplied, 0)
    if not TOKEN or deadline <= time.monotonic() or ws.headers.get("origin") not in ORIGINS:
        await ws.close(code=4401);return
    await ws.accept()
    try:
        while True:await ws.send_json(await status());await asyncio.sleep(1)
    except (WebSocketDisconnect,RuntimeError):pass
