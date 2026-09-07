import asyncio,importlib
import pytest
from fastapi import HTTPException
def load_api(monkeypatch,token="secret-token"):
    monkeypatch.setenv("PQVPN_MANAGEMENT_TOKEN",token);import app.backend.api as api;return importlib.reload(api)
def test_api_requires_bearer(monkeypatch):
    api=load_api(monkeypatch)
    with pytest.raises(HTTPException) as missing:api.require_token(None)
    assert missing.value.status_code==401
    with pytest.raises(HTTPException):api.require_token("Bearer wrong")
    assert api.require_token("Bearer secret-token") is None
def test_no_fake_public_servers(monkeypatch):
    api=load_api(monkeypatch,"x");data=asyncio.run(api.servers());assert all("pq-vpn.net" not in x["host"] for x in data["servers"])

def test_api_owns_the_client_it_controls(monkeypatch):
    api=load_api(monkeypatch,"x")
    async def immediately(function,*args,**kwargs): return function(*args,**kwargs)
    class Session: epoch=4
    class FakeClient:
        def __init__(self,cfg): self.cfg=cfg; self.session=Session(); self.disconnected=False
        def connect(self): return {"client_vpn_ip":"10.8.0.2","udp_port":51820}
        def rekey(self): self.session.epoch += 1
        def disconnect(self): self.disconnected=True
    monkeypatch.setattr(api,"load_client_config",lambda _:object())
    monkeypatch.setattr(api,"VPNClient",FakeClient)
    monkeypatch.setattr(api.asyncio,"to_thread",immediately)
    result=asyncio.run(api.connect("irrelevant.toml"))
    owned=api.service
    assert result["status"]=="connected"
    assert asyncio.run(api.rekey())=={"status":"rekeyed","epoch":5}
    assert api.service is owned
    assert asyncio.run(api.disconnect())=={"status":"disconnected"}
    assert owned.disconnected and api.service is None
