import asyncio,importlib
import pytest
from fastapi import HTTPException
def load_api(monkeypatch,token="secret-token"):
    monkeypatch.setenv("PQVPN_MANAGEMENT_TOKEN",token);import app.backend.api as api;return importlib.reload(api)
def test_api_requires_bearer(monkeypatch):
    api=load_api(monkeypatch)
    with pytest.raises(HTTPException) as missing:asyncio.run(api.require_token(None))
    assert missing.value.status_code==401
    with pytest.raises(HTTPException):asyncio.run(api.require_token("Bearer wrong"))
    assert asyncio.run(api.require_token("Bearer secret-token")) is None
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
import asyncio
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException, WebSocketDisconnect
import vpn.doctor as doctor


def test_websocket_tickets_are_short_lived_single_use_and_origin_checked(monkeypatch):
    api=load_api(monkeypatch)
    ticket=asyncio.run(api.websocket_ticket())['ticket']
    ws=SimpleNamespace(query_params={'ticket':ticket},headers={'origin':api.ORIGINS[0]},
        close=AsyncMock(),accept=AsyncMock(),send_json=AsyncMock(side_effect=WebSocketDisconnect()))
    asyncio.run(api.websocket(ws));ws.accept.assert_awaited_once()
    ws.accept.reset_mock();asyncio.run(api.websocket(ws))
    ws.close.assert_awaited_with(code=4401);ws.accept.assert_not_awaited()
    for bad in ('expired','origin','bearer','random'):
        ticket=asyncio.run(api.websocket_ticket())['ticket']
        if bad=='expired':api._tickets[ticket]=0
        ws.query_params={'token':api.TOKEN} if bad=='bearer' else {'ticket':ticket}
        if bad=='random':ws.query_params={'ticket':'not-an-issued-ticket'}
        ws.headers={'origin':'https://evil.example' if bad=='origin' else api.ORIGINS[0]}
        ws.accept.reset_mock();asyncio.run(api.websocket(ws));ws.accept.assert_not_awaited()


def test_ticket_http_endpoint_requires_authentication(monkeypatch):
    api=load_api(monkeypatch)
    async def request(authorization=None):
        messages=[]
        received=False
        response_started=asyncio.Event()
        async def receive():
            nonlocal received
            if received:
                await response_started.wait()
                return {'type':'http.disconnect'}
            received=True
            return {'type':'http.request','body':b'','more_body':False}
        async def send(message):
            messages.append(message)
            if message['type']=='http.response.start':response_started.set()
        headers=[] if authorization is None else [(b'authorization',authorization)]
        await api.app({'type':'http','asgi':{'version':'3.0'},'http_version':'1.1',
            'method':'POST','scheme':'http','path':'/api/v1/ws-ticket',
            'raw_path':b'/api/v1/ws-ticket','query_string':b'', 'root_path':'',
            'headers':headers,'server':('127.0.0.1',8000),'client':('127.0.0.1',12345)},receive,send)
        return next(message['status'] for message in messages if message['type']=='http.response.start')
    assert asyncio.run(request())==401
    assert asyncio.run(request(b'Bearer wrong'))==401
    assert not api._tickets
    assert asyncio.run(request(b'Bearer secret-token'))==200
    assert len(api._tickets)==1


def test_ticket_cache_is_bounded(monkeypatch):
    api=load_api(monkeypatch)
    for _ in range(256):asyncio.run(api.websocket_ticket())
    with pytest.raises(HTTPException) as exc:asyncio.run(api.websocket_ticket())
    assert exc.value.status_code==429
    api._tickets={key:0 for key in api._tickets}
    asyncio.run(api.websocket_ticket());assert len(api._tickets)==1


def test_remote_management_rejects_trivial_token(monkeypatch):
    monkeypatch.setenv('PQVPN_REMOTE_MANAGEMENT','1')
    monkeypatch.setenv('PQVPN_ALLOWED_ORIGINS','https://vpn.example')
    with pytest.raises(ValueError,match='strong random'):load_api(monkeypatch,'password'*10)
    monkeypatch.delenv('PQVPN_REMOTE_MANAGEMENT')
    load_api(monkeypatch)


@pytest.mark.parametrize('version,baseline_level', [((3, 14, 7), 'PASS'), ((3, 11, 0), 'WARN')])
def test_doctor_is_read_only_and_reports_failures(monkeypatch, tmp_path, capsys, version, baseline_level):
    config=tmp_path/'server.toml';config.write_text('[server]\n')
    calls=[]
    def command(*args):
        calls.append(args)
        if args[0]=='sysctl':return '0'
        if args[:3]==('ip','-j','-4'):
            if 'default' in args:return '[{"dev":"eth0"}]'
            return '[]'
        return ''
    monkeypatch.setattr(doctor,'command',command)
    monkeypatch.setattr(doctor,'_OQS_AVAILABLE',False)
    monkeypatch.setattr(doctor.sys,'version_info',version)
    assert doctor.run('server',config)==1
    output=capsys.readouterr().out
    assert 'FAIL Native ML-KEM' in output and 'External provider/host firewall' in output
    assert 'PASS Python minimum runtime version (3.11)' in output
    assert f'{baseline_level} Python tested baseline: 3.14.7; other versions require fresh validation' in output
    assert config.read_text()=='[server]\n' and list(tmp_path.iterdir())==[config]
    assert all(not any(word in ('add','replace','delete','-w','set') for word in call) for call in calls)


def test_missing_native_library_never_imports_downloading_binding():
    script='''
import ctypes,ctypes.util,builtins
ctypes.util.find_library=lambda _:None
def missing(*args,**kwargs):raise OSError('absent')
ctypes.CDLL=missing
original=builtins.__import__
def guarded(name,*args,**kwargs):
 if name=='oqs':raise AssertionError('binding import attempted')
 return original(name,*args,**kwargs)
builtins.__import__=guarded
import crypto.hybrid_crypto as crypto
assert not crypto._OQS_AVAILABLE
assert 'automatic download/build is disabled' in crypto._OQS_LOAD_ERROR
try:crypto.PQCProvider()
except crypto.PQCUnavailableError:pass
else:raise AssertionError('native absence did not fail closed')
'''
    env={**os.environ,'ALLOW_MOCK_PQC':'0'}
    subprocess.run([sys.executable,'-c',script],env=env,check=True,capture_output=True,timeout=10)
