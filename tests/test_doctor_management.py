import asyncio
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException, WebSocketDisconnect
from test_api_security import load_api
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
        async def receive():
            nonlocal received
            if received:await asyncio.Event().wait()
            received=True
            return {'type':'http.request','body':b'','more_body':False}
        async def send(message):messages.append(message)
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


def test_doctor_is_read_only_and_reports_failures(monkeypatch, tmp_path, capsys):
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
    assert doctor.run('server',config)==1
    output=capsys.readouterr().out
    assert 'FAIL Native ML-KEM' in output and 'External provider/host firewall' in output
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
