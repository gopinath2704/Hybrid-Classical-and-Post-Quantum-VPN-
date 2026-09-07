"""IPv6 policy and lifecycle tests; kernel commands are simulated here."""
import json
import os
from pathlib import Path
import select
import signal
import socket
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
import vpn.ipv6 as ipv6
import vpn.runtime as runtime
import vpn.doctor as doctor
from vpn.config import ClientConfig
from vpn.config import validate_client, load_client_config
from vpn.engine import TUNMode
from handshake.kemtls import HandshakeError, KEMTLSClient, KEMTLSServer
from vpn.identity import AuthorizedClients, fingerprint
from test_session_activity import connected
from test_dead_peer import PongFilter
from test_runtime_fixes import until


class NativeTun:
    name = 'testtun'
    mode = TUNMode.NATIVE


@pytest.fixture
def kernel(monkeypatch):
    state = SimpleNamespace(tables={'unrelated': 'original policy'}, calls=[], routes=[], fail_create=False)
    def process(args, **kwargs):
        state.calls.append((args, kwargs.get('input')))
        if args == ['nft', '-f', '-']:
            if state.fail_create: raise subprocess.CalledProcessError(1, args)
            table = kwargs['input'].splitlines()[0].split()[-1]
            assert table not in state.tables
            state.tables[table] = kwargs['input']
        elif args[:4] == ['nft', 'delete', 'table', 'ip6']:
            del state.tables[args[4]]
        else: raise AssertionError(f'unexpected OS mutation: {args}')
        return SimpleNamespace(returncode=0, stdout='')
    def ip(*args, **kwargs):
        state.routes.append(args)
        return SimpleNamespace(stdout='8.8.8.8 via 192.0.2.1 dev eth0\n' if args[:2] == ('route','get') else '')
    monkeypatch.setattr(ipv6.subprocess, 'run', process)
    monkeypatch.setattr(runtime, 'run_ip', ip)
    return state


def test_full_tunnel_blocks_ipv6_including_existing_flows_and_forwarding(kernel):
    net = runtime.ClientNetwork(NativeTun(), '8.8.8.8', True, [], [])
    net.apply()
    rules = kernel.tables[net.ipv6.table]
    assert 'create table ip6 ' in rules
    assert 'output oifname "lo" accept' in rules
    assert 'output counter drop' in rules
    assert 'hook forward priority filter; policy drop' in rules
    assert 'established' not in rules  # Existing public IPv6 connections cannot bypass.
    assert 'ip6' in rules and 'table inet' not in rules
    assert kernel.calls[0][0] == ['nft','-f','-']
    assert kernel.routes[0][:2] == ('route','get')
    net.restore(); net.restore()
    assert kernel.tables == {'unrelated':'original policy'}


@pytest.mark.parametrize('full,policy,blocked', [(True,None,True),(False,None,False),
    (False,'block',True),(True,'allow',False)])
def test_policy_defaults_and_explicit_split_block(kernel, full, policy, blocked, caplog):
    net = runtime.ClientNetwork(NativeTun(), '8.8.8.8', full, [], [], ipv6_policy=policy)
    net.apply()
    assert bool(net.ipv6.table) == blocked
    if policy == 'allow': assert 'NOT protected by PQVPN' in caplog.text
    net.restore()
    assert kernel.tables == {'unrelated':'original policy'}


def test_failed_atomic_block_does_not_touch_routes_or_unrelated_tables(kernel):
    kernel.fail_create = True
    net = runtime.ClientNetwork(NativeTun(), '8.8.8.8', True, [], [])
    with pytest.raises(subprocess.CalledProcessError): net.apply()
    assert not kernel.routes and net.ipv6.table is None
    assert kernel.tables == {'unrelated':'original policy'}


def test_guard_removed_even_if_dns_undo_raises(kernel, monkeypatch):
    net = runtime.ClientNetwork(NativeTun(), '8.8.8.8', True, [], [])
    net.apply()
    monkeypatch.setattr(net, '_restore_ipv4_dns', Mock(side_effect=OSError('resolver vanished')))
    with pytest.raises(OSError): net.restore()
    assert kernel.tables == {'unrelated':'original policy'}


@pytest.mark.parametrize('bad', ['auto','',False,[],42])
def test_unknown_policy_rejected(bad):
    with pytest.raises(ValueError, match='ipv6_policy'): validate_client(ClientConfig(ipv6_policy=bad))


def test_toml_policy_defaults_and_explicit_values(tmp_path):
    p=tmp_path/'client.toml'
    for content, expected in [('[client]\n','block'),('[client]\nfull_tunnel=false\n','allow'),
                              ('[client]\nfull_tunnel=false\nipv6_policy="block"\n','block')]:
        p.write_text(content); cfg=load_client_config(p)
        assert ipv6.effective_policy(cfg.full_tunnel,cfg.ipv6_policy)==expected


@pytest.mark.parametrize('routes,addresses,detected', [
    ([{'dst':'default','dev':'eth0','gateway':'fe80::1'}],[],True),
    ([],[{'ifname':'eth0','addr_info':[{'scope':'global','local':'2001:db8::2'}]}],True),
    ([{'dst':'fe80::/64','dev':'eth0'}],[{'ifname':'lo','addr_info':[{'scope':'host','local':'::1'}]}],False),
    ([{'dst':'default','type':'unreachable'}],[],False),
    ([],[{'ifname':'eth0','addr_info':[{'scope':'global','local':'fd00::2'}]}],True),
])
def test_read_only_connectivity_detection(routes, addresses, detected):
    calls=[]
    def read(*args):
        calls.append(args)
        return json.dumps(routes if 'route' in args else addresses)
    assert bool(ipv6.connectivity(read)) == detected
    assert calls == [('ip','-j','-6','route','show','table','all'),('ip','-j','-6','addr','show')]


def test_fail_policy_rejects_before_tun_or_routing(kernel, monkeypatch):
    monkeypatch.setattr(ipv6, 'connectivity', lambda: ['route default dev eth0'])
    tun=Mock();monkeypatch.setattr(runtime,'open_tun',tun)
    client=runtime.VPNClient(ClientConfig(ipv6_policy='fail'))
    with pytest.raises(RuntimeError,match='IPv6 connectivity'): client.connect()
    tun.assert_not_called()
    assert not kernel.routes and not kernel.calls


def test_fail_policy_with_no_ipv6_does_not_install_guard(kernel, monkeypatch):
    monkeypatch.setattr(ipv6,'connectivity',lambda:[])
    net=runtime.ClientNetwork(NativeTun(),'8.8.8.8',True,[],[],ipv6_policy='fail')
    net.apply();assert not kernel.calls
    net.restore()


@pytest.mark.parametrize('ending', ['disconnect','dead-peer','control-loss','rekey-failure','setup-failure'])
def test_actual_client_cleanup_removes_guard(connected, kernel, monkeypatch, ending):
    server,client=connected
    client.cfg.full_tunnel=True
    client.cfg.dead_peer_timeout=1
    network_class=runtime.ClientNetwork
    def network(tun,*args):
        net=network_class(NativeTun(),*args)
        if ending=='setup-failure':
            apply=net.apply
            def fail():
                apply()
                raise RuntimeError('failure after IPv6 guard installation')
            net.apply=fail
        return net
    monkeypatch.setattr(runtime,'ClientNetwork',network)
    if ending=='setup-failure':
        with pytest.raises(RuntimeError,match='after IPv6'):client.connect()
    else:
        client.connect()
        assert client.network.ipv6.table in kernel.tables
        if ending=='disconnect':client.disconnect()
        elif ending=='dead-peer':
            filtered=PongFilter(server.udp);filtered.drop=True;server.udp=filtered
        elif ending=='control-loss':
            next(iter(server.sessions.by_id.values())).control.shutdown(socket.SHUT_RDWR)
        else:
            monkeypatch.setattr(client.session,'derive_next_epoch',Mock(side_effect=HandshakeError('rekey failure')))
            with pytest.raises(HandshakeError):client.rekey()
        until(client._cleanup_done.is_set,5)
        assert client.state == ('DISCONNECTED' if ending=='disconnect' else 'FAILED')
    assert kernel.tables == {'unrelated':'original policy'}


def test_sigterm_real_cli_restores_ipv6_guard():
    script='''
import threading
from types import SimpleNamespace
from unittest.mock import patch
import vpn.cli as cli
from vpn.runtime import VPNClient, ClientNetwork
from vpn.config import ClientConfig
from vpn.engine import TUNMode
tables=set()
def process(args,**kwargs):
    if args==['nft','-f','-']:tables.add(kwargs['input'].splitlines()[0].split()[-1])
    elif args[:4]==['nft','delete','table','ip6']:tables.remove(args[4]);print('IPv6 restored',flush=True)
    else:raise AssertionError(args)
    return SimpleNamespace(returncode=0)
def ip(*args,**kwargs):return SimpleNamespace(stdout='8.8.8.8 via 192.0.2.1 dev eth0' if args[:2]==('route','get') else '')
class Client(VPNClient):
    def connect(self):
        self.network=ClientNetwork(SimpleNamespace(mode=TUNMode.NATIVE),'8.8.8.8',False,[],[],ipv6_policy='block')
        self.network.apply();assert tables
        return {'client_vpn_ip':'10.8.0.2','udp_port':51820}
with patch.object(cli,'VPNClient',Client),patch.object(cli,'load_client_config',return_value=ClientConfig()),patch.object(cli,'get_crypto_status',return_value={'is_quantum_safe':True}),patch('vpn.ipv6.subprocess.run',process),patch('vpn.runtime.run_ip',ip):
    cli.main()
assert not tables
'''
    proc=subprocess.Popen([sys.executable,'-u','-c',script,'client','connect'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    try:
        while True:
            assert select.select([proc.stdout],[],[],5)[0]
            line=proc.stdout.readline()
            assert line,proc.stderr.read()
            if 'connected:' in line:break
        proc.send_signal(signal.SIGTERM)
        out,err=proc.communicate(timeout=5)
        assert proc.returncode==0,err
        assert 'IPv6 restored' in out
    finally:
        if proc.poll() is None:proc.kill();proc.wait()


@pytest.mark.parametrize('policy,connected6,level',[('block',True,'PASS'),('fail',True,'FAIL'),('allow',True,'WARN'),('fail',False,'PASS')])
def test_doctor_ipv6_is_read_only(tmp_path,monkeypatch,capsys,policy,connected6,level):
    p=tmp_path/'client.toml';p.write_text(f'[client]\nipv6_policy="{policy}"\ndns_mode="none"\n')
    calls=[]
    def command(*args):
        calls.append(args)
        if '-j' in args:return json.dumps([{'dst':'default','dev':'eth0'}] if '-6' in args and 'route' in args and connected6 else [])
        return ''
    monkeypatch.setattr(doctor,'command',command)
    monkeypatch.setattr(doctor.shutil,'which',lambda _: '/usr/bin/tool')
    doctor.run('client',p)
    out=capsys.readouterr().out
    assert ('WARN IPv6 bypass explicitly permitted' if level=='WARN' else f'{level} IPv6 leak policy') in out
    assert any('-6' in call and 'addr' in call for call in calls)
    assert all(not set(call)&{'add','delete','replace','set','-w'} for call in calls)
    assert list(tmp_path.iterdir())==[p]


def test_revoked_client_cannot_start_new_handshake(identities,tmp_path):
    sk,pk,csk,cpk=identities
    db=AuthorizedClients(tmp_path/'clients.json');fp=db.authorize(cpk,'alice')
    client=KEMTLSClient(pk,fingerprint(pk),csk,True)
    server=KEMTLSServer(sk,pk,db.find,True)
    ch=client.initiate_handshake();sh=server.process_client_hello(ch)
    sf,ss=server.process_client_key_exchange(client.process_server_hello(sh))
    cs=client.process_server_finished(sf)
    assert db.revoke(fp)
    # Existing sessions intentionally continue; new authorization reads the updated DB.
    assert ss.decrypt_frame(cs.encrypt_frame(b'existing session'))[1]==b'existing session'
    new_client=KEMTLSClient(pk,fingerprint(pk),csk,True)
    with pytest.raises(HandshakeError,match='unauthorized'):
        KEMTLSServer(sk,pk,db.find,True).process_client_hello(new_client.initiate_handshake())
    cs.secure_wipe();ss.secure_wipe()


def test_revoke_cli_explains_active_session_boundary(identities,tmp_path,monkeypatch,capsys):
    import vpn.cli as cli
    db=AuthorizedClients(tmp_path/'clients.json');fp=db.authorize(identities[3],'alice')
    monkeypatch.setattr(sys,'argv',['pqvpn','client','revoke',fp,'--database',str(db.path)])
    cli.main()
    out=capsys.readouterr().out
    assert 'revoked for new sessions' in out and 'Restart' in out and 'all clients' in out
    assert 'Existing active sessions continue until disconnect/expiration/server restart.' in out


@pytest.mark.parametrize('match',[True,False])
def test_native_installer_verifies_commit_before_build(tmp_path,match):
    import re
    source=Path('scripts/install-liboqs.sh').read_text()
    commit=re.search(r'^LIBOQS_COMMIT=([0-9a-f]{40})$',source,re.M)[1]
    assert f'liboqs-source-commit={commit}' in Path('deploy/tested-versions.txt').read_text()
    bin=tmp_path/'bin';bin.mkdir()
    script='''#!/usr/bin/env python3
import os,sys,pathlib
name=pathlib.Path(sys.argv[0]).name
with open(os.environ['BUILD_LOG'],'a') as f:f.write(name+' '+' '.join(sys.argv[1:])+'\\n')
if name=='git' and 'rev-parse' in sys.argv:print(os.environ['TEST_COMMIT'])
'''
    for name in ('git','cmake','ldconfig'):
        p=bin/name;p.write_text(script);p.chmod(0o755)
    log=tmp_path/'calls'
    env={**os.environ,'PATH':str(bin)+os.pathsep+os.environ['PATH'],'BUILD_LOG':str(log),
         'TEST_COMMIT':commit if match else '0'*40}
    r=subprocess.run(['bash','scripts/install-liboqs.sh',str(tmp_path/'prefix')],env=env,capture_output=True,text=True,timeout=10)
    assert (r.returncode==0)==match
    assert ('cmake ' in log.read_text())==match
    if not match:assert 'source mismatch' in r.stderr
