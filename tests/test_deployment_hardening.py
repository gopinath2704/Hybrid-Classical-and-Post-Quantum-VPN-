import base64
import json
import os
from pathlib import Path
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from vpn.config import ServerConfig, ClientConfig, validate_server, validate_client, load_client_config
from vpn.identity import AuthorizedClients, generate_server_identity, generate_client_identity, validate_server_identity, load_client_private
from vpn.firewall import render, DENIED
from vpn.doctor import overlapping_routes
import vpn.runtime as runtime


@pytest.mark.parametrize('field,value', [('control_port',0),('control_port',65536),('udp_port',False),
    ('vpn_subnet','fd00::/64'),('server_vpn_ip','10.8.0.0'),('server_vpn_ip','10.8.0.255'),
    ('server_vpn_ip','10.9.0.1'),('tun_name','bad;name'),('tun_name','a'*16),('mtu',575),('mtu',9000),
    ('max_clients',0),('max_clients',254),('handshake_timeout',0),('idle_timeout',0),('session_timeout',300),
    ('rekey_interval',-1),('connections_per_source',0),('rate_limit_window',float('nan')),
    ('dns_servers',['bad']),('outbound_interface','bad/interface'),('manage_ip_forward','false'),
    ('allowed_forward_networks',['::/0'])])
def test_bad_server_config_fails_before_tun(field, value, monkeypatch):
    open_tun = Mock()
    monkeypatch.setattr(runtime, 'open_tun', open_tun)
    with pytest.raises((ValueError, TypeError)): runtime.VPNServer(replace(ServerConfig(), **{field:value}))
    open_tun.assert_not_called()


@pytest.mark.parametrize('field,value', [('ping_interval',0),('ping_timeout',-1),('dead_peer_timeout',4),
    ('dns_mode','resolv.conf'),('dns_routing_domains',['--evil']),('expected_vpn_subnet','::/64')])
def test_client_options_validate(field, value):
    with pytest.raises(ValueError): validate_client(replace(ClientConfig(), **{field:value}))


def test_obsolete_udp_setting_rejected(tmp_path):
    path = tmp_path/'client.toml'; path.write_text('[client]\nserver_udp_port=1234\n')
    with pytest.raises(ValueError, match='unknown'): load_client_config(path)


def test_firewall_order_and_scope():
    cfg = ServerConfig(allowed_forward_networks=['10.50.0.10/32'])
    text = render(cfg, 'eth0')
    assert 'policy drop' not in text
    assert text.index('oifname "pqvpn0" drop') < text.index('ip daddr 10.50.0.10/32 accept')
    assert text.index('ip daddr 10.50.0.10/32 accept') < text.index('169.254.0.0/16')
    assert text.index('169.254.0.0/16') < text.index('ip saddr 10.8.0.0/24 accept')
    assert all(cidr in text for cidr in DENIED)
    assert 'iifname "pqvpn0" drop' in text and 'oifname "pqvpn0" drop' in text
    input_chain = text.split(' chain input ')[1].split('table ip')[0]
    assert '10.8.0.1 icmp type echo-request accept' in input_chain
    assert 'tcp' not in input_chain and 'udp' not in input_chain
    assert 'echo-request' not in render(replace(cfg, allow_server_ping=False), 'eth0')


@pytest.fixture
def firewall_commands(tmp_path):
    bindir = tmp_path/'bin'; bindir.mkdir()
    state, logs, batches = tmp_path/'forward', tmp_path/'commands', tmp_path/'batches'
    state.write_text('0')
    script = '''#!/usr/bin/env python3
import os,sys,pathlib
name=pathlib.Path(sys.argv[0]).name; args=sys.argv[1:]
with open(os.environ['TEST_LOG'],'a') as f: f.write(name+' '+' '.join(args)+'\\n')
state=pathlib.Path(os.environ['TEST_FORWARD'])
if name=='sysctl':
 if args[0]=='-n': print(state.read_text())
 else: state.write_text(args[1].split('=')[1])
if name=='nft' and args[0]=='-f':
 with open(os.environ['TEST_BATCH'],'a') as f: f.write(pathlib.Path(args[1]).read_text()+'---END---\\n')
'''
    for name in ('nft','ip','sysctl'):
        path=bindir/name;path.write_text(script);path.chmod(0o755)
    env={**os.environ,'PATH':str(bindir)+os.pathsep+os.environ['PATH'], 'PQVPN_PYTHON':sys.executable,
         'PQVPN_RUNTIME_DIR':str(tmp_path/'run'), 'TEST_LOG':str(logs), 'TEST_FORWARD':str(state), 'TEST_BATCH':str(batches)}
    return tmp_path, state, logs, batches, env


@pytest.mark.parametrize('original', ['0','1'])
def test_forwarding_restore_and_reconcile(firewall_commands, original):
    root,state,logs,batches,env=firewall_commands
    state.write_text(original)
    cfg=root/'server.toml'; cfg.write_text('[server]\noutbound_interface="wan0"\n')
    def setup(): subprocess.run(['bash','scripts/server-setup.sh',str(cfg)],env=env,check=True,capture_output=True,timeout=10)
    setup();setup()
    assert state.read_text()=='1'
    assert (root/'run/ip_forward.prev').read_text().strip()==original
    batch=batches.read_text().split('---END---\n'); assert batch[0]==batch[1]
    cfg.write_text('[server]\noutbound_interface="wan1"\nvpn_subnet="10.66.0.0/24"\nserver_vpn_ip="10.66.0.1"\n')
    setup()
    latest=batches.read_text().split('---END---\n')[-2]
    assert 'wan1' in latest and 'wan0' not in latest and '10.8.0.0/24' not in latest
    subprocess.run(['bash','scripts/server-cleanup.sh'],env=env,check=True,capture_output=True,timeout=10)
    assert state.read_text()==original and not (root/'run/ip_forward.prev').exists()
    assert 'delete table inet unrelated' not in logs.read_text()


def test_unmanaged_forwarding_fails_if_disabled(firewall_commands):
    root,state,logs,batches,env=firewall_commands
    cfg=root/'server.toml';cfg.write_text('[server]\noutbound_interface="wan0"\nmanage_ip_forward=false\n')
    result=subprocess.run(['bash','scripts/server-setup.sh',str(cfg)],env=env,capture_output=True,timeout=10)
    assert result.returncode and state.read_text()=='0' and not batches.exists()


@pytest.mark.parametrize('mode,available,full', [('systemd-resolved',True,True),('systemd-resolved',False,True),('none',False,True),('systemd-resolved',True,False)])
def test_dns_fail_safe_and_restore(monkeypatch, mode, available, full, caplog):
    from test_network_transactions import Tun
    calls=[]
    def ip(*args,**kwargs):
        calls.append(args)
        return SimpleNamespace(stdout='8.8.8.8 via 192.0.2.1 dev eth0\n' if args[:2]==('route','get') else '')
    def process(args,**kwargs):
        calls.append(tuple(args)); return SimpleNamespace(returncode=0 if available else 1)
    monkeypatch.setattr(runtime,'run_ip',ip);monkeypatch.setattr(runtime.subprocess,'run',process)
    net=runtime.ClientNetwork(Tun(),'8.8.8.8',full,[],['1.1.1.1'],dns_mode=mode)
    if mode=='systemd-resolved' and not available:
        with pytest.raises(RuntimeError,match='requires resolvectl'): net.apply()
        assert ('route','del','8.8.8.8/32','via','192.0.2.1','dev','eth0') in calls
        assert not net.route_undo
    else:
        net.apply();net.restore()
        if mode=='none':
            assert 'explicitly unmanaged' in caplog.text
            assert not any(call[0]=='resolvectl' for call in calls)
        else:
            assert ('resolvectl','revert','pqvpn0') in calls
            assert (('resolvectl','domain','pqvpn0','~.') in calls) == full


def test_server_identity_pair_and_permissions(tmp_path):
    secret,public=tmp_path/'sk',tmp_path/'pk'
    generate_server_identity(secret,public,allow_mock=True)
    validate_server_identity(secret,public,allow_mock=True)
    generate_server_identity(tmp_path/'other',public,allow_mock=True)
    with pytest.raises(ValueError,match='consistency'):validate_server_identity(secret,public,allow_mock=True)
    secret.chmod(0o644)
    with pytest.raises(ValueError,match='0600'):validate_server_identity(secret,public,allow_mock=True)
    secret.chmod(0o600); link=tmp_path/'link'; link.symlink_to(secret)
    with pytest.raises(OSError):validate_server_identity(link,public,allow_mock=True)


def test_client_private_permissions(tmp_path):
    private=tmp_path/'key';generate_client_identity(private,tmp_path/'pub')
    load_client_private(private);private.chmod(0o620)
    with pytest.raises(ValueError):load_client_private(private)


@pytest.fixture
def db(tmp_path):
    private,public=tmp_path/'key',tmp_path/'pub';generate_client_identity(private,public)
    db=AuthorizedClients(tmp_path/'clients.json');db.authorize(public.read_bytes(),'alice','10.8.0.2')
    return db


@pytest.mark.parametrize('case', ['shape','fingerprint','key','duplicate','client_id','static','network','broadcast','server','outside','json_duplicate'])
def test_database_rejects_malformed_and_conflicting(db, case):
    data=json.loads(db.path.read_text());record=data['clients'][0]
    if case=='shape': data={'clients':{}}
    elif case=='fingerprint':record['fingerprint']='0'*64
    elif case=='key':record['public_key']=base64.b64encode(b'x').decode()
    elif case=='duplicate':data['clients'].append(dict(record))
    elif case in ('static','client_id'):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from vpn.identity import fingerprint
        key=Ed25519PrivateKey.generate().public_key().public_bytes_raw()
        second={**record,'public_key':base64.b64encode(key).decode(),'fingerprint':fingerprint(key)}
        second['client_id']='bob' if case=='static' else 'alice';second['assigned_ip']='10.8.0.2' if case=='static' else '10.8.0.3'
        data['clients'].append(second)
    else: record['assigned_ip']={'network':'10.8.0.0','broadcast':'10.8.0.255','server':'10.8.0.1','outside':'10.9.0.2','json_duplicate':'10.8.0.2'}[case]
    db.path.write_text('{"clients":[],"clients":[]}' if case=='json_duplicate' else json.dumps(data))
    with pytest.raises(ValueError):db._load(required=True,subnet='10.8.0.0/24',server_ip='10.8.0.1')


def test_concurrent_database_updates_are_not_lost(db):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    keys=[Ed25519PrivateKey.generate().public_key().public_bytes_raw() for _ in range(12)]
    with ThreadPoolExecutor(max_workers=6) as pool:
        list(pool.map(lambda pair: AuthorizedClients(db.path).authorize(pair[1],f'client{pair[0]}'),enumerate(keys)))
    assert len(db._load()['clients'])==13
    assert db.path.stat().st_mode & 0o777 == 0o600
    assert db.revoke(db._load()['clients'][0]['fingerprint'])


def test_subnet_collision_detection():
    assert overlapping_routes([{'dst':'10.8.0.0/16','dev':'docker0'}],'10.8.0.0/24')
    assert not overlapping_routes([{'dst':'default','gateway':'10.8.0.1'},{'dst':'192.168.0.0/24'}],'10.8.0.0/24')


def test_session_clock_is_monotonic(monkeypatch):
    monkeypatch.setattr(runtime.time,'time',lambda:-10**12)
    item=runtime.ServerSession(Mock(), '10.8.0.2', Mock(), 'alice')
    before=item.last_seen
    monkeypatch.setattr(runtime.time,'time',lambda:10**12)
    item.touch()
    assert 0 <= item.last_seen-before < 1 and abs(item.created-item.last_seen)<1


def test_static_leases_are_reserved_from_dynamic_allocations():
    pool=runtime.IPPool('10.8.0.0/29','10.8.0.1')
    pool.reserved={'10.8.0.2':'static'}
    assert pool.allocate('dynamic')=='10.8.0.3'
    assert pool.allocate('static','10.8.0.2')=='10.8.0.2'
