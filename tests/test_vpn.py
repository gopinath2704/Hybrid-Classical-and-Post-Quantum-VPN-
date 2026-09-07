"""Relevant TUN, MTU and authenticated-path quality tests restored for v2."""
import os,time
import pytest
from vpn.engine import *

def open_pipe():
    tun=TUNInterface(name="test0",mode=TUNMode.SOCKET_PIPE)
    try:tun.open()
    except PermissionError:pytest.skip("sandbox denies AF_UNIX socketpair")
    return tun
def test_tun_defaults_and_metadata():
    tun=TUNInterface();assert tun.name=="pqvpn0" and not tun.is_open
    custom=TUNInterface("x",1400,TUNMode.SOCKET_PIPE);assert custom.get_info()["mtu"]==1400
def test_tun_lifecycle_and_roundtrip():
    tun=open_pipe()
    try:
        with pytest.raises(RuntimeError):tun.open()
        packet=os.urandom(64)
        try:tun.inject(packet)
        except PermissionError:pytest.skip("sandbox denies socketpair traffic")
        assert tun.read()==packet;tun.write(packet);assert tun.drain()==packet
    finally:tun.close();tun.close()
def test_closed_tun_errors():
    tun=TUNInterface(mode=TUNMode.SOCKET_PIPE)
    with pytest.raises(RuntimeError):tun.read()
    with pytest.raises(RuntimeError):tun.write(b"x")
    with pytest.raises(RuntimeError):tun.fileno()
@pytest.mark.parametrize("path,ipv6,expected",[(1500,False,1430),(1400,False,1330),(1280,False,1210),(1500,True,1410)])
def test_exact_mtu_calculation(path,ipv6,expected):assert MTUMonitor(path).max_payload_size(ipv6)==expected
def test_mtu_update_history_and_minimum():
    monitor=MTUMonitor();monitor.update_mtu(1400);assert monitor.path_mtu==1400 and len(monitor.mtu_history)==2
    with pytest.raises(ValueError):monitor.update_mtu(1200)
def test_quality_metrics_jitter_loss_reset():
    monitor=NetworkQualityMonitor(10)
    for value in (10.,20.,10.):monitor.record_probe_sent();monitor.record_rtt(value)
    monitor.record_probe_sent();monitor.record_loss();snapshot=monitor.snapshot()
    assert snapshot.rtt_ms>0 and snapshot.jitter_ms>0 and snapshot.loss_rate==.25
    monitor.reset();assert monitor.avg_rtt==monitor.loss_rate==0
def test_quality_rolling_window():
    monitor=NetworkQualityMonitor(3)
    for i in range(5):monitor.record_rtt(float(i))
    assert monitor.rtt_samples==[2.,3.,4.]
