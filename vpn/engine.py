"""Small Linux TUN and authenticated-path telemetry primitives."""
from __future__ import annotations
import enum,os,socket,statistics,struct,sys,time
from collections import deque
from dataclasses import dataclass,field
from typing import Optional
from handshake.kemtls import DATA_FRAME_OVERHEAD
_TUNSETIFF=0x400454CA;_IFF_TUN=1;_IFF_NO_PI=0x1000;_TUN_READ_BUFFER=65535
class TUNMode(enum.Enum):NATIVE="native";SOCKET_PIPE="socket_pipe"
@dataclass
class TUNInterface:
    name:str="pqvpn0";mtu:int=1380;mode:TUNMode=TUNMode.NATIVE;is_open:bool=False
    _fd:Optional[int]=field(default=None,repr=False);_sock_local:Optional[socket.socket]=field(default=None,repr=False);_sock_remote:Optional[socket.socket]=field(default=None,repr=False)
    def open(self):
        if self.is_open:raise RuntimeError("TUN interface is already open")
        if self.mode==TUNMode.NATIVE:
            if sys.platform!="linux":raise OSError("native TUN is Linux-only")
            import fcntl
            fd=os.open("/dev/net/tun",os.O_RDWR)
            try:fcntl.ioctl(fd,_TUNSETIFF,struct.pack("16sH",self.name.encode(),_IFF_TUN|_IFF_NO_PI))
            except Exception:os.close(fd);raise
            self._fd=fd
        else:
            self._sock_local,self._sock_remote=socket.socketpair(socket.AF_UNIX,socket.SOCK_DGRAM);self._sock_local.setblocking(False);self._sock_remote.setblocking(False)
        self.is_open=True
    def read(self,size=_TUN_READ_BUFFER):
        if not self.is_open:raise RuntimeError("TUN interface is not open")
        return os.read(self._fd,size) if self.mode==TUNMode.NATIVE else self._sock_local.recv(size)
    def write(self,packet):
        if not self.is_open:raise RuntimeError("TUN interface is not open")
        return os.write(self._fd,packet) if self.mode==TUNMode.NATIVE else self._sock_local.send(packet)
    def inject(self,packet):
        if self.mode!=TUNMode.SOCKET_PIPE or not self.is_open:raise RuntimeError("inject requires an open SOCKET_PIPE")
        return self._sock_remote.send(packet)
    def drain(self,size=_TUN_READ_BUFFER):
        if self.mode!=TUNMode.SOCKET_PIPE or not self.is_open:raise RuntimeError("drain requires an open SOCKET_PIPE")
        return self._sock_remote.recv(size)
    def fileno(self):
        if not self.is_open:raise RuntimeError("TUN interface is not open")
        return self._fd if self.mode==TUNMode.NATIVE else self._sock_local.fileno()
    def close(self):
        if not self.is_open:return
        if self._fd is not None:os.close(self._fd);self._fd=None
        for name in ("_sock_local","_sock_remote"):
            value=getattr(self,name)
            if value:value.close();setattr(self,name,None)
        self.is_open=False
    def get_info(self):return {"name":self.name,"mtu":self.mtu,"mode":self.mode.value,"is_open":self.is_open}
    def __enter__(self):self.open();return self
    def __exit__(self,*_):self.close()

DEFAULT_MTU=1500;MIN_MTU=1280;IPV4_HEADER_SIZE=20;IPV6_HEADER_SIZE=40;UDP_HEADER_SIZE=8;TCP_HEADER_SIZE=20
VPN_TOTAL_OVERHEAD=DATA_FRAME_OVERHEAD
# Compatibility constants for the benchmark reporter. Data records transmit no nonce or length prefix.
FRAME_OVERHEAD_NONCE=0;FRAME_OVERHEAD_TAG=16;FRAME_OVERHEAD_TOTAL=DATA_FRAME_OVERHEAD;VPN_LENGTH_PREFIX=0
class MTUMonitor:
    def __init__(self,path_mtu=DEFAULT_MTU):self._path_mtu=path_mtu;self._history=[(time.time(),path_mtu)]
    @property
    def path_mtu(self):return self._path_mtu
    def update_mtu(self,value):
        if value<MIN_MTU:raise ValueError("MTU below supported minimum")
        self._path_mtu=value;self._history.append((time.time(),value))
    def total_overhead(self,ipv6=False):return (IPV6_HEADER_SIZE if ipv6 else IPV4_HEADER_SIZE)+UDP_HEADER_SIZE+DATA_FRAME_OVERHEAD
    def max_payload_size(self,ipv6=False):return self.path_mtu-self.total_overhead(ipv6)
    def tcp_mss_clamp(self,ipv6=False):return self.max_payload_size(ipv6)-(40 if ipv6 else 40)
    @property
    def mtu_history(self):return list(self._history)
    def get_info(self):
        return {"path_mtu":self.path_mtu,"max_payload_ipv4":self.max_payload_size(False),"max_payload_ipv6":self.max_payload_size(True),"tcp_mss_ipv4":self.tcp_mss_clamp(False),"tcp_mss_ipv6":self.tcp_mss_clamp(True),"total_overhead_ipv4":self.total_overhead(False),"total_overhead_ipv6":self.total_overhead(True),"history_count":len(self._history)}

@dataclass
class QualitySnapshot:
    timestamp:float;rtt_ms:float;jitter_ms:float;loss_rate:float;probes_sent:int;probes_received:int
    def to_dict(self):return {"timestamp":round(self.timestamp,3),"rtt_ms":round(self.rtt_ms,3),"jitter_ms":round(self.jitter_ms,3),"loss_rate":round(self.loss_rate,4),"probes_sent":self.probes_sent,"probes_received":self.probes_received}
class NetworkQualityMonitor:
    def __init__(self,window_size=100):self._window_size=window_size;self.samples=deque(maxlen=window_size);self._jitter=0.;self._last=None;self.sent=0;self.received=0;self.lost=0
    @property
    def window_size(self):return self._window_size
    @property
    def rtt_samples(self):return list(self.samples)
    @property
    def avg_rtt(self):return statistics.mean(self.samples) if self.samples else 0.
    @property
    def min_rtt(self):return min(self.samples) if self.samples else 0.
    @property
    def max_rtt(self):return max(self.samples) if self.samples else 0.
    @property
    def jitter(self):return self._jitter
    @property
    def loss_rate(self):return self.lost/self.sent if self.sent else 0.
    def record_probe_sent(self):self.sent+=1
    def record_rtt(self,value):
        if value<0:raise ValueError("RTT cannot be negative")
        self.samples.append(value);self.received+=1
        if self._last is not None:self._jitter+=(abs(value-self._last)-self._jitter)/16
        self._last=value
    def record_loss(self):self.lost+=1
    def snapshot(self):return QualitySnapshot(time.time(),statistics.mean(self.samples) if self.samples else 0.,self._jitter,self.lost/self.sent if self.sent else 0.,self.sent,self.received)
    def reset(self):self.samples.clear();self._jitter=0.;self._last=None;self.sent=0;self.received=0;self.lost=0
    def get_info(self):return {"window_size":self.window_size,"sample_count":len(self.samples),"avg_rtt_ms":round(self.avg_rtt,3),"min_rtt_ms":round(self.min_rtt,3),"max_rtt_ms":round(self.max_rtt,3),"jitter_ms":round(self.jitter,3),"loss_rate":round(self.loss_rate,4),"probes_sent":self.sent,"probes_received":self.received}
