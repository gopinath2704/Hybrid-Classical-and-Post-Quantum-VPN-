"""pqvpnd against the real Python VPNServer, in a throwaway network namespace (run by tests/conformance.rs
under `unshare -rn`). Per protocol version: a full handshake with cookie_mode = "always", data both ways
through the native TUN, automatic rekey and rehandshake, a clean SIGTERM teardown (routes identical, TUN
gone, server session closed), then a second connect that must resume from the ticket pqvpnd saved.

usage: conformance.py PQVPND REPO SERVER_HANDSHAKE SERVER_DATA_PLANE VERSIONS(comma list)
"""
import ipaddress
import os
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

PQVPND, REPO, SERVER_HANDSHAKE, SERVER_PLANE = sys.argv[1:5]
VERSIONS = [int(v) for v in sys.argv[5].split(",")]
sys.path.insert(0, REPO)

import vpn.runtime as runtime  # noqa: E402
from vpn.config import ServerConfig  # noqa: E402
from vpn.identity import (AuthorizedClients, generate_client_identity, generate_client_identity_kem,  # noqa: E402
                          generate_server_identity)

SERVER = "192.0.2.1"
TUN = "pqconf0"


def ip(*args: str) -> str:
    return subprocess.run(["ip", *args], check=True, capture_output=True, text=True).stdout


def until(predicate, timeout: float, what: str) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.05)
    raise AssertionError(f"timed out waiting for {what}")


def checksum(header: bytes) -> int:
    total = sum(struct.unpack(f"!{len(header) // 2}H", header))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def udp_packet(source: str, destination: str, port: int, payload: bytes) -> bytes:
    """IPv4/UDP with a valid header checksum (the kernel checks it on TUN input); UDP checksum 0 is allowed."""
    udp = struct.pack("!HHHH", 40000, port, 8 + len(payload), 0) + payload
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0x4000, 64, 17, 0,
                         ipaddress.IPv4Address(source).packed, ipaddress.IPv4Address(destination).packed)
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return header + udp


def data_both_ways(server: runtime.VPNServer, client_ip: str, tag: bytes) -> None:
    # Server -> client: an inner packet injected into the server's (emulated) TUN reaches a local socket here.
    receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    receiver.bind((client_ip, 0))
    receiver.settimeout(5)
    server.tun.inject(udp_packet("10.8.0.1", client_ip, receiver.getsockname()[1], b"down " + tag))
    assert receiver.recv(2048) == b"down " + tag, "server -> client through pqvpnd"
    receiver.close()
    # Client -> server: a datagram routed into pqvpnd's TUN comes out of the server's TUN.
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sender.sendto(b"up " + tag, ("10.8.0.1", 9))
    sender.close()
    server.tun._sock_remote.settimeout(5)
    while True:
        packet = server.tun.drain()
        if packet.endswith(b"up " + tag):
            assert packet[12:16] == ipaddress.IPv4Address(client_ip).packed, "inner source is the lease"
            return


def start_pqvpnd(config: Path) -> tuple[subprocess.Popen, str]:
    process = subprocess.Popen([PQVPND, "connect", "--config", str(config)], stdout=subprocess.PIPE, stderr=sys.stderr, text=True)
    line = process.stdout.readline()
    if not line.startswith("connected "):
        process.kill()
        raise AssertionError(f"pqvpnd did not connect: {line!r}, exit {process.wait()}")
    return process, line.split()[1]


def stop_pqvpnd(process: subprocess.Popen) -> None:
    process.send_signal(signal.SIGTERM)
    assert process.wait(10) == 0, "clean exit on SIGTERM"


def run_version(version: int, work: Path) -> None:
    label = f"v{version} server handshake={SERVER_HANDSHAKE} data_plane={SERVER_PLANE}"
    (work / "client").mkdir()
    fp = generate_server_identity(work / "server.key", work / "server.pub")
    (generate_client_identity_kem if version == 3 else generate_client_identity)(work / "client/client.key", work / "client/client.pub")
    AuthorizedClients(work / "clients.json").authorize((work / "client/client.pub").read_bytes(), "native")
    resumed = []
    real_hello = runtime.ResumptionServerHandshake.process_hello

    def spy(self, wire):
        out = real_hello(self, wire)
        resumed.append(True)
        return out
    runtime.ResumptionServerHandshake.process_hello = spy
    server = runtime.VPNServer(ServerConfig(listen_host=SERVER, control_port=0, udp_port=0, protocol_version=version,
        server_identity_private_key=str(work / "server.key"), server_identity_public_key=str(work / "server.pub"),
        authorized_clients_file=str(work / "clients.json"), dev_emulated_tun=True, dns_servers=[], cookie_mode="always",
        rekey_interval=2, rehandshake_interval=3, idle_timeout=60, data_plane=SERVER_PLANE, handshake=SERVER_HANDSHAKE))
    worker = threading.Thread(target=server.start, daemon=True)
    worker.start()
    until(lambda: server.tcp is not None and server.udp is not None, 10, "server")
    server.cfg.udp_port = server.udp.getsockname()[1]
    config = work / "client/client.toml"
    config.write_text(f'[client]\nserver_host = "{SERVER}"\nserver_control_port = {server.tcp.getsockname()[1]}\n'
                      f'server_identity_fingerprint = "{fp}"\nserver_identity_public_key = "../server.pub"\n'
                      f'client_identity_private_key = "client.key"\nclient_identity_public_key = "client.pub"\n'
                      f'protocol_version = {version}\nfull_tunnel = false\ndns_mode = "none"\ndns_servers = []\n'
                      f'tun_name = "{TUN}"\ndata_plane = "rust"\nhandshake = "rust"\nping_interval = 0.5\n')
    before = ip("route", "show", "table", "all")
    try:
        # 1. Full handshake (cookie always), data, rekey and rehandshake, SIGTERM teardown.
        process, client_ip = start_pqvpnd(config)
        assert resumed == [], "first connect is a full handshake"
        assert (work / "client/.pqvpn_ticket.json").exists(), "pqvpnd saved the resumption ticket"
        data_both_ways(server, client_ip, b"epoch0")
        item = next(iter(server.sessions.by_id.values()))
        until(lambda: item.crypto.epoch >= 2, 15, "a rekey and a rehandshake")
        data_both_ways(server, client_ip, b"rotated")
        stop_pqvpnd(process)
        until(lambda: not server.sessions.by_id, 5, "server session closed")
        assert ip("route", "show", "table", "all") == before, "every route restored"
        assert subprocess.run(["ip", "link", "show", "dev", TUN], capture_output=True).returncode != 0, "TUN gone"
        # 2. Resumption from the ticket pqvpnd wrote, then data and teardown again.
        process, client_ip = start_pqvpnd(config)
        assert resumed == [True], "second connect resumed from the ticket"
        data_both_ways(server, client_ip, b"resumed")
        stop_pqvpnd(process)
        until(lambda: not server.sessions.by_id, 5, "server session closed")
        assert ip("route", "show", "table", "all") == before, "every route restored after resume"
        print(f"ok {label}: cookie, full, data, rekey+rehandshake (epoch {item.crypto.epoch}), SIGTERM, resume", flush=True)
    finally:
        runtime.ResumptionServerHandshake.process_hello = real_hello
        server.stop()
        worker.join(5)


def main() -> None:
    ip("link", "set", "lo", "up")
    ip("link", "add", "pqconfup", "type", "dummy")
    ip("addr", "add", f"{SERVER}/24", "dev", "pqconfup")
    ip("link", "set", "pqconfup", "up")
    for version in VERSIONS:
        with tempfile.TemporaryDirectory(prefix=f"pqvpnd-conf-v{version}-") as work:
            run_version(version, Path(work))


if __name__ == "__main__":
    main()
