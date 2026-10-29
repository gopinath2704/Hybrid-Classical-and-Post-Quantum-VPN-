"""Known-answer vectors for the Rust core, generated from the Python record layer.

Regenerate with: PYTHONPATH=. python tests/test_rust_core.py
"""
import collections
import hashlib
import ipaddress
import json
import random
import struct
from dataclasses import fields
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from handshake.kemtls import (DATA_HEADER_FORMAT, DATA_HEADER_SIZE, DATA_MAGIC, MAX_SEQUENCE, Channel, FrameType,
                              HandshakeError, HandshakeSession, TrafficSecrets)
from vpn.runtime import validate_client_packet

VECTORS = Path(__file__).parent / "vectors" / "frame_encrypt.json"
DECRYPT_VECTORS = Path(__file__).parent / "vectors" / "frame_decrypt.json"
# Python rejection message -> stable kind shared with pqvpn_core's ValueError text.
KINDS = {
    "Frame too short": "short", "invalid record protocol or channel": "header", "invalid frame type": "frame_type",
    "wrong session, epoch, or direction": "binding", "replayed packet": "replayed",
    "packet is outside replay window": "outside_window", "Frame decryption failed": "tag",
    "control frame type requires encrypt_control": "control_type", "sequence exhausted; rekey required": "exhausted",
}
SEQUENCES = (0, (1 << 32) + 5, MAX_SEQUENCE - 1)


def _fixed(label: str, size: int) -> bytearray:
    return bytearray(hashlib.sha256(b"pqvpn kat " + label.encode()).digest()[:size])


def build_vectors() -> list[dict]:
    secrets = TrafficSecrets(**{f.name: _fixed(f.name, 12 if f.name.endswith("nonce_base") else 32) for f in fields(TrafficSecrets)})
    vectors = []
    for role, direction in (("client", "c2s"), ("server", "s2c")):
        for channel, frame_type in (("data", FrameType.DATA), ("control", FrameType.REKEY_REQUEST)):
            for sequence in SEQUENCES:
                session = HandshakeSession(bytes(_fixed("session id", 32)), secrets, b"c" * 32, b"s" * 32, role, epoch=7)
                setattr(session, f"_{channel}_send_sequence", sequence)
                plaintext = f"{role} {channel} {sequence}".encode() * 3
                frame = session.encrypt_frame(plaintext) if channel == "data" else session.encrypt_control(plaintext, frame_type)
                vectors.append({
                    "name": f"{direction}-{channel}-{sequence}",
                    "key": getattr(secrets, f"{channel}_{direction}_key").hex(),
                    "nonce_base": getattr(secrets, f"{channel}_{direction}_nonce_base").hex(),
                    "header": frame[:DATA_HEADER_SIZE].hex(),
                    "sequence": sequence,
                    "plaintext": plaintext.hex(),
                    "frame": frame.hex(),
                })
    return vectors


def test_vectors_match_python_record_layer():
    assert json.loads(VECTORS.read_text()) == build_vectors()


def _direction(role: str) -> str:
    return "c2s" if role == "client" else "s2c"


def forge(sender: HandshakeSession, sequence: int, frame_type: FrameType, payload: bytes) -> bytes:
    """Seal a DATA-channel frame at any sequence without touching the sender's counter or guard."""
    key = getattr(sender.secrets, f"data_{_direction(sender.role)}_key")
    base = getattr(sender.secrets, f"data_{_direction(sender.role)}_nonce_base")
    head = struct.pack(DATA_HEADER_FORMAT, DATA_MAGIC, sender.protocol_version, Channel.DATA, frame_type,
                       sender.send_direction, sender.session_id[:8], sender.epoch, sequence)
    return head + AESGCM(bytes(key)).encrypt(sender._nonce(base, sequence), payload, head)


def py_outcome(call) -> dict:
    try:
        frame_type, data = call()
    except HandshakeError as exc:
        return {"expect": KINDS[str(exc)]}
    return {"expect": "ok", "frame_type": int(frame_type), "plaintext": data.hex()}


def _sessions(secrets: TrafficSecrets, session_id: bytes, version: int, epoch: int) -> dict[str, HandshakeSession]:
    return {role: HandshakeSession(session_id, secrets, b"c" * 32, b"s" * 32, role, epoch=epoch, protocol_version=version)
            for role in ("client", "server")}


def _keys(secrets: TrafficSecrets, role: str) -> dict[str, str]:
    send, recv = _direction(role), _direction("server" if role == "client" else "client")
    return {"send_key": getattr(secrets, f"data_{send}_key").hex(), "send_nonce_base": getattr(secrets, f"data_{send}_nonce_base").hex(),
            "recv_key": getattr(secrets, f"data_{recv}_key").hex(), "recv_nonce_base": getattr(secrets, f"data_{recv}_nonce_base").hex()}


def _edit(frame: bytes, index: int, value: int) -> bytes:
    edited = bytearray(frame)
    edited[index] = value
    return bytes(edited)


def build_decrypt_vectors() -> list[dict]:
    secrets = TrafficSecrets(**{f.name: _fixed(f.name, 12 if f.name.endswith("nonce_base") else 32) for f in fields(TrafficSecrets)})
    session_id = bytes(_fixed("session id", 32))
    scripts = []
    for version in (0x20, 0x30):
        for receiver in ("server", "client"):
            peers = _sessions(secrets, session_id, version, epoch=7)
            rx, tx = peers[receiver], peers["client" if receiver == "server" else "server"]
            bind, keepalive = ((FrameType.UDP_BIND, FrameType.PING) if receiver == "server"
                               else (FrameType.UDP_BIND_ACK, FrameType.PONG))
            def at(sequence, payload=b"x", frame_type=FrameType.DATA):
                return forge(tx, sequence, frame_type, payload)
            ops = [("data-0", at(0, b"zero")), ("replay-0", at(0, b"zero")), ("bind-1", at(1, b"bind", bind)),
                   ("keepalive-2", at(2, b"\0" * 8, keepalive)), ("empty-3", at(3, b"")),
                   ("large-4", at(4, bytes(range(256)) * 6)), ("bad-tag-5", _edit(at(5), -1, at(5)[-1] ^ 1)),
                   ("data-5-after-bad-tag", at(5, b"five")),
                   ("aad-type-changed", _edit(at(6), 4, int(keepalive))),
                   ("wrong-epoch", _edit(at(6), 17, 8)), ("wrong-direction", _edit(at(6), 5, int(rx.send_direction))),
                   ("wrong-session", _edit(at(6), 6, at(6)[6] ^ 1)), ("control-channel", _edit(at(6), 3, int(Channel.CONTROL))),
                   ("wrong-version", _edit(at(6), 2, version ^ 1)), ("bad-magic", _edit(at(6), 0, 0)),
                   ("bad-type-99", _edit(at(6), 4, 99)), ("short-41", at(6, b"")[:41]),
                   ("forged-1000-bad-tag", _edit(at(1000), -1, at(1000)[-1] ^ 1)), ("data-8", at(8, b"eight")),
                   ("window-200", at(200)), ("edge-73", at(200 - 127)), ("outside-72", at(200 - 128)),
                   ("jump-10000", at(10_000)), ("stale-200", at(200)), ("edge-9873", at(10_000 - 127)),
                   ("replay-9873", at(10_000 - 127)), ("outside-9872", at(10_000 - 128)),
                   ("top-minus-1", at(MAX_SEQUENCE - 1, b"top")), ("top", at(MAX_SEQUENCE, b"top")),
                   ("replay-top", at(MAX_SEQUENCE, b"top"))]
            scripts.append({
                "name": f"v{version:#x}-{receiver}-receives", "role": receiver, "session_id": session_id.hex(),
                "protocol_version": version, "epoch": 7, **_keys(secrets, receiver),
                "ops": [{"name": name, "frame": frame.hex(), **py_outcome(lambda f=frame: rx.decrypt_frame(f))} for name, frame in ops],
            })
    return scripts


def test_decrypt_vectors_match_python_record_layer():
    assert json.loads(DECRYPT_VECTORS.read_text()) == build_decrypt_vectors()


@pytest.fixture
def core(backend):
    if backend == "rust":
        import pqvpn_core
        return pqvpn_core
    return pytest.importorskip("pqvpn_core", reason="pqvpn_core not built; run maturin develop -m core/pqvpn_core/Cargo.toml")


def test_rust_encrypt_frame_matches_vectors(core):
    for v in json.loads(VECTORS.read_text()):
        header = bytes.fromhex(v["header"])
        ciphertext = core.encrypt_frame(bytes.fromhex(v["key"]), bytes.fromhex(v["nonce_base"]), header, v["sequence"], bytes.fromhex(v["plaintext"]))
        assert header + ciphertext == bytes.fromhex(v["frame"]), v["name"]


@pytest.mark.parametrize("key, nonce, header, sequence", [
    (b"k" * 31, b"n" * 12, b"h" * 26, 0),
    (b"k" * 32, b"n" * 11, b"h" * 26, 0),
    (b"k" * 32, b"n" * 12, b"h" * 25, 0),
    (b"k" * 32, b"n" * 12, b"h" * 26, MAX_SEQUENCE),
])
def test_rust_encrypt_frame_rejects_bad_input(core, key, nonce, header, sequence):
    with pytest.raises(ValueError):
        core.encrypt_frame(key, nonce, header, sequence, b"payload")


def _rust_session(core, script: dict):
    return core.DataSession(script["role"], bytes.fromhex(script["session_id"]), script["protocol_version"], script["epoch"],
                            *(bytes.fromhex(script[k]) for k in ("send_key", "send_nonce_base", "recv_key", "recv_nonce_base")))


def rust_outcome(call) -> dict:
    try:
        frame_type, data = call()
    except ValueError as exc:
        return {"expect": str(exc)}
    return {"expect": "ok", "frame_type": frame_type, "plaintext": data.hex()}


def test_rust_decrypt_vectors(core):
    for script in json.loads(DECRYPT_VECTORS.read_text()):
        rx = _rust_session(core, script)
        for op in script["ops"]:
            expected = {k: op[k] for k in ("expect", "frame_type", "plaintext") if k in op}
            assert rust_outcome(lambda: rx.open(bytes.fromhex(op["frame"]))) == expected, (script["name"], op["name"])


def run_differential(core, scripts: int = 10_000, ops: int = 20) -> collections.Counter:
    """Seeded op scripts: Python HandshakeSession and Rust DataSession must agree on every seal and open."""
    stats: collections.Counter = collections.Counter()
    for seed in range(scripts):
        rng = random.Random(seed)
        secrets = TrafficSecrets(**{f.name: bytearray(rng.randbytes(12 if f.name.endswith("nonce_base") else 32)) for f in fields(TrafficSecrets)})
        session_id, version, epoch = rng.randbytes(32), rng.choice((0x20, 0x30, 0x31)), rng.randrange(1 << 32)
        py = _sessions(secrets, session_id, version, epoch)
        rs = {role: _rust_session(core, {"role": role, "session_id": session_id.hex(), "protocol_version": version,
                                         "epoch": epoch, **_keys(secrets, role)}) for role in py}
        pool: list[bytes] = []
        for _ in range(ops):
            op, role = rng.choice(("seal", "seal", "deliver", "deliver", "tamper", "edit", "truncate", "forge")), rng.choice(("client", "server"))
            if op == "seal":
                frame_type, payload = rng.choice((1, 2, 3, 4, 5, 5, 7)), rng.randbytes(rng.choice((0, 8, 64, 1400)))
                py_result = py_outcome(lambda: (0, py[role].encrypt_frame(payload, FrameType(frame_type))))
                rs_result = rust_outcome(lambda: (0, rs[role].seal(frame_type, payload)))
                assert py_result == rs_result, (seed, op)
                stats[f"seal:{py_result['expect']}"] += 1
                if py_result["expect"] == "ok":
                    pool.append(bytes.fromhex(py_result["plaintext"]))
                continue
            if op == "forge":
                sender = py["client" if role == "server" else "server"]
                frame = forge(sender, rng.choice((rng.randrange(400), rng.randrange(1 << 64), MAX_SEQUENCE - rng.randrange(3))),
                              FrameType(rng.randrange(1, 14)), rng.randbytes(rng.randrange(64)))
            elif not pool:
                continue
            else:
                frame = rng.choice(pool)
                if op == "tamper":
                    frame = _edit(frame, rng.randrange(len(frame)), rng.randrange(256))
                elif op == "edit":
                    frame = _edit(frame, rng.choice((2, 3, 4, 5, 6, 14, 17)), rng.randrange(256))
                elif op == "truncate":
                    frame = frame[:rng.randrange(len(frame))]
            py_result = py_outcome(lambda: py[role].decrypt_frame(frame))
            assert py_result == rust_outcome(lambda: rs[role].open(frame)), (seed, op, role)
            stats[f"open:{py_result['expect']}"] += 1
    return stats


def test_rust_differential_against_python(core):
    stats = run_differential(core)
    for kind in ("ok", "replayed", "outside_window", "tag", "binding", "header", "frame_type", "short"):
        assert stats[f"open:{kind}"] > 0, (kind, stats)
    assert stats["seal:ok"] > 0 and stats["seal:control_type"] > 0, stats


def _ipv4(source: str, destination: str, payload: bytes = b"", total: int | None = None, first: int = 0x45) -> bytes:
    length = 20 + len(payload) if total is None else total
    return (bytes([first, 0]) + struct.pack("!H", length) + bytes(8) + ipaddress.IPv4Address(source).packed
            + ipaddress.IPv4Address(destination).packed + payload)


def test_rust_inbound_checks_match_python(core):
    rng, lease, mtu = random.Random(0), "10.8.0.2", 1380
    for _ in range(5000):
        packet = _ipv4(rng.choice((lease, "10.8.0.3")), rng.choice((lease, "1.1.1.1")), rng.randbytes(rng.choice((0, 40, 1400))),
                       total=rng.choice((None, None, 19, 30)), first=rng.choice((0x45, 0x45, 0x46, 0x44, 0x60)))
        packet = packet[:rng.choice((len(packet), len(packet), rng.randrange(len(packet) + 1)))]
        python_server = len(packet) <= mtu and validate_client_packet(packet, lease)
        python_client = (len(packet) <= mtu and len(packet) >= 20 and validate_client_packet(packet, str(ipaddress.IPv4Address(packet[12:16])))
                         and packet[16:20] == ipaddress.IPv4Address(lease).packed)
        assert core.inbound_ok("server", packet, ipaddress.IPv4Address(lease).packed, mtu) == python_server
        assert core.inbound_ok("client", packet, ipaddress.IPv4Address(lease).packed, mtu) == python_client


if __name__ == "__main__":
    VECTORS.parent.mkdir(exist_ok=True)
    VECTORS.write_text(json.dumps(build_vectors(), indent=1) + "\n")
    DECRYPT_VECTORS.write_text(json.dumps(build_decrypt_vectors(), indent=1) + "\n")


@pytest.mark.parametrize("client_plane, server_plane", [("python", "rust"), ("rust", "python")])
@pytest.mark.parametrize("suite", ["v2", "v3-kem", "v3-mldsa"])
def test_mixed_data_planes_interoperate_across_rekey(core, request, suite, client_plane, server_plane):
    from test_crypto_protocol import exchange, exchange_mldsa, exchange_v3
    make, ids = {"v2": (exchange, "identities"), "v3-kem": (exchange_v3, "v3_identities"),
                 "v3-mldsa": (exchange_mldsa, "mldsa_identities")}[suite]
    client, server = make(request.getfixturevalue(ids), data_plane=client_plane, server_plane=server_plane)
    for epoch in (0, 1):
        assert server.open_data(client.seal_data(b"up"))[1] == b"up"
        assert client.open_data(server.seal_data(b"down", FrameType.PONG), FrameType.PONG)[1] == b"down"
        if epoch == 0:
            old, nonce = client.seal_data(b"stale"), bytes(32)
            client.activate_epoch(1, client.derive_next_epoch(1, nonce))
            server.activate_epoch(1, server.derive_next_epoch(1, nonce))
    with pytest.raises(HandshakeError, match="wrong session, epoch, or direction"):
        server.open_data(old)


def test_rust_mode_python_never_holds_data_ciphers(core, identities):
    from test_crypto_protocol import exchange
    client, server = exchange(identities, data_plane="rust")
    for session in (client, server):
        assert not hasattr(session, "_data_send_cipher") and not hasattr(session, "_data_recv_cipher")
        assert all(not any(getattr(session.secrets, name)) for name in
                   ("data_c2s_key", "data_s2c_key", "data_c2s_nonce_base", "data_s2c_nonce_base"))
        with pytest.raises(HandshakeError, match="owned by the Rust data plane"):
            session.encrypt_frame(b"x")
        with pytest.raises(HandshakeError, match="owned by the Rust data plane"):
            session.decrypt_frame(b"x" * 64)
    frame = client.seal_data(b"x")
    server.secure_wipe()
    with pytest.raises(HandshakeError, match="session closed"):
        server.open_data(frame)
    with pytest.raises(HandshakeError, match="session closed"):
        server.derive_next_epoch(1, bytes(32))


def test_rust_mode_fails_loudly_without_pqvpn_core(identities, monkeypatch):
    import sys
    from test_crypto_protocol import exchange
    from vpn.config import ServerConfig, validate_server
    # None in sys.modules makes every import style (statement or importlib) raise ImportError.
    monkeypatch.setitem(sys.modules, "pqvpn_core", None)
    with pytest.raises(ImportError, match="pqvpn_core"):
        exchange(identities, data_plane="rust")
    with pytest.raises(ValueError, match="requires the pqvpn_core module"):
        validate_server(ServerConfig(data_plane="rust"))


def test_data_plane_owns_both_descriptors_or_neither():
    import os
    import socket
    from vpn.network import TUNInterface, TUNMode
    from vpn.runtime import rust_data_plane
    pqvpn_core = pytest.importorskip("pqvpn_core")
    udp, stream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM), socket.socketpair()[0]
    udp_fd, stream_fd = os.dup(udp.fileno()), os.dup(stream.fileno())
    with pytest.raises(OSError, match="EmulatedTun"):
        pqvpn_core.DataPlane("server", udp_fd, stream_fd, 1380, emulated_tun=True)
    os.close(udp_fd)  # rejected: both are still ours
    os.close(stream_fd)
    with TUNInterface(mode=TUNMode.SOCKET_PIPE) as tun:
        before = set(os.listdir("/proc/self/fd"))
        with pytest.raises(ValueError, match="role"):
            rust_data_plane("relay", udp, tun, 1380)
        with pytest.raises(ValueError, match="peer and ping"):
            rust_data_plane("client", udp, tun, 1380)
        assert set(os.listdir("/proc/self/fd")) == before  # rust_data_plane closed its dups
        dp = rust_data_plane("server", udp, tun, 1380)
        dp.start()
        dp.stop()
        assert set(os.listdir("/proc/self/fd")) == before  # the worker closed the ones it owned
    udp.close()
    stream.close()
