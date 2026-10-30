"""Handshake known-answer vectors for the Rust core, recorded from the Python handshake.

Every random draw of a normal run is recorded, in call order, per protocol step. pqvpn_core's test-only
`Replay` feeds the same draws to Rust, which must reproduce every wire message, transcript and secret byte
for byte. The test below replays the draws through Python, so the file stays tied to the current Python code.
Rekey and rehandshake mirror VPNClient.rekey/rehandshake and VPNServer._rekey_server/_rehandshake_server.

Regenerate with: PYTHONPATH=. python tests/test_handshake_vectors.py
"""
import contextlib
import hashlib
import hmac
import json
import os
import struct
import time
from dataclasses import fields
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import handshake.kemtls as kemtls
from crypto.hybrid_crypto import ECCProvider, HybridKEM, PQCProvider
from handshake.kemtls import (PROTOCOL_VERSION, PROTOCOL_VERSION_V3, ClientHello, ClientHelloV3, ClientKeyExchange,
                              ClientKeyExchangeV3, FrameType, HandshakeError, KEMTLSClient, KEMTLSClientV3,
                              KEMTLSServer, KEMTLSServerV3, ResumptionAccept, ResumptionClientHandshake, ResumptionHello,
                              ResumptionServerHandshake, ResumptionTicketKey, ServerFinished, ServerFinishedV3,
                              ServerHello, ServerHelloV3, TrafficSecrets, unpack_cookie_challenge)
from vpn.identity import fingerprint, verify_client_signature

VECTORS = Path(__file__).parent / "vectors" / "handshake.json"
NOW = 1_800_000_000
CONFIG = b'{"client_vpn_ip": "10.8.0.2", "vector": true}'
_urandom = os.urandom
_x25519 = ECCProvider.generate_keypair
_mlkem_keypair = PQCProvider.generate_keypair
_encapsulate = PQCProvider.encapsulate


class Draws:
    """Records each step's draws, or replays recorded ones and checks kind, order and count."""

    def __init__(self, recorded: list[dict] | None = None) -> None:
        self.recorded = None if recorded is None else {step["name"]: step["draws"] for step in recorded}
        self.queue: list[dict] = []
        self.log: list[dict] = []

    @contextlib.contextmanager
    def step(self, steps: list[dict], name: str, role: str):
        self.queue, self.log = list(self.recorded[name]) if self.recorded else [], []
        entry = {"name": name, "role": role}
        yield entry
        assert not self.queue, f"{name}: {len(self.queue)} recorded draws not consumed"
        steps.append({**entry, "draws": self.log})

    def take(self, kind: str, make) -> dict:
        if self.recorded is not None:
            assert self.queue, f"Python drew an extra {kind}"
            draw = self.queue.pop(0)
            assert draw["kind"] == kind, f"expected a {kind} draw, recorded {draw['kind']}"
        else:
            draw = {"kind": kind, **make()}
        self.log.append(draw)
        return draw

    @contextlib.contextmanager
    def patched(self):
        def urandom(n: int) -> bytes:
            return bytes.fromhex(self.take("random", lambda: {"value": _urandom(n).hex()})["value"])

        def x25519(provider):
            def make():
                private, _ = _x25519(provider)
                return {"private": private.private_bytes_raw().hex()}
            private = X25519PrivateKey.from_private_bytes(bytes.fromhex(self.take("x25519", make)["private"]))
            return private, private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

        def mlkem_keypair(provider):
            def make():
                sk, pk = _mlkem_keypair(provider)
                return {"sk": sk.hex(), "pk": pk.hex()}
            draw = self.take("mlkem_keypair", make)
            return bytes.fromhex(draw["sk"]), bytes.fromhex(draw["pk"])

        def encapsulate(provider, pk: bytes):
            def make():
                ct, ss = _encapsulate(provider, pk)
                return {"ek_sha256": hashlib.sha256(pk).hexdigest(), "ct": ct.hex(), "ss": ss.hex()}
            draw = self.take("encapsulate", make)
            assert draw["ek_sha256"] == hashlib.sha256(pk).hexdigest(), "encapsulated to a different key"
            return bytes.fromhex(draw["ct"]), bytes.fromhex(draw["ss"])

        # kemtls only calls os.urandom and time.time; replacing its module references keeps other threads unaffected.
        with mock.patch.object(kemtls, "os", SimpleNamespace(urandom=urandom)), \
                mock.patch.object(kemtls, "time", SimpleNamespace(time=lambda: NOW, monotonic=time.monotonic)), \
                mock.patch.object(ECCProvider, "generate_keypair", x25519), \
                mock.patch.object(PQCProvider, "generate_keypair", mlkem_keypair), \
                mock.patch.object(PQCProvider, "encapsulate", encapsulate):
            yield


def _secrets(session) -> dict:
    return {f.name: bytes(getattr(session.secrets, f.name)).hex() for f in fields(TrafficSecrets)}


def _channel_and_epochs(run: dict, draws: Draws, client, server) -> None:
    """Control frames both ways, then rekey to epoch 1 and rehandshake to epoch 2 (runtime.py:576-611, 1087-1172)."""
    steps = run["steps"]
    run["control"] = {"config": server.encrypt_control(CONFIG, FrameType.CONFIG).hex(),
                      "client_error": client.encrypt_control(b"client says hi", FrameType.ERROR).hex(),
                      "second": server.encrypt_control(b"", FrameType.CLOSE).hex()}
    for name in ("config", "second"):
        assert client.decrypt_control(bytes.fromhex(run["control"][name]))
    assert server.decrypt_control(bytes.fromhex(run["control"]["client_error"]))

    with draws.step(steps, "rekey_request", "client") as step:
        nonce = kemtls.os.urandom(32)
        payload = struct.pack("!I", 1) + nonce
        pending = client.derive_next_epoch(1, nonce)
        step["wire"] = client.encrypt_control(payload, FrameType.REKEY_REQUEST).hex()
    with draws.step(steps, "rekey_response", "server") as step:
        _, payload = server.decrypt_control(bytes.fromhex(step_wire(steps, "rekey_request")), FrameType.REKEY_REQUEST)
        nxt = server.derive_next_epoch(1, payload[4:])
        confirm = hmac.new(bytes(server.secrets.control_confirm_key), b"rekey response" + payload, hashlib.sha256).digest()
        step["wire"] = server.encrypt_control(payload[:4] + confirm, FrameType.REKEY_RESPONSE).hex()
        server.activate_epoch(1, nxt)
    _, response = client.decrypt_control(bytes.fromhex(step_wire(steps, "rekey_response")), FrameType.REKEY_RESPONSE)
    assert hmac.compare_digest(response[4:], hmac.new(bytes(client.secrets.control_confirm_key),
                                                      b"rekey response" + payload, hashlib.sha256).digest())
    client.activate_epoch(1, pending)
    run["secrets"]["1"] = _secrets(client)
    assert _secrets(server) == run["secrets"]["1"]

    with draws.step(steps, "rehandshake_request", "client") as step:
        hybrid = HybridKEM("ML-KEM-768")
        dh_private, dh_public = hybrid.ecc.generate_keypair()
        kem_secret, kem_public = hybrid.pqc.generate_keypair()
        request = struct.pack("!I", 2) + dh_public + kem_public
        step["wire"] = client.encrypt_control(request, FrameType.REHANDSHAKE_REQUEST).hex()
    with draws.step(steps, "rehandshake_response", "server") as step:
        _, payload = server.decrypt_control(bytes.fromhex(step_wire(steps, "rehandshake_request")), FrameType.REHANDSHAKE_REQUEST)
        hybrid = HybridKEM("ML-KEM-768")
        server_private, server_public = hybrid.ecc.generate_keypair()
        dh_ss = hybrid.ecc.derive_shared_secret(server_private, payload[4:36])
        ct, k_mlkem = hybrid.pqc.encapsulate(payload[36:])
        body = struct.pack("!I", 2) + server_public + ct
        nxt = server.derive_rehandshake_epoch(2, dh_ss, k_mlkem, payload + body)
        confirm = hmac.new(bytes(nxt.control_confirm_key), b"rehandshake confirm" + payload + body, hashlib.sha256).digest()
        step["wire"] = server.encrypt_control(body + confirm, FrameType.REHANDSHAKE_RESPONSE).hex()
        server.activate_epoch(2, nxt)
    _, response = client.decrypt_control(bytes.fromhex(step_wire(steps, "rehandshake_response")), FrameType.REHANDSHAKE_RESPONSE)
    body = response[:4 + 32 + 1088]
    pending = client.derive_rehandshake_epoch(2, hybrid.ecc.derive_shared_secret(dh_private, body[4:36]),
                                              hybrid.pqc.decapsulate(kem_secret, body[36:]), request + body)
    assert hmac.compare_digest(response[-32:], hmac.new(bytes(pending.control_confirm_key),
                                                        b"rehandshake confirm" + request + body, hashlib.sha256).digest())
    client.activate_epoch(2, pending)
    run["secrets"]["2"] = _secrets(client)
    assert _secrets(server) == run["secrets"]["2"]


def step_wire(steps: list[dict], name: str) -> str:
    return next(s["wire"] for s in steps if s["name"] == name)


def _full_run(name: str, ids: dict, draws: Draws) -> dict:
    server_sk, server_pk = bytes.fromhex(ids["server_kem_sk"]), bytes.fromhex(ids["server_kem_pk"])
    if name == "v2":
        version = PROTOCOL_VERSION
        client = KEMTLSClient(server_pk, fingerprint(server_pk), Ed25519PrivateKey.from_private_bytes(bytes.fromhex(ids["client_ed25519"])))
        server = KEMTLSServer(server_sk, server_pk, lambda _: {"client_id": "vector"})
    else:
        version = PROTOCOL_VERSION_V3
        client_sk, client_pk = bytes.fromhex(ids["client_kem_sk"]), bytes.fromhex(ids["client_kem_pk"])
        client = KEMTLSClientV3(server_pk, fingerprint(server_pk), client_sk, client_pk)
        server = KEMTLSServerV3(server_sk, server_pk, lambda _: (client_pk, {"client_id": "vector"}))
    run = {"name": name, "version": version, "steps": [], "secrets": {}}
    steps = run["steps"]
    with draws.step(steps, "client_hello", "client") as step:
        step["wire"] = client.initiate_handshake().hex()
    with draws.step(steps, "server_hello", "server") as step:
        step["wire"] = server.process_client_hello(bytes.fromhex(step_wire(steps, "client_hello"))).hex()
    with draws.step(steps, "client_key_exchange", "client") as step:
        step["wire"] = client.process_server_hello(bytes.fromhex(step_wire(steps, "server_hello"))).hex()
    with draws.step(steps, "server_finished", "server") as step:
        finished, server_session = server.process_client_key_exchange(bytes.fromhex(step_wire(steps, "client_key_exchange")))
        step["wire"] = finished.hex()
    client_session = client.process_server_finished(finished)
    run["transcript_hash"] = hashlib.sha256(bytes.fromhex(step_wire(steps, "client_hello"))
                                            + bytes.fromhex(step_wire(steps, "server_hello"))).hexdigest()
    run["secrets"]["0"] = _secrets(client_session)
    assert _secrets(server_session) == run["secrets"]["0"]
    # The ticket a resumption run presents; issued from the epoch-0 rekey_secret right after CONFIG (runtime.py:491-496).
    with draws.step(steps, "issue_ticket", "server") as step:
        step["wire"] = ResumptionTicketKey().issue(bytes(server_session.secrets.rekey_secret), "vector", version,
                                                   86400, "10.8.0.2").hex()
    run["resumption_secret"] = bytes(client_session.secrets.rekey_secret).hex()
    _channel_and_epochs(run, draws, client_session, server_session)
    return run


def _resume_run(full: dict, draws: Draws) -> dict:
    """Resumes with the ticket from `full`; the server's ticket key is replayed from its issue_ticket draws."""
    version = full["version"]
    run = {"name": "resume-" + full["name"], "version": version, "steps": [], "secrets": {},
           "resumption_secret": full["resumption_secret"], "ticket": step_wire(full["steps"], "issue_ticket")}
    steps = run["steps"]
    ticket_key = ResumptionTicketKey.__new__(ResumptionTicketKey)
    key = next(s for s in full["steps"] if s["name"] == "issue_ticket")["draws"][0]["value"]
    ticket_key._cipher = kemtls.AESGCM(bytes.fromhex(key))
    client = ResumptionClientHandshake(bytes.fromhex(run["resumption_secret"]), version)
    server = ResumptionServerHandshake(ticket_key, version)
    with draws.step(steps, "resumption_hello", "client") as step:
        step["wire"] = client.initiate(bytes.fromhex(run["ticket"])).hex()
    with draws.step(steps, "resumption_accept", "server") as step:
        accept, server_session = server.process_hello(bytes.fromhex(step_wire(steps, "resumption_hello")))
        step["wire"] = accept.hex()
    client_session = client.process_accept(accept)
    assert (server.client_id, server.assigned_ip) == ("vector", "10.8.0.2")
    run["secrets"]["0"] = _secrets(client_session)
    assert _secrets(server_session) == run["secrets"]["0"]
    return run


def _outcome(parse, wire: bytes) -> str:
    try:
        parse(wire)
        return "ok"
    except HandshakeError as exc:
        return str(exc)


def _codec_rejections(runs: dict) -> list[dict]:
    """Python's verdict on mutated messages; Rust must give the same verdict (and the same message)."""
    parsers = {
        "client_hello": {PROTOCOL_VERSION: ClientHello.unpack, PROTOCOL_VERSION_V3: ClientHelloV3.unpack},
        "server_hello": {PROTOCOL_VERSION: ServerHello.unpack, PROTOCOL_VERSION_V3: ServerHelloV3.unpack},
        "client_key_exchange": {PROTOCOL_VERSION: ClientKeyExchange.unpack, PROTOCOL_VERSION_V3: ClientKeyExchangeV3.unpack},
        "server_finished": {PROTOCOL_VERSION: ServerFinished.unpack, PROTOCOL_VERSION_V3: ServerFinishedV3.unpack},
        "resumption_hello": {v: (lambda w, v=v: ResumptionHello.unpack(w, v)) for v in (PROTOCOL_VERSION, PROTOCOL_VERSION_V3)},
        "resumption_accept": {v: (lambda w, v=v: ResumptionAccept.unpack(w, v)) for v in (PROTOCOL_VERSION, PROTOCOL_VERSION_V3)},
    }
    cases = []
    for run in runs.values():
        for step in run["steps"]:
            if step["name"] not in parsers:
                continue
            wire = bytes.fromhex(step["wire"])
            length = struct.unpack("!H", wire[4:6])[0]
            mutations = {
                "valid": wire, "empty": b"", "short_header": wire[:5], "header_only": wire[:6],
                "truncated": wire[:-1], "trailing": wire + b"\0", "bad_magic": b"\x48\x57" + wire[2:],
                "v2_version": wire[:2] + bytes([0x20]) + wire[3:], "v3_version": wire[:2] + bytes([0x30]) + wire[3:],
                "mldsa_version": wire[:2] + bytes([0x31]) + wire[3:],
                "other_type": wire[:3] + bytes([wire[3] % 8 + 1]) + wire[4:], "unknown_type": wire[:3] + b"\x09" + wire[4:],
                "error_type": wire[:3] + b"\xff" + wire[4:], "zero_length": wire[:4] + b"\0\0",
                "length_minus_one": wire[:4] + struct.pack("!H", length - 1) + wire[6:-1],
                "length_plus_one": wire[:4] + struct.pack("!H", length + 1) + wire[6:] + b"\0",
                "oversize": wire[:4] + struct.pack("!H", 8187) + wire[6:],
            }
            for mutation, data in mutations.items():
                cases.append({"parser": step["name"], "version": run["version"], "mutation": mutation, "wire": data.hex(),
                              "result": _outcome(parsers[step["name"]][run["version"]], data)})
    cookie = bytes(range(32))
    for mutation, data in {
        "valid": b"\x48\x56\x20\x05\x00\x20" + cookie, "any_version": b"\x48\x56\x99\x05\x00\x20" + cookie,
        "trailing": b"\x48\x56\x20\x05\x00\x20" + cookie + b"xx", "short_body": b"\x48\x56\x20\x05\x00\x20" + cookie[:7],
        "short_header": b"\x48\x56\x20\x05\x00", "bad_magic": b"\x48\x57\x20\x05\x00\x20" + cookie,
        "wrong_type": b"\x48\x56\x20\x06\x00\x20" + cookie, "wrong_length": b"\x48\x56\x20\x05\x00\x21" + cookie + b"x",
    }.items():
        try:
            result = "ok:" + unpack_cookie_challenge(data).hex()
        except HandshakeError as exc:
            result = str(exc)
        cases.append({"parser": "cookie_challenge", "version": 0, "mutation": mutation, "wire": data.hex(), "result": result})
    return cases


_P = 2**255 - 19
# Low-order and non-canonical X25519 encodings (the usual libsodium/BoringSSL blocklist).
_X25519_POINTS = [0, 1, 325606250916557431795983626356110631294008115727848805560023387167927233504,
                  39382357235489614581723060781553021112529911719440698176882885853963445705823, _P - 1, _P, _P + 1,
                  _P + 325606250916557431795983626356110631294008115727848805560023387167927233504,
                  _P + 39382357235489614581723060781553021112529911719440698176882885853963445705823, 2**255 - 1]
_L = 2**252 + 27742317777372353535851937790883648493


def _primitive_rejections(ids: dict) -> dict:
    ecc, pqc = ECCProvider(), PQCProvider()
    private, _ = _x25519(ecc)
    x25519 = []
    for point in _X25519_POINTS:
        encoded = (point % 2**256).to_bytes(32, "little")
        try:
            ecc.derive_shared_secret(private, encoded)
            result = "ok"
        except ValueError:
            result = "error"
        x25519.append({"point": encoded.hex(), "result": result})
    # An encapsulation key whose first 12-bit coefficient is 4095 >= q fails the FIPS 203 modulus check.
    pk = bytes.fromhex(ids["server_kem_pk"])
    mlkem = []
    for name, ek in {"valid": pk, "coefficient_over_q": b"\xff\x0f" + pk[2:], "all_ff": b"\xff" * 1152 + pk[1152:]}.items():
        try:
            _encapsulate(pqc, ek)
            result = "ok"
        except (RuntimeError, ValueError):
            result = "error"
        mlkem.append({"name": name, "ek": ek.hex(), "result": result})
    signer = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(ids["client_ed25519"]))
    public, message = signer.public_key().public_bytes_raw(), b"pqvpn vector message"
    signature = signer.sign(message)
    s = int.from_bytes(signature[32:], "little")
    ed25519 = []
    for name, (key, sig) in {"valid": (public, signature),
                             "s_plus_l": (public, signature[:32] + (s + _L).to_bytes(32, "little")),
                             "flipped_r": (public, bytes([signature[0] ^ 1]) + signature[1:]),
                             "small_order_key": (bytes(32), signature)}.items():
        try:
            verify_client_signature(key, sig, message)
            result = "ok"
        except Exception:
            result = "error"
        ed25519.append({"name": name, "public": key.hex(), "message": message.hex(), "signature": sig.hex(), "result": result})
    return {"x25519": x25519, "mlkem_encapsulation_key": mlkem, "ed25519": ed25519}


def _kem_kat(runs: dict, ids: dict) -> list[dict]:
    """liboqs decapsulations, including FIPS 203 implicit rejection of a tampered ciphertext."""
    sk = bytes.fromhex(ids["server_kem_sk"])
    ct = bytes.fromhex(step_wire(runs["v2"]["steps"], "client_key_exchange"))[6:6 + 1088]
    tampered = bytes([ct[0] ^ 1]) + ct[1:]
    return [{"name": name, "sk": sk.hex(), "ct": c.hex(), "ss": PQCProvider().decapsulate(sk, c).hex()}
            for name, c in (("valid", ct), ("tampered", tampered))]


def build(recorded: dict | None = None) -> dict:
    if recorded is None:
        server_sk, server_pk = PQCProvider().generate_keypair()
        client_sk, client_pk = PQCProvider().generate_keypair()
        ed = Ed25519PrivateKey.generate().private_bytes_raw()
        ids = {"server_kem_sk": server_sk.hex(), "server_kem_pk": server_pk.hex(), "client_ed25519": ed.hex(),
               "client_kem_sk": client_sk.hex(), "client_kem_pk": client_pk.hex()}
    else:
        ids = recorded["identities"]
    runs = {}
    for name in ("v2", "v3", "resume-v2", "resume-v3"):
        source = None if recorded is None else next(r for r in recorded["runs"] if r["name"] == name)["steps"]
        draws = Draws(source)
        with draws.patched():
            runs[name] = _full_run(name, ids, draws) if name in ("v2", "v3") else _resume_run(runs[name[7:]], draws)
    return {"now": NOW, "identities": ids, "runs": list(runs.values()), "codec_rejections": _codec_rejections(runs),
            "kem_kat": _kem_kat(runs, ids), "primitive_rejections": _primitive_rejections(ids)}


def test_handshake_vectors_replay_through_python():
    # Everything is deterministic given the recorded draws, including liboqs's implicit-rejection secret.
    recorded = json.loads(VECTORS.read_text())
    assert build(recorded) == recorded


if __name__ == "__main__":
    VECTORS.write_text(json.dumps(build(), indent=1) + "\n")
