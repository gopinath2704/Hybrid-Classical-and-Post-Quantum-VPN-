"""Known-answer vectors for the Rust core, generated from the Python record layer.

Regenerate with: PYTHONPATH=. python tests/test_rust_core.py
"""
import hashlib
import json
from dataclasses import fields
from pathlib import Path

import pytest

from handshake.kemtls import DATA_HEADER_SIZE, MAX_SEQUENCE, FrameType, HandshakeSession, TrafficSecrets

VECTORS = Path(__file__).parent / "vectors" / "frame_encrypt.json"
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


if __name__ == "__main__":
    VECTORS.parent.mkdir(exist_ok=True)
    VECTORS.write_text(json.dumps(build_vectors(), indent=1) + "\n")
