"""Seeds corpus/<target>/ for the handshake fuzz targets from tests/vectors/handshake.json. Run from core/fuzz."""
import hashlib
import json
import struct
from pathlib import Path

VECTORS = json.loads((Path(__file__).parents[2] / "tests/vectors/handshake.json").read_text())
# handshake_decode: decoder index per message; handshake_machines: step whose fuzzed message it is.
DECODER = {"client_hello": 0, "server_hello": 1, "client_key_exchange": 2, "server_finished": 3,
           "resumption_hello": 4, "resumption_accept": 5}
MACHINE = {"client_hello": 0, "client_key_exchange": 1, "server_hello": 2, "server_finished": 3,
           "resumption_hello": 4, "resumption_accept": 5}


def write(target: str, seed: bytes) -> None:
    directory = Path(__file__).parent / "corpus" / target
    directory.mkdir(parents=True, exist_ok=True)
    (directory / hashlib.sha1(seed).hexdigest()).write_bytes(seed)


for run in VECTORS["runs"]:
    suite_bit = 1 if run["version"] == 0x30 else 0
    for step in run["steps"]:
        wire = bytes.fromhex(step["wire"])
        if step["name"] in DECODER:
            write("handshake_decode", bytes([DECODER[step["name"]] << 1 | suite_bit]) + wire)
            for framed in (0, 16):
                body = wire[6:] if framed else wire
                write("handshake_machines", bytes([MACHINE[step["name"]] | suite_bit << 3 | framed]) + body)
for case in VECTORS["codec_rejections"]:
    if case["parser"] == "cookie_challenge":
        write("handshake_decode", bytes([6 << 1]) + bytes.fromhex(case["wire"]))
for version in (0x20, 0x30):
    plaintext = bytes(32) + struct.pack("!BqHH", version, 1_800_086_400, 6, 8) + b"vector10.8.0.2"
    write("handshake_decode", bytes([7 << 1]) + plaintext)
for suite_bit in (0, 8):
    for framed in (0, 16):
        for path, length in ((0, 36), (1, 1220), (2, 64), (3, 64), (4, 36), (5, 1156)):
            write("established", bytes([path | suite_bit | framed]) + struct.pack("!I", 1) + bytes(range(256))[: length - 4])
        write("established", bytes([6 | suite_bit]) + bytes([7]) + b'{"client_vpn_ip": "10.8.0.2"}')
print("seeded", {t: len(list((Path(__file__).parent / "corpus" / t).iterdir())) for t in
                 ("handshake_decode", "handshake_machines", "established")})
