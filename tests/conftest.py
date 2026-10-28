import os
os.environ.setdefault("ALLOW_MOCK_PQC","1")
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from crypto.hybrid_crypto import PQCProvider, PQSignatureProvider
@pytest.fixture
def identities():
    kem=PQCProvider(allow_mock=True);server_sk,server_pk=kem.generate_keypair();client_sk=Ed25519PrivateKey.generate()
    return server_sk,server_pk,client_sk,client_sk.public_key().public_bytes_raw()

@pytest.fixture
def v3_identities():
    kem = PQCProvider(allow_mock=True)
    server_sk, server_pk = kem.generate_keypair()
    client_sk, client_pk = kem.generate_keypair()
    return server_sk, server_pk, client_sk, client_pk

@pytest.fixture
def mldsa_identities():
    kem = PQCProvider(allow_mock=True)
    server_sk, server_pk = kem.generate_keypair()
    sig = PQSignatureProvider(allow_mock=True)
    client_sig_sk, client_sig_pk = sig.generate_keypair()
    return server_sk, server_pk, client_sig_sk, client_sig_pk

def pytest_addoption(parser):
    parser.addoption("--backend", choices=("python", "rust"), default="python", help="record-layer backend under test")

def pytest_configure(config):
    config.addinivalue_line("markers", "data_plane: runs the per-packet data loop")
    if config.getoption("backend") == "rust":
        try:
            import pqvpn_core  # noqa: F401
        except ImportError as exc:
            raise pytest.UsageError(f"--backend rust requires pqvpn_core (maturin develop -m core/pqvpn_core/Cargo.toml): {exc}") from exc

@pytest.fixture
def backend(request) -> str:
    return request.config.getoption("backend")

@pytest.fixture
def data_plane(backend) -> str:
    """The data_plane value tests pass explicitly to configs and handshakes."""
    return backend
