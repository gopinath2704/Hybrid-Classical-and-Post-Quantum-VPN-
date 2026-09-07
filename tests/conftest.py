import os
os.environ.setdefault("ALLOW_MOCK_PQC","1")
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from crypto.hybrid_crypto import PQCProvider
@pytest.fixture
def identities():
    kem=PQCProvider(allow_mock=True);server_sk,server_pk=kem.generate_keypair();client_sk=Ed25519PrivateKey.generate()
    return server_sk,server_pk,client_sk,client_sk.public_key().public_bytes_raw()
