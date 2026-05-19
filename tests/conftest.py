import os
import pytest
from cryptography import x509

FIXTURE_DIR = os.path.join(os.path.dirname(__file__), "fixtures", "ca")

@pytest.fixture(scope="session")
def ca_cert_bytes():
    """Returns the Root CA certificate bytes."""
    with open(os.path.join(FIXTURE_DIR, "ca.pem"), "rb") as f:
        return f.read()

@pytest.fixture(scope="session")
def ca_cert():
    """Returns the parsed Root CA certificate object."""
    with open(os.path.join(FIXTURE_DIR, "ca.pem"), "rb") as f:
        cert_data = f.read()
        return x509.load_pem_x509_certificate(cert_data)

@pytest.fixture(scope="session")
def filesystem_server_cert_bytes():
    """Returns the filesystem-server certificate bytes."""
    with open(os.path.join(FIXTURE_DIR, "filesystem-server.pem"), "rb") as f:
        return f.read()

@pytest.fixture(scope="session")
def adversarial_server_cert_bytes():
    """Returns the adversarial-server certificate bytes."""
    with open(os.path.join(FIXTURE_DIR, "adversarial-server_expired.pem"), "rb") as f:
        return f.read()
