import datetime
import pytest
import os
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import NameOID
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

def verify_cert_chain(cert_bytes: bytes, ca_cert_bytes: bytes, server_id: str) -> bool:
    """Verifies a certificate's signature, validity timeframe, and server_id name match."""
    try:
        cert = x509.load_pem_x509_certificate(cert_bytes)
        ca_cert = x509.load_pem_x509_certificate(ca_cert_bytes)
        
        # 1. Verify Signature
        ca_pubkey = ca_cert.public_key()
        ca_pubkey.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm
        )
        
        # 2. Verify Expiration Time
        now = datetime.datetime.now(datetime.timezone.utc)
        try:
            # Modern Cryptography library (> 42.0.0)
            valid_time = cert.not_valid_before_utc <= now <= cert.not_valid_after_utc
        except AttributeError:
            # Fallback for older versions
            naive_now = datetime.datetime.utcnow()
            valid_time = cert.not_valid_before <= naive_now <= cert.not_valid_after
            
        if not valid_time:
            return False
            
        # 3. Verify Server ID Name Match
        name_matched = False
        # Check Common Name (CN)
        for attr in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
            if attr.value == server_id:
                name_matched = True
                
        # Check Subject Alternative Names (SAN) if CN didn't match
        if not name_matched:
            try:
                san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                for dns_name in san.value:
                    if isinstance(dns_name, x509.DNSName) and dns_name.value == server_id:
                        name_matched = True
            except x509.ExtensionNotFound:
                pass
                
        return name_matched
        
    except (InvalidSignature, Exception):
        return False

def test_valid_certificate_verifies(filesystem_server_cert_bytes, ca_cert_bytes):
    # Valid filesystem-server cert should verify successfully
    assert verify_cert_chain(
        filesystem_server_cert_bytes,
        ca_cert_bytes,
        "filesystem-server"
    ) is True

def test_expired_certificate_fails(adversarial_server_cert_bytes, ca_cert_bytes):
    # Expired cert signed by same CA should fail time validation check
    assert verify_cert_chain(
        adversarial_server_cert_bytes,
        ca_cert_bytes,
        "adversarial-server"
    ) is False

def test_wrong_server_id_fails(filesystem_server_cert_bytes, ca_cert_bytes):
    # Valid cert for filesystem-server checked against server-b name should fail ID match
    assert verify_cert_chain(
        filesystem_server_cert_bytes,
        ca_cert_bytes,
        "database-server"
    ) is False

def test_untrusted_issuer_fails(filesystem_server_cert_bytes, adversarial_server_cert_bytes):
    # Verifying a cert against a wrong CA cert (e.g. self) should fail signature check
    assert verify_cert_chain(
        filesystem_server_cert_bytes,
        adversarial_server_cert_bytes, # Mismatched CA cert
        "filesystem-server"
    ) is False

def test_tampered_signature_fails(filesystem_server_cert_bytes, ca_cert_bytes):
    # Base64 payload tampering
    tampered_bytes = filesystem_server_cert_bytes.replace(b"A", b"B", 1)
    assert verify_cert_chain(
        tampered_bytes,
        ca_cert_bytes,
        "filesystem-server"
    ) is False

def test_future_validity_fails(ca_cert_bytes):
    import os
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    
    FIXTURE_DIR = os.path.join(os.path.dirname(__file__), "fixtures", "ca")
    ca_cert = x509.load_pem_x509_certificate(ca_cert_bytes)
    
    with open(os.path.join(FIXTURE_DIR, "ca.key"), "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)
        
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    
    future_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "future-server")]))
        .issuer_name(ca_cert.subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now + datetime.timedelta(days=10))
        .not_valid_after(now + datetime.timedelta(days=20))
        .sign(ca_key, hashes.SHA256())
    )
    
    future_pem = future_cert.public_bytes(serialization.Encoding.PEM)
    assert verify_cert_chain(future_pem, ca_cert_bytes, "future-server") is False

def test_spoofed_ca_name_fails(ca_cert_bytes):
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    
    spoofed_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "MCP-Secure Root CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MCP-Secure Security Group"),
    ])
    
    now = datetime.datetime.now(datetime.timezone.utc)
    spoofed_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(spoofed_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=10))
        .sign(spoofed_key, hashes.SHA256())
    )
    
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "filesystem-server")]))
        .issuer_name(ca_name)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=10))
        .sign(spoofed_key, hashes.SHA256())
    )
    
    server_pem = server_cert.public_bytes(serialization.Encoding.PEM)
    assert verify_cert_chain(server_pem, ca_cert_bytes, "filesystem-server") is False

def test_garbage_input_fails(ca_cert_bytes):
    assert verify_cert_chain(b"This is not a certificate", ca_cert_bytes, "srv") is False
    assert verify_cert_chain(b"", ca_cert_bytes, "srv") is False

