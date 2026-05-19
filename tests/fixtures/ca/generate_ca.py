import datetime
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import os

def generate_ca_and_certs(output_dir: str):
    os.makedirs(output_dir, exist_ok=True)

    # 1. Generate Root CA Key
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    
    # Root CA Subject & Issuer Name
    ca_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "MCP-Secure Root CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MCP-Secure Security Group"),
    ])
    
    now = datetime.datetime.now(datetime.timezone.utc)
    
    # 2. Build Root CA Cert
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
        .sign(ca_key, hashes.SHA256())
    )
    
    # Save CA cert and key
    with open(os.path.join(output_dir, "ca.pem"), "wb") as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
    with open(os.path.join(output_dir, "ca.key"), "wb") as f:
        f.write(ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Helper function to generate and sign server cert
    def sign_server_cert(server_id: str, is_expired: bool = False):
        server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        
        server_name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, server_id),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MCP-Secure Server"),
        ])
        
        if is_expired:
            not_before = now - datetime.timedelta(days=10)
            not_after = now - datetime.timedelta(days=1)
        else:
            not_before = now - datetime.timedelta(days=1)
            not_after = now + datetime.timedelta(days=90)
            
        cert_builder = (
            x509.CertificateBuilder()
            .subject_name(server_name)
            .issuer_name(ca_name)
            .public_key(server_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            )
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName(server_id)
                ]),
                critical=False
            )
        )
        
        server_cert = cert_builder.sign(ca_key, hashes.SHA256())
        
        cert_filename = f"{server_id}.pem" if not is_expired else f"{server_id}_expired.pem"
        key_filename = f"{server_id}.key" if not is_expired else f"{server_id}_expired.key"
        
        with open(os.path.join(output_dir, cert_filename), "wb") as f:
            f.write(server_cert.public_bytes(serialization.Encoding.PEM))
        with open(os.path.join(output_dir, key_filename), "wb") as f:
            f.write(server_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

    # Generate normal server certs
    sign_server_cert("filesystem-server", is_expired=False)
    # Generate expired server certs
    sign_server_cert("adversarial-server", is_expired=True)

if __name__ == "__main__":
    import sys
    target_dir = sys.argv[1] if len(sys.argv) > 1 else "."
    generate_ca_and_certs(target_dir)
