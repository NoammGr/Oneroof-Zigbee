"""Local TLS: a private CA and a server certificate, generated on first start.

Why our own CA instead of a bare self-signed server cert: clients (Home
Assistant, a phone, a laptop) trust *one* file — `ca.crt` — and we can rotate
the server certificate later without touching them. Keys are ECDSA P-256,
written 0600; the CA key never leaves `data_dir`.

Files in data_dir/tls/:
    ca.key, ca.crt          private CA (10 years)
    server.key, server.crt  server cert signed by the CA (2 years, auto-renewed
                            when < 30 days remain); SANs: hostnames + IPs given
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import logging
import os
import socket
import ssl
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

log = logging.getLogger("oneroof_zigbee.security.tls")

CA_DAYS = 3650
SERVER_DAYS = 730
RENEW_BEFORE_DAYS = 30


def _write_private(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def _key_pem(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _ensure_ca(tls_dir: Path) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    key_p, crt_p = tls_dir / "ca.key", tls_dir / "ca.crt"
    if key_p.exists() and crt_p.exists():
        key = serialization.load_pem_private_key(key_p.read_bytes(), None)
        crt = x509.load_pem_x509_certificate(crt_p.read_bytes())
        assert isinstance(key, ec.EllipticCurvePrivateKey)
        return key, crt
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "OneRoof Zigbee local CA"),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, "OneRoof")])
    crt = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(_now() - dt.timedelta(minutes=5))
        .not_valid_after(_now() + dt.timedelta(days=CA_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True, content_commitment=False,
                                     key_encipherment=False, data_encipherment=False, key_agreement=False,
                                     encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    _write_private(key_p, _key_pem(key))
    _write_private(crt_p, crt.public_bytes(serialization.Encoding.PEM))
    os.chmod(crt_p, 0o644)  # the CA *certificate* is meant to be copied to clients
    log.warning("generated local CA at %s — install ca.crt on clients that should verify the broker", crt_p)
    return key, crt


def _server_needs_renewal(crt_p: Path, sans: set[str]) -> bool:
    if not crt_p.exists():
        return True
    crt = x509.load_pem_x509_certificate(crt_p.read_bytes())
    if crt.not_valid_after_utc - _now() < dt.timedelta(days=RENEW_BEFORE_DAYS):
        return True
    try:
        ext = crt.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        have = {str(v) for v in ext.get_values_for_type(x509.DNSName)} | {str(v) for v in ext.get_values_for_type(x509.IPAddress)}
    except x509.ExtensionNotFound:
        return True
    return not sans <= have


def ensure_server_cert(data_dir: Path, hostnames: list[str] | None = None) -> tuple[Path, Path, Path]:
    """Return (server.crt, server.key, ca.crt), generating/renewing as needed."""
    tls_dir = data_dir / "tls"
    ca_key, ca_crt = _ensure_ca(tls_dir)
    names = set(hostnames or [])
    names |= {"localhost", socket.gethostname(), "127.0.0.1", "::1"}
    try:
        names.add(socket.gethostbyname(socket.gethostname()))
    except OSError:
        pass
    srv_key_p, srv_crt_p = tls_dir / "server.key", tls_dir / "server.crt"
    if _server_needs_renewal(srv_crt_p, names):
        key = ec.generate_private_key(ec.SECP256R1())
        san: list[x509.GeneralName] = []
        for n in sorted(names):
            try:
                san.append(x509.IPAddress(ipaddress.ip_address(n)))
            except ValueError:
                san.append(x509.DNSName(n))
        crt = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "OneRoof Zigbee")]))
            .issuer_name(ca_crt.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(_now() - dt.timedelta(minutes=5)).not_valid_after(_now() + dt.timedelta(days=SERVER_DAYS))
            .add_extension(x509.SubjectAlternativeName(san), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256())
        )
        _write_private(srv_key_p, _key_pem(key))
        _write_private(srv_crt_p, crt.public_bytes(serialization.Encoding.PEM))
        log.info("issued server certificate for %s", ", ".join(sorted(names)))
    return srv_crt_p, srv_key_p, tls_dir / "ca.crt"


def fingerprint(cert_path: Path) -> str:
    crt = x509.load_pem_x509_certificate(cert_path.read_bytes())
    raw = crt.fingerprint(hashes.SHA256()).hex().upper()
    return ":".join(raw[i:i + 2] for i in range(0, len(raw), 2))


def server_context(cert: Path, key: Path, client_ca: Path | None = None) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!MD5:!3DES")
    ctx.load_cert_chain(cert, key)
    if client_ca:
        ctx.load_verify_locations(client_ca)
        ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def client_context(ca: Path | None, *, server_hostname_check: bool = True) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    if ca:
        ctx.load_verify_locations(ca)
    ctx.check_hostname = server_hostname_check
    return ctx
