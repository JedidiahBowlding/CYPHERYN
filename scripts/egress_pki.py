#!/usr/bin/env python3
"""Create development/certification PKI for the trusted egress mTLS hop.

Production operators should issue equivalent identities from their managed PKI.
Private key material never leaves the selected output directory.
"""

from __future__ import annotations

import argparse
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def _write(path: Path, data: bytes, mode: int) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(descriptor, "wb") as output:
        output.write(data)
    os.chmod(path, mode)


def _key(path: Path) -> ed25519.Ed25519PrivateKey:
    key = ed25519.Ed25519PrivateKey.generate()
    _write(
        path,
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
        0o600,
    )
    return key


def _ca(directory: Path, stem: str, common_name: str) -> tuple[x509.Certificate, object]:
    key = _key(directory / f"{stem}.key")
    now = datetime.now(UTC)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=397))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, algorithm=None)
    )
    _write(directory / f"{stem}.pem", certificate.public_bytes(serialization.Encoding.PEM), 0o644)
    return certificate, key


def _load_ca(directory: Path, stem: str) -> tuple[x509.Certificate, object]:
    certificate = x509.load_pem_x509_certificate((directory / f"{stem}.pem").read_bytes())
    key = serialization.load_pem_private_key((directory / f"{stem}.key").read_bytes(), None)
    return certificate, key


def _leaf(
    directory: Path,
    stem: str,
    common_name: str,
    ca: x509.Certificate,
    ca_key: object,
    *,
    server: bool,
) -> None:
    key = _key(directory / f"{stem}.key")
    now = datetime.now(UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .issuer_name(ca.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=90))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False
        )
        .add_extension(
            x509.ExtendedKeyUsage(
                [ExtendedKeyUsageOID.SERVER_AUTH if server else ExtendedKeyUsageOID.CLIENT_AUTH]
            ),
            critical=True,
        )
    )
    if server:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("egress-control-plane"),
                    x509.DNSName("localhost"),
                    x509.IPAddress(__import__("ipaddress").ip_address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
    else:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(
                [x509.UniformResourceIdentifier("spiffe://cypheryn.internal/egress-proxy")]
            ),
            critical=False,
        )
    certificate = builder.sign(ca_key, algorithm=None)
    _write(directory / f"{stem}.crt", certificate.public_bytes(serialization.Encoding.PEM), 0o644)


def initialize(directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    server_ca, server_key = _ca(directory, "control-plane-ca", "CYPHERYN Egress Server CA")
    _leaf(
        directory,
        "control-plane-server",
        "egress-control-plane",
        server_ca,
        server_key,
        server=True,
    )
    client_ca, client_key = _ca(directory, "proxy-client-ca", "CYPHERYN Proxy Client CA")
    _leaf(
        directory,
        "proxy-client",
        "cypheryn-egress-proxy",
        client_ca,
        client_key,
        server=False,
    )
    _write(
        directory / "proxy-client-ca-bundle.pem",
        (directory / "proxy-client-ca.pem").read_bytes(),
        0o644,
    )


def prepare_rotation(directory: Path) -> None:
    current = directory / "proxy-client-ca.pem"
    if not current.exists():
        raise RuntimeError("Initialize the egress PKI before preparing rotation")
    next_ca, next_key = _ca(directory, "proxy-client-ca-next", "CYPHERYN Proxy Client CA Next")
    _leaf(
        directory,
        "proxy-client-next",
        "cypheryn-egress-proxy",
        next_ca,
        next_key,
        server=False,
    )
    _write(
        directory / "proxy-client-ca-bundle.pem",
        current.read_bytes() + (directory / "proxy-client-ca-next.pem").read_bytes(),
        0o644,
    )


def complete_rotation(directory: Path) -> None:
    for suffix in ("pem", "key"):
        source = directory / f"proxy-client-ca-next.{suffix}"
        if not source.exists():
            raise RuntimeError("No prepared next client CA exists")
        _write(
            directory / f"proxy-client-ca.{suffix}",
            source.read_bytes(),
            0o600 if suffix == "key" else 0o644,
        )
    for suffix in ("crt", "key"):
        source = directory / f"proxy-client-next.{suffix}"
        _write(
            directory / f"proxy-client.{suffix}",
            source.read_bytes(),
            0o600 if suffix == "key" else 0o644,
        )
    _write(
        directory / "proxy-client-ca-bundle.pem",
        (directory / "proxy-client-ca.pem").read_bytes(),
        0o644,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("init", "prepare-rotation", "complete-rotation"))
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    if args.command == "init":
        initialize(args.directory)
    elif args.command == "prepare-rotation":
        prepare_rotation(args.directory)
    else:
        complete_rotation(args.directory)
    print(
        f"Egress mTLS material updated in {args.directory}; "
        "private key values were not displayed."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
