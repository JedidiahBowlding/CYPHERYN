from __future__ import annotations

import shutil
import socket
import ssl
import subprocess
import sys
import threading
from pathlib import Path

import pytest
from pydantic import ValidationError

from intel_platform.config import Settings
from intel_platform.egress_proxy import ControlPlane, ProxySecurityError


class MtlsJsonServer:
    def __init__(self, directory: Path):
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_cert_chain(
            directory / "control-plane-server.crt",
            directory / "control-plane-server.key",
        )
        context.load_verify_locations(directory / "proxy-client-ca-bundle.pem")
        self.context = context
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(10)
        self.listener.settimeout(0.2)
        self.port = self.listener.getsockname()[1]
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def _serve(self):
        while not self.stop.is_set():
            try:
                raw, _ = self.listener.accept()
            except TimeoutError:
                continue
            except OSError:
                if self.stop.is_set():
                    return
                raise
            try:
                with self.context.wrap_socket(raw, server_side=True) as connection:
                    request = b""
                    while b"\r\n\r\n" not in request:
                        request += connection.recv(4096)
                    headers, received_body = request.split(b"\r\n\r\n", 1)
                    content_length = 0
                    for line in headers.split(b"\r\n")[1:]:
                        name, _, value = line.partition(b":")
                        if name.lower() == b"content-length":
                            content_length = int(value.strip())
                    while len(received_body) < content_length:
                        received_body += connection.recv(4096)
                    body = b'{"proxy_request_id":"mtls-receipt","outcome":"PENDING_VALIDATION"}'
                    connection.sendall(
                        b"HTTP/1.1 201 Created\r\nContent-Type: application/json\r\n"
                        + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
                        + body
                    )
            except (OSError, ssl.SSLError):
                raw.close()

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_):
        self.stop.set()
        self.listener.close()
        self.thread.join(timeout=2)


def _run_pki(repo_root: Path, command: str, directory: Path) -> None:
    subprocess.run(  # noqa: S603 - fixed interpreter and repository-owned script
        [sys.executable, str(repo_root / "scripts" / "egress_pki.py"), command, str(directory)],
        check=True,
        capture_output=True,
        text=True,
        timeout=15,
    )


def _settings(directory: Path, port: int, stem: str = "proxy-client") -> Settings:
    return Settings(
        environment="development",
        trusted_egress_proxy_enabled=True,
        trusted_egress_proxy_control_plane_url=f"https://localhost:{port}",
        trusted_egress_proxy_mtls_ca_file=str(directory / "control-plane-ca.pem"),
        trusted_egress_proxy_mtls_cert_file=str(directory / f"{stem}.crt"),
        trusted_egress_proxy_mtls_key_file=str(directory / f"{stem}.key"),
    )


def _receipt(control_plane: ControlPlane) -> str:
    return control_plane.start_receipt(
        "00000000-0000-0000-0000-000000000001",
        {"certification": True},
    )


def test_production_proxy_requires_https_and_mtls():
    with pytest.raises(ValidationError, match="requires HTTPS"):
        Settings(
            environment="production",
            allow_dev_identity=False,
            trusted_egress_proxy_enabled=True,
        )
    with pytest.raises(ValidationError, match="requires mTLS"):
        Settings(
            environment="production",
            allow_dev_identity=False,
            trusted_egress_proxy_enabled=True,
            trusted_egress_proxy_control_plane_url="https://control-plane.internal",
        )


def test_current_overlap_rotation_and_old_certificate_rejection(tmp_path):
    repo_root = Path(__file__).parents[3]
    directory = tmp_path / "pki"
    _run_pki(repo_root, "init", directory)

    with MtlsJsonServer(directory) as server:
        assert _receipt(ControlPlane(_settings(directory, server.port), "Bearer workload")) == (
            "mtls-receipt"
        )

    old_cert = directory / "proxy-client-old.crt"
    old_key = directory / "proxy-client-old.key"
    shutil.copyfile(directory / "proxy-client.crt", old_cert)
    shutil.copyfile(directory / "proxy-client.key", old_key)
    _run_pki(repo_root, "prepare-rotation", directory)

    with MtlsJsonServer(directory) as server:
        assert _receipt(ControlPlane(_settings(directory, server.port), "Bearer workload"))
        assert _receipt(
            ControlPlane(_settings(directory, server.port, "proxy-client-next"), "Bearer workload")
        )

    _run_pki(repo_root, "complete-rotation", directory)
    with MtlsJsonServer(directory) as server:
        assert _receipt(ControlPlane(_settings(directory, server.port), "Bearer workload"))
        old_settings = _settings(directory, server.port)
        old_settings.trusted_egress_proxy_mtls_cert_file = str(old_cert)
        old_settings.trusted_egress_proxy_mtls_key_file = str(old_key)
        with pytest.raises(ProxySecurityError, match="CONTROL_PLANE_UNAVAILABLE"):
            _receipt(ControlPlane(old_settings, "Bearer workload"))


def test_gateway_authorizes_only_proxy_security_operations():
    caddyfile = Path(__file__).parents[3] / "deploy" / "egress" / "Caddyfile"
    configuration = caddyfile.read_text(encoding="utf-8")
    assert "require_and_verify" in configuration
    assert "proxy-client-ca-bundle.pem" in configuration
    assert "decisions/[^/]+/(validate|proxy-receipts)" in configuration
    assert 'respond "proxy service identity is not authorized' in configuration
