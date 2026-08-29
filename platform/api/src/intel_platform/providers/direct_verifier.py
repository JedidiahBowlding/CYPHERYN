import hashlib
import ipaddress
import json
import socket
import ssl
from datetime import UTC, datetime

import certifi

from ..provider_contract import ProviderCapabilities, ProviderContext, ProviderResult


class DirectVerifierProvider:
    """Small, authorized probes that distinguish a response, refusal, and silence."""

    name = "direct_verifier"
    capabilities = ProviderCapabilities(
        target_types=frozenset({"domain", "ip_address"}),
        passive_only=False,
        requires_credentials=False,
    )

    def collect(self, context: ProviderContext) -> ProviderResult:
        value = context.target.canonical_value
        observed_at = datetime.now(UTC).isoformat()
        addresses = self._addresses(value)
        observations: list[dict] = []
        for address in addresses[:8]:
            for port in (80, 443):
                observations.append(self._tcp(address, port))
            observations.append(self._ike(address))
        dns = {"resolved": bool(addresses), "addresses": addresses}
        tls = self._tls(value) if context.target.target_type.value == "domain" else None
        payload = {
            "target": value,
            "observed_at": observed_at,
            "dns": dns,
            "services": observations,
            "tls": tls,
        }
        encoded = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
        return ProviderResult(
            result_count=len(observations) + 1,
            metadata={"direct_verification": payload, "active": True},
            response_fingerprint=hashlib.sha256(encoded).hexdigest(),
            redacted_payload=payload,
        )

    @staticmethod
    def _addresses(value: str) -> list[str]:
        try:
            address = ipaddress.ip_address(value)
            if not address.is_global:
                raise RuntimeError("Direct verification requires a public address")
            return [str(address)]
        except ValueError:
            addresses = sorted({item[4][0] for item in socket.getaddrinfo(value, None)})
            if any(not ipaddress.ip_address(item).is_global for item in addresses):
                raise RuntimeError("Direct verification resolved to a non-public address") from None
            return addresses

    @staticmethod
    def _tcp(address: str, port: int) -> dict:
        started = datetime.now(UTC)
        try:
            with socket.create_connection((address, port), timeout=2):
                state = "responded"
        except ConnectionRefusedError:
            state = "refused"
        except (TimeoutError, OSError):
            state = "inconclusive"
        elapsed = int((datetime.now(UTC) - started).total_seconds() * 1000)
        return {
            "address": address,
            "port": port,
            "protocol": "tcp",
            "state": state,
            "latency_ms": elapsed,
        }

    @staticmethod
    def _ike(address: str) -> dict:
        # An intentionally malformed IKEv2 header often elicits a standards-defined
        # notification. A timeout is not treated as proof that UDP/500 is closed.
        packet = bytes.fromhex("0000000000000000000000000000000021202208000000000000001c")
        state = "inconclusive"
        started = datetime.now(UTC)
        sock = socket.socket(
            socket.AF_INET6 if ":" in address else socket.AF_INET, socket.SOCK_DGRAM
        )
        sock.settimeout(2)
        try:
            sock.connect((address, 500))
            sock.send(packet)
            data = sock.recv(2048)
            if data:
                state = "responded"
        except ConnectionRefusedError:
            state = "refused"
        except (TimeoutError, OSError):
            pass
        finally:
            sock.close()
        elapsed = int((datetime.now(UTC) - started).total_seconds() * 1000)
        return {
            "address": address,
            "port": 500,
            "protocol": "udp",
            "state": state,
            "latency_ms": elapsed,
        }

    @staticmethod
    def _tls(host: str) -> dict:
        try:
            ssl_context = ssl.create_default_context(cafile=certifi.where())
            with socket.create_connection((host, 443), timeout=3) as raw:
                with ssl_context.wrap_socket(raw, server_hostname=host) as secured:
                    cert = secured.getpeercert()
            return {"state": "valid", "expires_at": cert.get("notAfter")}
        except (OSError, ssl.SSLError, TimeoutError):
            return {"state": "inconclusive", "expires_at": None}
