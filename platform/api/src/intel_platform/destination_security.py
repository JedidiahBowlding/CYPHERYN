from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit


class UnsafeDestination(ValueError):
    pass


DNS_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


@dataclass(frozen=True)
class CanonicalDestination:
    canonical_identifier: str
    hostname: str
    port: int
    scheme: str
    resolved_addresses: tuple[str, ...]


def _public_address(value: str) -> str:
    address = ipaddress.ip_address(value)
    if not address.is_global:
        raise UnsafeDestination("Destination resolved to a non-public network address")
    return address.compressed


def canonicalize_destination(
    value: str,
    *,
    resolve: bool = True,
    resolver=socket.getaddrinfo,
) -> CanonicalDestination:
    candidate = value.strip()
    if not candidate or len(candidate) > 2048:
        raise UnsafeDestination("Destination is missing or too long")
    parsed = urlsplit(candidate if "://" in candidate else f"https://{candidate}")
    if parsed.scheme.lower() not in {"https"}:
        raise UnsafeDestination("Only HTTPS destinations are supported")
    if parsed.username or parsed.password or parsed.fragment:
        raise UnsafeDestination("Destination credentials and fragments are prohibited")
    if not parsed.hostname:
        raise UnsafeDestination("Destination hostname is missing")
    try:
        hostname = parsed.hostname.encode("idna").decode("ascii").lower().rstrip(".")
    except UnicodeError as exc:
        raise UnsafeDestination("Destination hostname is not valid IDNA") from exc
    if not hostname or len(hostname) > 253 or ".." in hostname:
        raise UnsafeDestination("Destination hostname is invalid")
    try:
        port = parsed.port or 443
    except ValueError as exc:
        raise UnsafeDestination("Destination port is invalid") from exc
    if port != 443:
        raise UnsafeDestination("Non-standard destination ports require a separate policy")
    addresses: set[str] = set()
    try:
        literal = ipaddress.ip_address(hostname)
    except ValueError:
        literal = None
    if literal is not None:
        addresses.add(_public_address(hostname))
    elif resolve:
        if any(not DNS_LABEL.fullmatch(label) for label in hostname.split(".")):
            raise UnsafeDestination("Destination hostname contains an invalid DNS label")
        try:
            answers = resolver(hostname, port, type=socket.SOCK_STREAM)
        except OSError as exc:
            raise UnsafeDestination("Destination DNS resolution failed closed") from exc
        for answer in answers:
            addresses.add(_public_address(answer[4][0]))
        if not addresses:
            raise UnsafeDestination("Destination did not resolve to a public address")
    if parsed.path not in {"", "/"} or parsed.query:
        # Policy binds to an origin. Paths remain action metadata and redirects must be
        # re-evaluated by the enforcing client rather than silently followed.
        pass
    if literal is None and any(not DNS_LABEL.fullmatch(label) for label in hostname.split(".")):
        raise UnsafeDestination("Destination hostname contains an invalid DNS label")
    origin_host = f"[{hostname}]" if isinstance(literal, ipaddress.IPv6Address) else hostname
    canonical = f"https://{origin_host}"
    return CanonicalDestination(canonical, hostname, port, "https", tuple(sorted(addresses)))
