import ipaddress
import re
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from fastapi import HTTPException, status

from .models import TargetType


def canonicalize_target(target_type: TargetType, value: str) -> str:
    raw = value.strip()
    try:
        if target_type == TargetType.DOMAIN:
            domain = raw.rstrip(".").lower().encode("idna").decode("ascii")
            if "." not in domain or any(not part for part in domain.split(".")):
                raise ValueError("invalid domain")
            return domain
        if target_type == TargetType.IP_ADDRESS:
            return ipaddress.ip_address(raw).compressed
        if target_type == TargetType.NETWORK:
            network = ipaddress.ip_network(raw, strict=True)
            if network.num_addresses > 256:
                raise ValueError("network targets are limited to 256 addresses")
            if not network.network_address.is_global:
                raise ValueError("network target must be public")
            return network.compressed
        if target_type == TargetType.ASN:
            number = raw.upper().removeprefix("AS")
            if not number.isdigit() or not 0 < int(number) <= 4_294_967_295:
                raise ValueError("invalid ASN")
            return f"AS{int(number)}"
        if target_type == TargetType.URL:
            parsed = urlsplit(raw)
            if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
                raise ValueError("invalid URL")
            host = parsed.hostname.encode("idna").decode("ascii").lower()
            port = parsed.port
            netloc = host if port is None else f"{host}:{port}"
            return urlunsplit((parsed.scheme.lower(), netloc, parsed.path or "/", parsed.query, ""))
        if target_type == TargetType.EMAIL_ADDRESS:
            local, domain = raw.rsplit("@", 1)
            if not local:
                raise ValueError("invalid email")
            return f"{local}@{domain.rstrip('.').lower().encode('idna').decode('ascii')}"
        if target_type in {TargetType.USERNAME, TargetType.ORGANIZATION, TargetType.PERSON}:
            if not raw:
                raise ValueError("empty target")
            return " ".join(raw.split())
        if target_type == TargetType.REPOSITORY:
            parsed = urlsplit(raw)
            if parsed.scheme:
                if (
                    parsed.scheme.lower() != "https"
                    or parsed.hostname not in {"github.com", "www.github.com"}
                    or len([part for part in parsed.path.split("/") if part]) != 2
                ):
                    raise ValueError("repository URL must be https://github.com/owner/repository")
                path = parsed.path.rstrip("/").removesuffix(".git")
                return f"https://github.com{path}.git"
            path = Path(raw).expanduser().resolve(strict=True)
            if not path.is_dir() or path in {Path("/"), Path.home()} or len(path.parts) < 4:
                raise ValueError("local repository must be a specific existing directory")
            return str(path)
        if target_type == TargetType.CONTAINER_IMAGE:
            image = raw.lower()
            if (
                not image
                or image.startswith("-")
                or len(image) > 500
                or not re.fullmatch(r"[a-z0-9][a-z0-9._:/@-]*", image)
            ):
                raise ValueError("invalid container image reference")
            if ":" not in image.rsplit("/", 1)[-1] and "@sha256:" not in image:
                raise ValueError("container image must use an explicit tag or digest")
            return image
        if target_type == TargetType.SBOM:
            path = Path(raw).expanduser().resolve(strict=True)
            if (
                not path.is_file()
                or path.suffix.lower() not in {".json", ".xml", ".spdx"}
                or path.stat().st_size > 50_000_000
            ):
                raise ValueError("SBOM must be a JSON, XML, or SPDX file under 50 MB")
            return str(path)
    except (ValueError, UnicodeError) as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "unsupported target type")
