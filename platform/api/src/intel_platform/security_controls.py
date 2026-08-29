import re
from collections.abc import Mapping
from typing import Any

SENSITIVE_KEY = re.compile(
    r"(^|_)(api_?key|auth|authorization|bearer|cookie|credential|password|secret|token)(_|$)",
    re.IGNORECASE,
)
SENSITIVE_TEXT = re.compile(
    r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+|"
    r"((?:api[_ -]?key|password|secret|token)\s*[:=]\s*)[^\s,;]+"
)


def redact_payload(value: Any) -> Any:
    """Recursively remove common secret fields before persistence or API output."""
    if isinstance(value, Mapping):
        return {
            str(key): "[REDACTED]" if SENSITIVE_KEY.search(str(key)) else redact_payload(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_payload(item) for item in value]
    if isinstance(value, tuple):
        return [redact_payload(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


def redact_text(value: str) -> str:
    def replace(match: re.Match) -> str:
        prefix = match.group(1) or match.group(2) or ""
        return f"{prefix}[REDACTED]"

    return SENSITIVE_TEXT.sub(replace, value)
