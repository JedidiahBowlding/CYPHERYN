import json
import re

import httpx

from .models import AnalysisSnapshot


class LocalNarrativeError(RuntimeError):
    pass


def generate_local_narrative(
    snapshot: AnalysisSnapshot,
    base_url: str,
    model: str,
    timeout_seconds: int,
) -> dict:
    indexed_claims = [{"index": index, **claim} for index, claim in enumerate(snapshot.claims)]
    compact_claims = [_compact_mapping(claim) for claim in indexed_claims[:16]]
    context = {
        "risk_score": snapshot.risk_score,
        "risk_level": snapshot.risk_level,
        "metrics": _compact_mapping(snapshot.metrics, value_limit=180),
    }
    executive = _generate_section(
        base_url=base_url,
        model=model,
        timeout_seconds=timeout_seconds,
        prompt=(
            "Write a concise executive security summary from only this JSON. Do not add facts. "
            "Preserve indicators exactly. Return only JSON with executive_summary.\n"
            + json.dumps(
                {
                    **context,
                    "top_claims": compact_claims[:8],
                    "recommendations": [
                        _compact_value(item, 240) for item in snapshot.recommendations[:6]
                    ],
                },
                separators=(",", ":"),
                sort_keys=True,
            )
        ),
        schema={
            "type": "object",
            "properties": {"executive_summary": {"type": "string"}},
            "required": ["executive_summary"],
        },
        num_predict=320,
    )
    technical = _generate_section(
        base_url=base_url,
        model=model,
        timeout_seconds=timeout_seconds,
        prompt=(
            "Write a concise technical security summary from only this JSON. Do not add facts. "
            "Preserve indicators exactly. Claim references must use the supplied index values. "
            "Return only JSON with technical_summary and key_points; each key point has text and "
            "claim_refs. Describe correlations only as limited inferences.\n"
            + json.dumps(
                {
                    **context,
                    "claims": compact_claims,
                    "correlations": [
                        _compact_value(item, 300) for item in snapshot.correlations[:6]
                    ],
                },
                separators=(",", ":"),
                sort_keys=True,
            )
        ),
        schema={
            "type": "object",
            "properties": {
                "technical_summary": {"type": "string"},
                "key_points": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "text": {"type": "string"},
                            "claim_refs": {"type": "array", "items": {"type": "integer"}},
                        },
                        "required": ["text", "claim_refs"],
                    },
                },
            },
            "required": ["technical_summary", "key_points"],
        },
        num_predict=700,
    )
    raw = {**executive, **technical}
    corrected = correct_unambiguous_indicators(raw, snapshot.claims)
    sanitized = strip_unsupported_security_sentences(corrected, snapshot.claims)
    return validate_narrative(sanitized, len(snapshot.claims), snapshot.claims)


def _compact_value(value: object, limit: int) -> object:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value if not isinstance(value, str) else value[:limit]
    return json.dumps(value, separators=(",", ":"), sort_keys=True, default=str)[:limit]


def _compact_mapping(value: object, value_limit: int = 320) -> dict:
    if not isinstance(value, dict):
        return {"value": _compact_value(value, value_limit)}
    return {str(key): _compact_value(item, value_limit) for key, item in value.items()}


def _generate_section(
    *,
    base_url: str,
    model: str,
    timeout_seconds: int,
    prompt: str,
    schema: dict,
    num_predict: int,
) -> dict:
    endpoint = f"{base_url.rstrip('/')}/api/generate"
    try:
        response = httpx.post(
            endpoint,
            json={
                "model": model,
                "prompt": prompt,
                "stream": False,
                "format": schema,
                "options": {"num_predict": num_predict},
            },
            timeout=timeout_seconds,
        )
        response.raise_for_status()
        envelope = response.json()
        value = json.loads(envelope.get("response", "{}"))
        if not isinstance(value, dict):
            raise TypeError("section is not a JSON object")
        return value
    except (httpx.HTTPError, json.JSONDecodeError, TypeError) as exc:
        raise LocalNarrativeError(f"Local model response failed: {exc}") from exc


def correct_unambiguous_indicators(value: dict, supported_claims: list) -> dict:
    supported_text = " ".join(str(item) for item in supported_claims)
    supported_ips = set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", supported_text))
    if len(supported_ips) != 1:
        return value
    canonical_ip = next(iter(supported_ips))

    def correct(text: object) -> str:
        return re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", canonical_ip, str(text or ""))

    corrected = dict(value)
    corrected["executive_summary"] = correct(value.get("executive_summary"))
    corrected["technical_summary"] = correct(value.get("technical_summary"))
    corrected["key_points"] = [
        {**item, "text": correct(item.get("text"))}
        for item in value.get("key_points", [])
        if isinstance(item, dict)
    ]
    return corrected


def strip_unsupported_security_sentences(value: dict, supported_claims: list) -> dict:
    supported_text = " ".join(str(item) for item in supported_claims).casefold()
    forbidden = {
        "attack",
        "breach",
        "bypass",
        "compromise",
        "malicious",
        "misconfiguration",
        "vulnerability",
    }
    unsupported = {term for term in forbidden if term not in supported_text}

    def clean(text: object) -> str:
        sentences = re.split(r"(?<=[.!?])\s+", str(text or "").strip())
        return " ".join(
            sentence
            for sentence in sentences
            if not any(term in sentence.casefold() for term in unsupported)
        ).strip()

    cleaned = dict(value)
    cleaned["executive_summary"] = clean(value.get("executive_summary"))
    cleaned["technical_summary"] = clean(value.get("technical_summary"))
    cleaned["key_points"] = [
        item
        for item in value.get("key_points", [])
        if isinstance(item, dict)
        and not any(term in str(item.get("text", "")).casefold() for term in unsupported)
    ]
    return cleaned


def validate_narrative(value: dict, claim_count: int, supported_claims: list | None = None) -> dict:
    if not isinstance(value, dict):
        raise LocalNarrativeError("Local model narrative must be an object")
    executive = str(value.get("executive_summary", "")).strip()[:4000]
    technical = str(value.get("technical_summary", "")).strip()[:8000]
    if not executive or not technical:
        raise LocalNarrativeError("Local model narrative omitted required summaries")
    supported_text = " ".join(str(item) for item in (supported_claims or [])).casefold()
    point_text = " ".join(
        str(item.get("text", "")) for item in value.get("key_points", []) if isinstance(item, dict)
    )
    combined = f"{executive} {technical} {point_text}".casefold()
    forbidden = {
        "attack",
        "breach",
        "bypass",
        "compromise",
        "malicious",
        "misconfiguration",
        "vulnerability",
    }
    unsupported = sorted(
        term for term in forbidden if term in combined and term not in supported_text
    )
    if unsupported:
        raise LocalNarrativeError(
            f"Local model introduced unsupported security claims: {', '.join(unsupported)}"
        )
    indicators = set(
        re.findall(
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b|\b\d{1,5}/(?:tcp|udp)\b",
            combined,
        )
    )
    altered = sorted(indicator for indicator in indicators if indicator not in supported_text)
    if altered:
        raise LocalNarrativeError(
            f"Local model introduced altered or unsupported indicators: {', '.join(altered)}"
        )
    points = []
    for item in value.get("key_points", [])[:20]:
        if not isinstance(item, dict):
            continue
        refs = sorted(
            {
                int(ref)
                for ref in item.get("claim_refs", [])
                if isinstance(ref, int) and 0 <= ref < claim_count
            }
        )
        text = str(item.get("text", "")).strip()[:1000]
        if text and (refs or claim_count == 0):
            points.append({"text": text, "claim_refs": refs})
    return {
        "executive_summary": executive,
        "technical_summary": technical,
        "key_points": points,
    }
