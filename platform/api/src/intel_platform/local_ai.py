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
    contract = {
        "risk_score": snapshot.risk_score,
        "risk_level": snapshot.risk_level,
        "metrics": snapshot.metrics,
        "claims": [{"index": index, **claim} for index, claim in enumerate(snapshot.claims)],
        "correlations": snapshot.correlations,
        "recommendations": snapshot.recommendations,
    }
    prompt = (
        "You are a defensive security report writer. Use only the supplied JSON contract. "
        "Do not add facts, identities, incidents, vulnerabilities, or causal claims. "
        "Never introduce breach, compromise, attack, malicious activity, or misconfiguration "
        "unless that exact concept appears in a supplied claim. "
        "Copy every IP address, domain, hash, URL, and port exactly; never reformat or infer one. "
        "Return JSON with executive_summary, technical_summary, and key_points. "
        "Each key_points item must contain text and claim_refs, an array of claim indexes. "
        "Describe correlations as inferences and preserve their limitations.\n\n"
        + json.dumps(contract, separators=(",", ":"), sort_keys=True)
    )
    endpoint = f"{base_url.rstrip('/')}/api/generate"
    try:
        response = httpx.post(
            endpoint,
            json={"model": model, "prompt": prompt, "stream": False, "format": "json"},
            timeout=timeout_seconds,
        )
        response.raise_for_status()
        envelope = response.json()
        raw = json.loads(envelope.get("response", "{}"))
    except (httpx.HTTPError, json.JSONDecodeError, TypeError) as exc:
        raise LocalNarrativeError(f"Local model response failed: {exc}") from exc
    corrected = correct_unambiguous_indicators(raw, snapshot.claims)
    sanitized = strip_unsupported_security_sentences(corrected, snapshot.claims)
    return validate_narrative(sanitized, len(snapshot.claims), snapshot.claims)


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
