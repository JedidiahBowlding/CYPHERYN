from types import SimpleNamespace

from intel_platform.analysis import finding_risk_domain, is_risk_finding
from intel_platform.providers.domain_security import DomainSecurityProvider


def test_lookalikes_are_brand_risk_not_host_risk() -> None:
    assert (
        finding_risk_domain(SimpleNamespace(rule_id="domain.registered_lookalike"))
        == "brand"
    )
    assert finding_risk_domain(SimpleNamespace(rule_id="web.cwe.693")) == "host"


def test_optional_bimi_and_scanner_diagnostics_are_not_risk_findings() -> None:
    assert not is_risk_finding(SimpleNamespace(rule_id="email.missing_bimi"))
    assert not is_risk_finding(SimpleNamespace(rule_id="testssl.scanProblem"))
    assert not is_risk_finding(SimpleNamespace(rule_id="nikto.FAIL"))
    assert is_risk_finding(SimpleNamespace(rule_id="testssl.heartbleed"))


def test_missing_bimi_is_posture_data_not_a_vulnerability() -> None:
    observations = {
        "domain": "example.test",
        "email_security": {
            "spf": True,
            "dmarc": True,
            "mta_sts": True,
            "tls_rpt": True,
            "bimi": False,
        },
        "certificate": {},
    }
    assert DomainSecurityProvider._findings(observations) == []
