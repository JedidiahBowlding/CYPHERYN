from intel_platform.provider_safety import (
    ProviderBlockedError,
    counts_toward_circuit_breaker,
    default_timeout_seconds,
)


def test_active_scanner_timeout_profiles_are_long_enough_to_complete() -> None:
    assert default_timeout_seconds("nmap") == 300
    assert default_timeout_seconds("nuclei") == 180
    assert default_timeout_seconds("zap_passive") == 180
    assert default_timeout_seconds("openvas") == 900
    assert default_timeout_seconds("dns") == 20


def test_policy_rejections_do_not_extend_provider_circuit_breaker() -> None:
    assert not counts_toward_circuit_breaker(
        ProviderBlockedError("Provider circuit breaker is open")
    )
    assert counts_toward_circuit_breaker(TimeoutError("provider timed out"))
