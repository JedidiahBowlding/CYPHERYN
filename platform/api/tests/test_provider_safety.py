from intel_platform.provider_safety import default_timeout_seconds


def test_active_scanner_timeout_profiles_are_long_enough_to_complete() -> None:
    assert default_timeout_seconds("nmap") == 90
    assert default_timeout_seconds("nuclei") == 180
    assert default_timeout_seconds("zap_passive") == 180
    assert default_timeout_seconds("openvas") == 900
    assert default_timeout_seconds("dns") == 20
