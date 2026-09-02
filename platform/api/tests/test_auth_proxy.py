from starlette.requests import Request

from intel_platform.auth import get_principal
from intel_platform.config import Settings

SECRET = "a" * 32


def request_with_headers(headers: dict[str, str]) -> Request:
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/api/v1/organizations",
            "headers": [(key.lower().encode(), value.encode()) for key, value in headers.items()],
        }
    )


def proxy_settings() -> Settings:
    return Settings(trusted_auth_proxy=True, auth_proxy_secret=SECRET)


def test_trusted_proxy_identity_is_accepted() -> None:
    principal = get_principal(
        request_with_headers(
            {
                "X-Cypheryn-Proxy-Secret": SECRET,
                "X-Auth-Request-User": "google-oauth2|123",
                "X-Auth-Request-Email": "queryone23@gmail.com",
            }
        ),
        proxy_settings(),
    )

    assert principal.subject == "google-oauth2|123"
    assert principal.email == "queryone23@gmail.com"


def test_spoofed_proxy_identity_without_secret_is_rejected() -> None:
    request = request_with_headers(
        {
            "X-Auth-Request-User": "google-oauth2|attacker",
            "X-Auth-Request-Email": "attacker@example.com",
        }
    )

    try:
        get_principal(request, proxy_settings())
    except Exception as exc:
        assert getattr(exc, "status_code", None) == 401
    else:
        raise AssertionError("spoofed proxy identity was accepted")


def test_spoofed_proxy_identity_with_wrong_secret_is_rejected() -> None:
    request = request_with_headers(
        {
            "X-Cypheryn-Proxy-Secret": "b" * 32,
            "X-Auth-Request-User": "google-oauth2|attacker",
        }
    )

    try:
        get_principal(request, proxy_settings())
    except Exception as exc:
        assert getattr(exc, "status_code", None) == 401
    else:
        raise AssertionError("proxy identity with wrong secret was accepted")
