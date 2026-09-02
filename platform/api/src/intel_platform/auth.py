import hmac
from dataclasses import dataclass

import jwt
from fastapi import Depends, HTTPException, Request, status
from jwt import PyJWKClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import Settings, get_settings
from .database import get_db
from .models import Membership, MembershipRole, User


@dataclass(frozen=True)
class Principal:
    subject: str
    email: str | None = None


def get_principal(
    request: Request,
    settings: Settings = Depends(get_settings),
) -> Principal:
    if settings.allow_dev_identity:
        subject = request.headers.get("X-Dev-Subject")
        if subject:
            return Principal(subject=subject, email=request.headers.get("X-Dev-Email"))

    # The public production API is reached through Caddy after oauth2-proxy has
    # authenticated the browser session. Identity headers alone are never
    # trusted: Caddy adds a private shared secret at the final API hop, and the
    # API compares it in constant time before accepting the asserted subject.
    if settings.trusted_auth_proxy:
        supplied_secret = request.headers.get("X-Cypheryn-Proxy-Secret", "")
        subject = request.headers.get("X-Auth-Request-User", "").strip()
        if (
            supplied_secret
            and subject
            and hmac.compare_digest(supplied_secret, settings.auth_proxy_secret)
        ):
            return Principal(
                subject=subject,
                email=request.headers.get("X-Auth-Request-Email"),
            )

    authorization = request.headers.get("Authorization", "")
    if not authorization.startswith("Bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Bearer authentication required")
    if not settings.oidc_jwks_url or not settings.oidc_issuer:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "OIDC is not configured")

    token = authorization.removeprefix("Bearer ").strip()
    try:
        signing_key = PyJWKClient(settings.oidc_jwks_url).get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256", "ES256"],
            audience=settings.oidc_audience,
            issuer=settings.oidc_issuer,
            options={"require": ["exp", "iat", "sub"]},
        )
    except jwt.PyJWTError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid bearer token") from exc
    return Principal(subject=claims["sub"], email=claims.get("email"))


def get_current_user(
    principal: Principal = Depends(get_principal), db: Session = Depends(get_db)
) -> User:
    user = db.scalar(select(User).where(User.external_subject == principal.subject))
    if user is None:
        user = User(external_subject=principal.subject, email=principal.email)
        db.add(user)
        db.commit()
        db.refresh(user)
    return user


WRITE_ROLES = {
    MembershipRole.ORGANIZATION_ADMIN,
    MembershipRole.INVESTIGATION_LEAD,
    MembershipRole.ANALYST,
}


def membership_for(db: Session, user_id: str, organization_id: str) -> Membership:
    membership = db.scalar(
        select(Membership).where(
            Membership.user_id == user_id,
            Membership.organization_id == organization_id,
        )
    )
    if membership is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Resource not found")
    return membership


def require_writer(db: Session, user_id: str, organization_id: str) -> Membership:
    membership = membership_for(db, user_id, organization_id)
    if membership.role not in WRITE_ROLES:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Write permission required")
    return membership
