from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import smtplib
import socket
import ssl
from datetime import UTC, datetime, timedelta
from email.message import EmailMessage
from urllib.parse import urlsplit

import httpx
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from .config import get_settings
from .database import SessionLocal
from .models import AlertNotification, NotificationPreference
from .provider_secrets import ProviderSecretError, decrypt_credentials


def validate_webhook_url(value: str) -> str:
    parsed = urlsplit(value.strip())
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Webhook URL must use HTTPS without embedded credentials")
    try:
        addresses = {
            ipaddress.ip_address(item[4][0])
            for item in socket.getaddrinfo(parsed.hostname, parsed.port or 443)
        }
    except (OSError, ValueError) as exc:
        raise ValueError("Webhook hostname could not be resolved") from exc
    if not addresses or any(not address.is_global for address in addresses):
        raise ValueError("Webhook must resolve only to public addresses")
    return value.strip()


def preference_for(db: Session, organization_id: str) -> NotificationPreference | None:
    return db.scalar(
        select(NotificationPreference).where(
            NotificationPreference.organization_id == organization_id
        )
    )


def _suppression_reason(preference: NotificationPreference | None, now: datetime) -> str:
    if preference is None:
        return ""
    start, end = preference.maintenance_starts_at, preference.maintenance_ends_at
    if start and start.tzinfo is None:
        start = start.replace(tzinfo=UTC)
    if end and end.tzinfo is None:
        end = end.replace(tzinfo=UTC)
    if start and end and start <= now <= end:
        return "maintenance_window"
    quiet_start, quiet_end = preference.quiet_start_hour, preference.quiet_end_hour
    if quiet_start is not None and quiet_end is not None:
        hour = now.hour
        quiet = (
            quiet_start <= hour < quiet_end
            if quiet_start < quiet_end
            else hour >= quiet_start or hour < quiet_end
        )
        if quiet:
            return "quiet_period"
    return ""


def emit_notification(
    db: Session,
    *,
    organization_id: str,
    event_type: str,
    title: str,
    message: str,
    dedupe_key: str,
    severity: str = "info",
    investigation_id: str | None = None,
    finding_id: str | None = None,
) -> AlertNotification:
    now = datetime.now(UTC)
    preference = preference_for(db, organization_id)
    dedupe_minutes = preference.dedupe_minutes if preference else 60
    existing = db.scalar(
        select(AlertNotification)
        .where(
            AlertNotification.organization_id == organization_id,
            AlertNotification.dedupe_key == dedupe_key[:500],
            AlertNotification.last_seen_at >= now - timedelta(minutes=dedupe_minutes),
        )
        .order_by(AlertNotification.last_seen_at.desc())
    )
    if existing is not None:
        existing.occurrence_count += 1
        existing.last_seen_at = now
        existing.read_at = None
        existing.message = message
        return existing
    suppressed = _suppression_reason(preference, now)
    notification = AlertNotification(
        organization_id=organization_id,
        investigation_id=investigation_id,
        finding_id=finding_id,
        event_type=event_type,
        severity=severity,
        title=title[:300],
        message=message,
        dedupe_key=dedupe_key[:500],
        external_suppressed_reason=suppressed,
        email_status=(
            "suppressed"
            if suppressed
            else "pending"
            if preference and preference.email_enabled
            else "disabled"
        ),
        webhook_status=(
            "suppressed"
            if suppressed
            else "pending"
            if preference and preference.webhook_enabled
            else "disabled"
        ),
    )
    db.add(notification)
    db.flush()
    return notification


def _deliver_email(notification: AlertNotification, preference: NotificationPreference) -> None:
    settings = get_settings()
    if not settings.smtp_host or not settings.smtp_from:
        raise RuntimeError("SMTP is not configured")
    message = EmailMessage()
    message["Subject"] = f"[CYPHERYN] {notification.title}"
    message["From"] = settings.smtp_from
    message["To"] = preference.email_to
    message.set_content(notification.message)
    with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=20) as client:
        if settings.smtp_use_tls:
            client.starttls(context=ssl.create_default_context())
        if settings.smtp_username:
            client.login(settings.smtp_username, settings.smtp_password)
        client.send_message(message)


def _deliver_webhook(notification: AlertNotification, preference: NotificationPreference) -> None:
    url = validate_webhook_url(preference.webhook_url)
    payload = {
        "id": notification.id,
        "event_type": notification.event_type,
        "severity": notification.severity,
        "title": notification.title,
        "message": notification.message,
        "investigation_id": notification.investigation_id,
        "finding_id": notification.finding_id,
        "occurred_at": notification.created_at.isoformat(),
    }
    encoded = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    headers = {"Content-Type": "application/json", "User-Agent": "CYPHERYN-Alerts/1.0"}
    if preference.encrypted_webhook_secret:
        settings = get_settings()
        try:
            secret = decrypt_credentials(
                preference.encrypted_webhook_secret, settings.provider_encryption_key
            ).get("secret", "")
        except ProviderSecretError as exc:
            raise RuntimeError("Webhook signing secret could not be decrypted") from exc
        if secret:
            headers["X-CYPHERYN-Signature"] = (
                "sha256=" + hmac.new(secret.encode(), encoded, hashlib.sha256).hexdigest()
            )
    response = httpx.post(url, content=encoded, headers=headers, timeout=20, follow_redirects=False)
    if response.status_code < 200 or response.status_code >= 300:
        raise RuntimeError(f"Webhook returned HTTP {response.status_code}")


def deliver_pending_notifications(session_factory=SessionLocal) -> int:
    delivered = 0
    with session_factory() as db:
        notifications = list(
            db.scalars(
                select(AlertNotification)
                .where(
                    or_(
                        AlertNotification.email_status == "pending",
                        AlertNotification.webhook_status == "pending",
                    )
                )
                .order_by(AlertNotification.created_at)
                .limit(20)
            )
        )
        for notification in notifications:
            preference = preference_for(db, notification.organization_id)
            if preference is None:
                notification.email_status = "disabled"
                notification.webhook_status = "disabled"
                continue
            errors = []
            if notification.email_status == "pending":
                try:
                    _deliver_email(notification, preference)
                    notification.email_status = "delivered"
                    delivered += 1
                except (OSError, RuntimeError, smtplib.SMTPException) as exc:
                    notification.email_status = "failed"
                    errors.append(str(exc))
            if notification.webhook_status == "pending":
                try:
                    _deliver_webhook(notification, preference)
                    notification.webhook_status = "delivered"
                    delivered += 1
                except (httpx.HTTPError, OSError, RuntimeError, ValueError) as exc:
                    notification.webhook_status = "failed"
                    errors.append(str(exc))
            notification.delivery_error = "; ".join(errors)[:500]
        db.commit()
    return delivered
