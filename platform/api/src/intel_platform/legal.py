from dataclasses import dataclass
from datetime import date

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import LegalAcceptance


@dataclass(frozen=True)
class AgreementRelease:
    terms_version: str
    responsible_use_version: str
    effective_date: date
    last_updated: date


# This is the single authoritative agreement release. A material legal update
# should change the relevant version(s) and dates together.
CURRENT_AGREEMENTS = AgreementRelease(
    terms_version="1.0",
    responsible_use_version="1.0",
    effective_date=date(2026, 9, 3),
    last_updated=date(2026, 9, 3),
)


def current_acceptance(db: Session, user_id: str) -> LegalAcceptance | None:
    return db.scalar(
        select(LegalAcceptance)
        .where(
            LegalAcceptance.user_id == user_id,
            LegalAcceptance.terms_version == CURRENT_AGREEMENTS.terms_version,
            LegalAcceptance.responsible_use_version
            == CURRENT_AGREEMENTS.responsible_use_version,
        )
        .order_by(LegalAcceptance.accepted_at.desc())
    )
