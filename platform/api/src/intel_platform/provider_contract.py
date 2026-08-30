from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol

from sqlalchemy.orm import Session

from .models import CollectionJob, Target


class ProviderCancelledError(RuntimeError):
    """Raised when collection stops because an analyst requested cancellation."""


class ProviderHttpError(RuntimeError):
    """A provider HTTP failure whose message never contains request credentials."""

    def __init__(self, provider: str, status_code: int) -> None:
        self.provider = provider
        self.status_code = status_code
        super().__init__(f"{provider} returned HTTP {status_code}")


@dataclass(frozen=True)
class ProviderCapabilities:
    target_types: frozenset[str]
    passive_only: bool = True
    requires_credentials: bool = False
    supports_cancellation: bool = True


@dataclass(frozen=True)
class ProviderContext:
    db: Session
    job: CollectionJob
    target: Target
    settings: dict = field(default_factory=dict)
    credentials: dict = field(default_factory=dict)
    deadline_at: datetime | None = None


@dataclass(frozen=True)
class ProviderResult:
    result_count: int
    entity_ids: tuple[str, ...] = ()
    relationship_ids: tuple[str, ...] = ()
    metadata: dict = field(default_factory=dict)
    response_fingerprint: str | None = None
    redacted_payload: dict = field(default_factory=dict)


class CollectionProvider(Protocol):
    name: str
    capabilities: ProviderCapabilities

    def collect(self, context: ProviderContext) -> ProviderResult: ...


class ProviderRegistry:
    def __init__(self) -> None:
        self._providers: dict[str, CollectionProvider] = {}

    def register(self, provider: CollectionProvider) -> None:
        if provider.name in self._providers:
            raise ValueError(f"Provider already registered: {provider.name}")
        self._providers[provider.name] = provider

    def get(self, name: str) -> CollectionProvider:
        try:
            return self._providers[name]
        except KeyError as exc:
            raise LookupError(f"Unknown provider: {name}") from exc

    def list(self) -> tuple[CollectionProvider, ...]:
        return tuple(self._providers.values())


registry = ProviderRegistry()
