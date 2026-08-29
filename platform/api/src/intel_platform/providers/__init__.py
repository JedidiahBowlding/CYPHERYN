from ..provider_contract import ProviderRegistry
from .certificate_transparency import CertificateTransparencyProvider
from .direct_verifier import DirectVerifierProvider
from .dns_discovery import DnsDiscoveryProvider
from .domain_security import DomainSecurityProvider
from .hibp import HibpProvider
from .local_observer import LocalObserverProvider
from .local_tools import LOCAL_TOOL_PROVIDERS
from .maigret import MaigretProvider
from .openvas import OpenVasProvider
from .public_identity import PublicIdentityProvider
from .rdap import RdapProvider
from .safe_mock import SafeMockProvider
from .source_code import SOURCE_CODE_PROVIDERS
from .supply_chain import SUPPLY_CHAIN_PROVIDERS
from .taxii import TaxiiProvider
from .threat_intel import THREAT_PROVIDERS
from .web_posture import WebPostureProvider


def register_builtin_providers(registry: ProviderRegistry) -> None:
    for provider_type in LOCAL_TOOL_PROVIDERS:
        try:
            registry.register(provider_type())
        except ValueError:
            pass
    try:
        registry.register(DirectVerifierProvider())
    except ValueError:
        pass
    try:
        registry.register(PublicIdentityProvider())
    except ValueError:
        pass
    try:
        registry.register(MaigretProvider())
    except ValueError:
        pass
    try:
        registry.register(HibpProvider())
    except ValueError:
        pass
    try:
        registry.register(WebPostureProvider())
    except ValueError:
        pass
    try:
        registry.register(CertificateTransparencyProvider())
    except ValueError:
        pass
    try:
        registry.register(DnsDiscoveryProvider())
    except ValueError:
        pass
    try:
        registry.register(DomainSecurityProvider())
    except ValueError:
        pass
    try:
        registry.register(SafeMockProvider())
    except ValueError:
        pass
    try:
        registry.register(LocalObserverProvider())
    except ValueError:
        pass
    try:
        registry.register(OpenVasProvider())
    except ValueError:
        pass
    try:
        registry.register(TaxiiProvider())
    except ValueError:
        pass
    for provider_type in THREAT_PROVIDERS:
        try:
            registry.register(provider_type())
        except ValueError:
            pass
    for provider_type in SOURCE_CODE_PROVIDERS:
        try:
            registry.register(provider_type())
        except ValueError:
            pass
    for provider_type in SUPPLY_CHAIN_PROVIDERS:
        try:
            registry.register(provider_type())
        except ValueError:
            pass
    try:
        registry.register(RdapProvider())
    except ValueError:
        pass
