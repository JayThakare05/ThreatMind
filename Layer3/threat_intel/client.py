"""
Layer 3 — Threat Intelligence Client.

Provides an abstraction for threat intelligence enrichment.

For the first version, uses a local/mock implementation that requires
no external API calls or API keys. The interface is designed so that
real providers (VirusTotal, AbuseIPDB, etc.) can be plugged in later.

API keys should NEVER be hard-coded. Use environment variables via .env.
"""

import os
from abc import ABC, abstractmethod
from typing import Optional

from Layer3.config.settings import THREAT_INTEL_API_KEY, THREAT_INTEL_PROVIDER
from Layer3.schemas.incident import ThreatIntelResult


class ThreatIntelProvider(ABC):
    """Abstract interface for threat intelligence providers."""

    @abstractmethod
    def check_ip(self, ip: str) -> ThreatIntelResult:
        """Check reputation of an IP address."""
        ...

    @abstractmethod
    def check_domain(self, domain: str) -> ThreatIntelResult:
        """Check reputation of a domain."""
        ...

    @abstractmethod
    def check_hash(self, file_hash: str) -> ThreatIntelResult:
        """Check reputation of a file hash."""
        ...

    @abstractmethod
    def check_url(self, url: str) -> ThreatIntelResult:
        """Check reputation of a URL."""
        ...


class MockThreatIntelProvider(ThreatIntelProvider):
    """
    Mock threat intelligence provider for development and testing.

    Returns local/static results without making external API calls.
    Includes a small set of "known malicious" indicators for testing.
    """

    # Mock known-malicious indicators for testing
    _MOCK_MALICIOUS_IPS: set[str] = {
        "185.10.20.50",   # Sample dataset IP
        "10.0.0.99",      # Test IP
        "192.168.1.100",  # Test IP
    }

    def check_ip(self, ip: str) -> ThreatIntelResult:
        """Check IP reputation against mock data."""
        is_malicious = ip in self._MOCK_MALICIOUS_IPS
        return ThreatIntelResult(
            indicator=ip,
            indicator_type="ip",
            malicious=is_malicious,
            confidence=0.75 if is_malicious else 0.0,
            source="mock",
            details=(
                "Known malicious IP in mock threat intel database"
                if is_malicious
                else "No threat intel data available (mock provider)"
            ),
        )

    def check_domain(self, domain: str) -> ThreatIntelResult:
        """Check domain reputation (mock — always returns benign)."""
        return ThreatIntelResult(
            indicator=domain,
            indicator_type="domain",
            malicious=False,
            confidence=0.0,
            source="mock",
            details="No threat intel data available (mock provider)",
        )

    def check_hash(self, file_hash: str) -> ThreatIntelResult:
        """Check file hash reputation (mock — always returns benign)."""
        return ThreatIntelResult(
            indicator=file_hash,
            indicator_type="hash",
            malicious=False,
            confidence=0.0,
            source="mock",
            details="No threat intel data available (mock provider)",
        )

    def check_url(self, url: str) -> ThreatIntelResult:
        """Check URL reputation (mock — always returns benign)."""
        return ThreatIntelResult(
            indicator=url,
            indicator_type="url",
            malicious=False,
            confidence=0.0,
            source="mock",
            details="No threat intel data available (mock provider)",
        )


def get_threat_intel_provider() -> ThreatIntelProvider:
    """
    Factory function to get the configured threat intelligence provider.

    Reads THREAT_INTEL_PROVIDER from environment/config. Currently only
    supports 'mock'. Future providers can be added here.

    Returns:
        An instance of ThreatIntelProvider.
    """
    provider_name = THREAT_INTEL_PROVIDER.lower()

    if provider_name == "mock":
        return MockThreatIntelProvider()

    # Future: add real providers here
    # elif provider_name == "virustotal":
    #     return VirusTotalProvider(api_key=THREAT_INTEL_API_KEY)

    # Default to mock
    return MockThreatIntelProvider()


def enrich_indicators(
    provider: ThreatIntelProvider,
    ips: list[str] | None = None,
    domains: list[str] | None = None,
    hashes: list[str] | None = None,
    urls: list[str] | None = None,
) -> list[ThreatIntelResult]:
    """
    Enrich a set of indicators using the given threat intel provider.

    Args:
        provider: The threat intelligence provider to use.
        ips: List of IP addresses to check.
        domains: List of domains to check.
        hashes: List of file hashes to check.
        urls: List of URLs to check.

    Returns:
        List of ThreatIntelResult objects.
    """
    results: list[ThreatIntelResult] = []

    for ip in (ips or []):
        results.append(provider.check_ip(ip))

    for domain in (domains or []):
        results.append(provider.check_domain(domain))

    for file_hash in (hashes or []):
        results.append(provider.check_hash(file_hash))

    for url in (urls or []):
        results.append(provider.check_url(url))

    return results
