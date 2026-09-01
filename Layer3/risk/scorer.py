"""
Layer 3 — Dynamic Risk Scorer.

Calculates an explainable risk score (0–100) based on configurable
weighted factors. Every score includes a breakdown of contributing
factors and a human-readable explanation.

Risk weights and severity thresholds are defined in config/settings.py
and can be overridden via environment variables.
"""

from Layer3.config.settings import (
    RISK_WEIGHTS,
    SEVERITY_SCORES,
    get_severity_label,
)
from Layer3.correlation.correlator import CorrelatedGroup
from Layer3.schemas.incident import (
    MitreMapping,
    RiskBreakdown,
    ThreatIntelResult,
)


def calculate_risk_score(
    group: CorrelatedGroup,
    mitre_mappings: list[MitreMapping],
    threat_intel_results: list[ThreatIntelResult],
    asset_criticality: float = 0.5,
) -> tuple[int, RiskBreakdown, list[str]]:
    """
    Calculate an explainable dynamic risk score for a correlated incident.

    Args:
        group: The correlated event group.
        mitre_mappings: MITRE ATT&CK technique mappings for this group.
        threat_intel_results: Threat intelligence results for entities.
        asset_criticality: Asset criticality factor (0.0–1.0). Defaults to 0.5.

    Returns:
        Tuple of:
        - risk_score (int, 0–100)
        - RiskBreakdown with per-factor contributions
        - risk_factors (list of human-readable explanations)
    """
    risk_factors: list[str] = []

    # ── 1. Severity Contribution ──────────────────────────────────────────
    severity_raw = _calculate_severity_component(group)
    severity_contribution = severity_raw * RISK_WEIGHTS["severity"] * 100
    if severity_raw > 0.5:
        risk_factors.append(
            f"High severity events detected (severity score: {severity_raw:.2f})"
        )

    # ── 2. Correlation Contribution ───────────────────────────────────────
    correlation_raw = _calculate_correlation_component(group)
    correlation_contribution = correlation_raw * RISK_WEIGHTS["correlation"] * 100
    if len(group.events) > 1:
        risk_factors.append(
            f"Multiple correlated events ({len(group.events)} events, "
            f"strength: {group.correlation_strength:.2f})"
        )

    # ── 3. Attack Progression Contribution ────────────────────────────────
    progression_raw = _calculate_progression_component(group)
    progression_contribution = (
        progression_raw * RISK_WEIGHTS["attack_progression"] * 100
    )
    if group.attack_progression_detected:
        risk_factors.append(
            f"Attack progression detected: {', '.join(group.attack_phases)}"
        )

    # ── 4. MITRE Contribution ─────────────────────────────────────────────
    mitre_raw = _calculate_mitre_component(mitre_mappings)
    mitre_contribution = mitre_raw * RISK_WEIGHTS["mitre"] * 100
    if mitre_mappings:
        technique_names = [m.name for m in mitre_mappings]
        risk_factors.append(
            f"MITRE ATT&CK techniques identified: {', '.join(technique_names)}"
        )

    # ── 5. Threat Intelligence Contribution ───────────────────────────────
    ti_raw = _calculate_threat_intel_component(threat_intel_results)
    ti_contribution = ti_raw * RISK_WEIGHTS["threat_intel"] * 100
    malicious_indicators = [r for r in threat_intel_results if r.malicious]
    if malicious_indicators:
        indicators = [r.indicator for r in malicious_indicators]
        risk_factors.append(
            f"Malicious indicators detected: {', '.join(indicators)}"
        )

    # ── 6. Asset Criticality Contribution ─────────────────────────────────
    criticality_contribution = (
        asset_criticality * RISK_WEIGHTS["asset_criticality"] * 100
    )
    if asset_criticality > 0.7:
        risk_factors.append(
            f"High asset criticality ({asset_criticality:.2f})"
        )

    # ── Total Score ───────────────────────────────────────────────────────
    raw_score = (
        severity_contribution
        + correlation_contribution
        + progression_contribution
        + mitre_contribution
        + ti_contribution
        + criticality_contribution
    )

    # Clamp to 0–100
    risk_score = max(0, min(100, int(round(raw_score))))

    breakdown = RiskBreakdown(
        severity_contribution=round(severity_contribution, 2),
        correlation_contribution=round(correlation_contribution, 2),
        attack_progression_contribution=round(progression_contribution, 2),
        mitre_contribution=round(mitre_contribution, 2),
        threat_intel_contribution=round(ti_contribution, 2),
        asset_criticality_contribution=round(criticality_contribution, 2),
    )

    return risk_score, breakdown, risk_factors


def _calculate_severity_component(group: CorrelatedGroup) -> float:
    """
    Calculate severity component based on the highest severity event.
    Returns 0.0–1.0.
    """
    if not group.events:
        return 0.0

    max_score = max(
        SEVERITY_SCORES.get(e.severity.upper(), 10) for e in group.events
    )
    return max_score / 100.0


def _calculate_correlation_component(group: CorrelatedGroup) -> float:
    """
    Calculate correlation component based on group size and strength.
    Returns 0.0–1.0.
    """
    if len(group.events) <= 1:
        return 0.0

    # More events = higher risk (capped at 10 events for full score)
    event_factor = min(len(group.events) / 10.0, 1.0)

    # Combine with correlation strength
    strength_factor = min(group.correlation_strength, 1.0)

    return (event_factor + strength_factor) / 2.0


def _calculate_progression_component(group: CorrelatedGroup) -> float:
    """
    Calculate attack progression component.
    Returns 0.0–1.0.
    """
    if not group.attack_progression_detected:
        return 0.0

    # More matched phases = higher score
    phase_count = len(group.attack_phases)
    return min(phase_count / 3.0, 1.0)


def _calculate_mitre_component(mappings: list[MitreMapping]) -> float:
    """
    Calculate MITRE component based on number and confidence of mappings.
    Returns 0.0–1.0.
    """
    if not mappings:
        return 0.0

    # Average confidence weighted by number of techniques
    avg_confidence = sum(m.confidence for m in mappings) / len(mappings)
    technique_factor = min(len(mappings) / 5.0, 1.0)

    return (avg_confidence + technique_factor) / 2.0


def _calculate_threat_intel_component(
    results: list[ThreatIntelResult],
) -> float:
    """
    Calculate threat intelligence component.
    Returns 0.0–1.0.
    """
    if not results:
        return 0.0

    malicious_count = sum(1 for r in results if r.malicious)
    if malicious_count == 0:
        return 0.0

    # Ratio of malicious indicators
    malicious_ratio = malicious_count / len(results)

    # Average confidence of malicious results
    malicious_results = [r for r in results if r.malicious]
    avg_confidence = (
        sum(r.confidence for r in malicious_results) / len(malicious_results)
    )

    return (malicious_ratio + avg_confidence) / 2.0
