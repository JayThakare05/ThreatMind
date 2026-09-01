"""
Layer 3 — Output Schemas (Layer 3 → Layer 4 Contract).

Defines the InvestigatedIncident and all its sub-models.
This is the structured output consumed by Agent 3, Agent 4, and the SOC dashboard.
"""

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field


class TimelineEntry(BaseModel):
    """A single entry in the incident timeline."""

    timestamp: datetime
    event_id: str
    action: str
    event_type: str
    user: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    hostname: Optional[str] = None
    process: Optional[str] = None
    command_line: Optional[str] = None
    severity: Optional[str] = None
    mitre_technique: Optional[str] = None
    details: Optional[str] = None
    phase: Optional[str] = Field(
        default=None,
        description="Attack phase label (e.g., 'Initial Access', 'Execution')."
    )


class MitreMapping(BaseModel):
    """A MITRE ATT&CK technique mapping with evidence."""

    technique_id: str = Field(
        ...,
        description="MITRE ATT&CK technique ID (e.g., T1110)."
    )
    name: str = Field(
        ...,
        description="Technique name (e.g., Brute Force)."
    )
    tactic: Optional[str] = Field(
        default=None,
        description="MITRE tactic (e.g., Credential Access)."
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Confidence that this technique was used (0.0–1.0)."
    )
    evidence: list[str] = Field(
        default_factory=list,
        description="Event IDs supporting this mapping."
    )
    reason: str = Field(
        default="",
        description="Human-readable explanation of why this technique was mapped."
    )


class ThreatIntelResult(BaseModel):
    """Result from threat intelligence enrichment."""

    indicator: str = Field(
        ...,
        description="The indicator that was checked (IP, domain, hash, URL)."
    )
    indicator_type: str = Field(
        ...,
        description="Type of indicator: ip, domain, hash, url."
    )
    malicious: bool = Field(
        default=False,
        description="Whether the indicator is considered malicious."
    )
    confidence: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Confidence in the assessment."
    )
    source: str = Field(
        default="unknown",
        description="Source of the intelligence (e.g., mock, VirusTotal)."
    )
    details: Optional[str] = Field(
        default=None,
        description="Additional details from the intelligence source."
    )


class IncidentEntities(BaseModel):
    """Entities involved in an incident."""

    users: list[str] = Field(default_factory=list)
    source_ips: list[str] = Field(default_factory=list)
    destination_ips: list[str] = Field(default_factory=list)
    hosts: list[str] = Field(default_factory=list)
    processes: list[str] = Field(default_factory=list)


class RiskBreakdown(BaseModel):
    """Breakdown of how the risk score was calculated."""

    severity_contribution: float = 0.0
    correlation_contribution: float = 0.0
    attack_progression_contribution: float = 0.0
    mitre_contribution: float = 0.0
    threat_intel_contribution: float = 0.0
    asset_criticality_contribution: float = 0.0


class InvestigationMetadata(BaseModel):
    """Metadata about the investigation process itself."""

    investigation_start: datetime
    investigation_end: Optional[datetime] = None
    agent_version: str = "0.1.0"
    layer2_analysis_id: Optional[str] = None
    total_events_correlated: int = 0
    correlation_window_minutes: int = 5


class AIInvestigationResult(BaseModel):
    """
    Structured reasoning output from the AI Threat Investigator.
    """
    incident_id: str = Field(description="The ID of the incident being analyzed.")
    summary: str = Field(description="Brief summary of what most likely happened.")
    attack_type: str = Field(description="The likely attack pattern or category.")
    assessment: str = Field(description="Detailed narrative explaining the conclusion.")
    confidence: str = Field(description="High, Medium, or Low confidence in this assessment.")
    key_findings: list[str] = Field(description="Bullet points of high-confidence findings.")
    evidence: list[str] = Field(description="List of event IDs that support the findings.")
    attack_progression: str = Field(description="Explanation of how the attack progressed.")
    mitre_assessment: str = Field(description="Assessment of whether the deterministic MITRE mappings are accurate and supported by evidence.")
    uncertainties: list[str] = Field(description="Things that are uncertain or cannot be definitively concluded.")
    recommended_investigation: list[str] = Field(description="Additional steps a SOC analyst should take.")
    missing_evidence: list[str] = Field(description="Important evidence that would help confirm hypotheses but is currently missing.")


class InvestigatedIncident(BaseModel):
    """
    The primary output of Layer 3 — a fully investigated incident.

    Consumed by:
    - Agent 3 (Response Agent)
    - Agent 4 (Reporting Agent)
    - SOC Analyst Dashboard
    """

    incident_id: str = Field(
        ...,
        description="Unique incident identifier (e.g., INC-001)."
    )
    title: str = Field(
        ...,
        description="Human-readable incident title."
    )
    severity: str = Field(
        ...,
        description="Overall severity: LOW / MEDIUM / HIGH / CRITICAL."
    )
    risk_score: int = Field(
        ...,
        ge=0,
        le=100,
        description="Overall risk score (0–100)."
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Overall investigation confidence."
    )

    entities: IncidentEntities = Field(
        default_factory=IncidentEntities,
        description="All entities involved in the incident."
    )
    correlated_events: list[str] = Field(
        default_factory=list,
        description="Event IDs belonging to this correlated incident."
    )
    timeline: list[TimelineEntry] = Field(
        default_factory=list,
        description="Chronological event timeline."
    )
    mitre_attack: list[MitreMapping] = Field(
        default_factory=list,
        description="MITRE ATT&CK technique mappings."
    )
    threat_intel: list[ThreatIntelResult] = Field(
        default_factory=list,
        description="Threat intelligence enrichment results."
    )
    risk_breakdown: Optional[RiskBreakdown] = Field(
        default=None,
        description="Detailed risk score breakdown."
    )
    risk_factors: list[str] = Field(
        default_factory=list,
        description="Human-readable list of risk factors."
    )
    assessment: str = Field(
        default="",
        description="Investigation conclusion narrative."
    )
    ai_analysis: Optional[AIInvestigationResult] = Field(
        default=None,
        description="Optional independent AI reasoning and assessment."
    )
    investigation_metadata: Optional[InvestigationMetadata] = Field(
        default=None,
        description="Metadata about the investigation process."
    )
