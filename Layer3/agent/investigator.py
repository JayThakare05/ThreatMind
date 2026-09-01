"""
Layer 3 — Threat Investigation Agent (Orchestrator).

Agent 2 orchestrates the complete investigation pipeline:

    Layer 2 suspicious events
            ↓
    1. Validate input
            ↓
    2. Correlate events
            ↓
    3. Extract entities
            ↓
    4. Build entity relationships
            ↓
    5. Reconstruct timeline
            ↓
    6. Map MITRE ATT&CK
            ↓
    7. Enrich with threat intelligence
            ↓
    8. Calculate dynamic risk
            ↓
    9. Generate investigation assessment
            ↓
    Investigated Incident(s)

Phase 1: Deterministic — no LLM reasoning.
Phase 3+: Will introduce LLM-driven investigation planning.
"""

import uuid
from datetime import datetime

from Layer3.agent.state import InvestigationPhase, InvestigationState
from Layer3.agent.llm_investigator import LLMInvestigator
from Layer3.config.settings import CORRELATION_WINDOW_MINUTES, get_severity_label
from Layer3.correlation.correlator import CorrelatedGroup, correlate_events
from Layer3.correlation.entities import (
    build_entity_graph,
    extract_entities,
)
from Layer3.mitre.mapper import get_mitre_event_map, map_techniques
from Layer3.risk.scorer import calculate_risk_score
from Layer3.schemas.events import Layer2Output, SuspiciousEvent
from Layer3.schemas.incident import (
    IncidentEntities,
    InvestigatedIncident,
    InvestigationMetadata,
)
from Layer3.threat_intel.client import (
    enrich_indicators,
    get_threat_intel_provider,
)
from Layer3.timeline.builder import build_timeline, describe_attack_progression


class ThreatInvestigator:
    """
    Agent 2 — Threat Investigation Agent.

    Orchestrates the deterministic investigation pipeline.
    Takes Layer 2 output and produces one or more InvestigatedIncident objects.
    """

    def __init__(self):
        self._threat_intel = get_threat_intel_provider()
        self._llm_investigator = LLMInvestigator()
        self._incident_counter = 0

    def investigate(self, layer2_output: Layer2Output) -> list[InvestigatedIncident]:
        """
        Run the full investigation pipeline on Layer 2 output.

        Args:
            layer2_output: Batch of suspicious events from Layer 2.

        Returns:
            List of InvestigatedIncident objects, one per correlated group.
        """
        state = InvestigationState(
            investigation_id=f"INV-{uuid.uuid4().hex[:8].upper()}",
            started_at=datetime.utcnow(),
            layer2_output=layer2_output,
        )

        try:
            # ── Step 1: Validate Input ────────────────────────────────────
            state.set_phase(InvestigationPhase.VALIDATING)
            events = self._validate_input(layer2_output)
            if not events:
                state.add_error("No valid suspicious events to investigate.")
                return []

            # ── Step 2: Correlate Events ──────────────────────────────────
            state.set_phase(InvestigationPhase.CORRELATING)
            groups = correlate_events(events)
            state.correlated_group_count = len(groups)

            # ── Process each correlated group into an incident ────────────
            incidents: list[InvestigatedIncident] = []
            for group in groups:
                incident = self._investigate_group(group, layer2_output.analysis_id)
                incidents.append(incident)

            state.incidents = incidents
            state.completed_at = datetime.utcnow()
            state.set_phase(InvestigationPhase.COMPLETED)

            return incidents

        except Exception as e:
            state.add_error(f"Investigation failed: {str(e)}")
            raise

    def _validate_input(self, layer2_output: Layer2Output) -> list[SuspiciousEvent]:
        """Validate and filter the input events."""
        valid_events: list[SuspiciousEvent] = []

        for event in layer2_output.suspicious_events:
            # Basic validation — ensure required fields are present
            if event.event_id and event.timestamp and event.event_type:
                valid_events.append(event)

        return valid_events

    def _investigate_group(
        self,
        group: CorrelatedGroup,
        analysis_id: str,
    ) -> InvestigatedIncident:
        """
        Investigate a single correlated event group through all pipeline stages.

        Args:
            group: A CorrelatedGroup of related suspicious events.
            analysis_id: The Layer 2 analysis ID for traceability.

        Returns:
            A fully populated InvestigatedIncident.
        """
        self._incident_counter += 1
        incident_id = f"INC-{self._incident_counter:03d}"

        # ── Step 3: Extract Entities ──────────────────────────────────────
        entities = extract_entities(group.events)

        # ── Step 4: Build Entity Relationships ────────────────────────────
        entity_graph = build_entity_graph(group.events)

        # ── Step 5: Map MITRE ATT&CK ─────────────────────────────────────
        mitre_mappings = map_techniques(group.events)
        mitre_event_map = get_mitre_event_map(mitre_mappings)

        # ── Step 6: Reconstruct Timeline ──────────────────────────────────
        timeline = build_timeline(group.events, mitre_map=mitre_event_map)

        # ── Step 7: Enrich with Threat Intelligence ───────────────────────
        threat_intel_results = enrich_indicators(
            provider=self._threat_intel,
            ips=entities.source_ips + entities.destination_ips,
        )

        # ── Step 8: Calculate Dynamic Risk ────────────────────────────────
        risk_score, risk_breakdown, risk_factors = calculate_risk_score(
            group=group,
            mitre_mappings=mitre_mappings,
            threat_intel_results=threat_intel_results,
        )

        severity = get_severity_label(risk_score)

        # ── Step 9: Generate Assessment ───────────────────────────────────
        assessment = self._generate_assessment(
            group, entities, mitre_mappings, risk_score, severity
        )

        # Calculate overall confidence
        confidence = self._calculate_confidence(
            group, mitre_mappings, threat_intel_results
        )

        # Build title
        title = self._generate_title(entities, mitre_mappings, group)

        # ── Assemble Investigated Incident ────────────────────────────────
        incident = InvestigatedIncident(
            incident_id=incident_id,
            title=title,
            severity=severity,
            risk_score=risk_score,
            confidence=round(confidence, 2),
            entities=entities,
            correlated_events=group.event_ids,
            timeline=timeline,
            mitre_attack=mitre_mappings,
            threat_intel=threat_intel_results,
            risk_breakdown=risk_breakdown,
            risk_factors=risk_factors,
            assessment=assessment,
            investigation_metadata=InvestigationMetadata(
                investigation_start=datetime.utcnow(),
                investigation_end=datetime.utcnow(),
                layer2_analysis_id=analysis_id,
                total_events_correlated=len(group.events),
                correlation_window_minutes=CORRELATION_WINDOW_MINUTES,
            ),
        )

        # ── Step 10: AI Investigation (Phase 2) ───────────────────────────
        ai_result = self._llm_investigator.analyze(incident)
        if ai_result:
            incident.ai_analysis = ai_result

        return incident

    def _generate_title(
        self,
        entities: IncidentEntities,
        mitre_mappings: list,
        group: CorrelatedGroup,
    ) -> str:
        """Generate a human-readable incident title."""
        parts: list[str] = []

        if group.attack_progression_detected:
            parts.append("Multi-Stage Attack")
        elif any(m.technique_id == "T1110" for m in mitre_mappings):
            parts.append("Brute Force Attack")
        elif any("T1059" in m.technique_id for m in mitre_mappings):
            parts.append("Suspicious Execution")
        else:
            parts.append("Suspicious Activity")

        if entities.users:
            parts.append(f"targeting {', '.join(entities.users)}")

        if entities.hosts:
            parts.append(f"on {', '.join(entities.hosts)}")

        return " ".join(parts)

    def _generate_assessment(
        self,
        group: CorrelatedGroup,
        entities: IncidentEntities,
        mitre_mappings: list,
        risk_score: int,
        severity: str,
    ) -> str:
        """Generate a human-readable investigation assessment narrative."""
        parts: list[str] = []

        # Describe what was observed
        parts.append(
            f"Investigation of {len(group.events)} correlated events "
            f"identified a {severity.lower()}-severity incident "
            f"(risk score: {risk_score}/100)."
        )

        # Describe entities
        if entities.users:
            parts.append(
                f"Affected user(s): {', '.join(entities.users)}."
            )
        if entities.source_ips:
            parts.append(
                f"Source IP(s): {', '.join(entities.source_ips)}."
            )
        if entities.hosts:
            parts.append(
                f"Target host(s): {', '.join(entities.hosts)}."
            )

        # Describe attack progression
        if group.attack_progression_detected:
            progression = describe_attack_progression(
                build_timeline(group.events)
            )
            parts.append(progression)

        # Describe MITRE techniques
        if mitre_mappings:
            technique_strs = [
                f"{m.name} ({m.technique_id}, confidence: {m.confidence:.0%})"
                for m in mitre_mappings
            ]
            parts.append(
                f"MITRE ATT&CK techniques: {'; '.join(technique_strs)}."
            )

        return " ".join(parts)

    def _calculate_confidence(
        self,
        group: CorrelatedGroup,
        mitre_mappings: list,
        threat_intel_results: list,
    ) -> float:
        """
        Calculate overall investigation confidence based on evidence quality.

        Higher confidence when:
        - More events are correlated
        - MITRE mappings have high confidence
        - Threat intel confirms indicators
        - Attack progression is detected
        """
        factors: list[float] = []

        # Correlation confidence
        if len(group.events) > 1:
            factors.append(min(group.correlation_strength + 0.5, 1.0))
        else:
            factors.append(0.5)

        # MITRE confidence
        if mitre_mappings:
            avg_mitre = sum(m.confidence for m in mitre_mappings) / len(
                mitre_mappings
            )
            factors.append(avg_mitre)

        # Threat intel confidence
        if threat_intel_results:
            malicious = [r for r in threat_intel_results if r.malicious]
            if malicious:
                factors.append(
                    sum(r.confidence for r in malicious) / len(malicious)
                )

        # Progression bonus
        if group.attack_progression_detected:
            factors.append(0.9)

        return sum(factors) / len(factors) if factors else 0.5
