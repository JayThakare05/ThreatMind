"""
Layer 3 — Investigation State.

Tracks the state of an ongoing investigation.
Used by the Investigator to maintain context across investigation steps.

In Phase 1 (deterministic), this is a simple data container.
In Phase 3+ (agentic), this will support LLM-driven investigation planning.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field

from Layer3.schemas.events import Layer2Output
from Layer3.schemas.incident import InvestigatedIncident


class InvestigationPhase(str, Enum):
    """Phases of the investigation workflow."""

    INITIALIZED = "initialized"
    VALIDATING = "validating"
    CORRELATING = "correlating"
    EXTRACTING_ENTITIES = "extracting_entities"
    BUILDING_TIMELINE = "building_timeline"
    MAPPING_MITRE = "mapping_mitre"
    ENRICHING_THREAT_INTEL = "enriching_threat_intel"
    CALCULATING_RISK = "calculating_risk"
    GENERATING_ASSESSMENT = "generating_assessment"
    COMPLETED = "completed"
    FAILED = "failed"


class InvestigationState(BaseModel):
    """
    Tracks the current state of a threat investigation.

    This state object flows through the investigation pipeline,
    accumulating results from each stage.
    """

    # Investigation identity
    investigation_id: str = ""
    phase: InvestigationPhase = InvestigationPhase.INITIALIZED

    # Timestamps
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    # Input
    layer2_output: Optional[Layer2Output] = None

    # Results accumulated during investigation
    correlated_group_count: int = 0
    entities_extracted: bool = False
    timeline_built: bool = False
    mitre_mapped: bool = False
    threat_intel_enriched: bool = False
    risk_calculated: bool = False

    # Output
    incidents: list[InvestigatedIncident] = Field(default_factory=list)

    # Error tracking
    errors: list[str] = Field(default_factory=list)

    def set_phase(self, phase: InvestigationPhase) -> None:
        """Update the investigation phase."""
        self.phase = phase

    def add_error(self, error: str) -> None:
        """Record an error encountered during investigation."""
        self.errors.append(error)
        self.phase = InvestigationPhase.FAILED

    @property
    def is_complete(self) -> bool:
        return self.phase == InvestigationPhase.COMPLETED

    @property
    def is_failed(self) -> bool:
        return self.phase == InvestigationPhase.FAILED
