"""
Layer 3 — Input Schemas (Layer 2 → Layer 3 Contract).

Defines the data structures that Layer 3 expects to receive from Layer 2.
These schemas are the explicit contract between the two layers.
"""

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field


class SuspiciousEvent(BaseModel):
    """
    A single suspicious/flagged event from Layer 2.

    This is the atomic unit of input to the Threat Investigation Agent.
    All optional fields remain Optional because not every log source
    provides every field.
    """

    event_id: str = Field(
        ...,
        description="Unique event identifier assigned by Layer 1/2 or generated."
    )
    timestamp: datetime = Field(
        ...,
        description="When the event occurred (ISO 8601)."
    )
    event_type: str = Field(
        ...,
        description="Normalized event type (e.g., LOGIN_FAILED, POWERSHELL_EXECUTION)."
    )
    action: str = Field(
        ...,
        description="Specific action performed (e.g., login_failed, process_exec)."
    )
    severity: str = Field(
        default="LOW",
        description="Severity assigned by Layer 2: LOW / MEDIUM / HIGH / CRITICAL."
    )
    confidence: float = Field(
        default=1.0,
        ge=0.0,
        le=1.0,
        description="Layer 2's confidence that this event is suspicious (0.0–1.0)."
    )

    # Entity fields — all optional depending on log source
    user: Optional[str] = Field(
        default=None,
        description="Username / account involved."
    )
    source_ip: Optional[str] = Field(
        default=None,
        description="Source IP address."
    )
    destination_ip: Optional[str] = Field(
        default=None,
        description="Destination IP address."
    )
    hostname: Optional[str] = Field(
        default=None,
        description="Host / machine name."
    )
    process: Optional[str] = Field(
        default=None,
        description="Process name or path."
    )
    command_line: Optional[str] = Field(
        default=None,
        description="Full command line if applicable."
    )
    parent_process: Optional[str] = Field(
        default=None,
        description="Parent process name or path."
    )

    # Context fields
    details: Optional[str] = Field(
        default=None,
        description="Human-readable description of the event."
    )
    raw_event: Optional[dict[str, Any]] = Field(
        default=None,
        description="Original raw event preserved for evidence."
    )
    alert_reason: Optional[str] = Field(
        default=None,
        description="Why Layer 2 flagged this event as suspicious."
    )


class Layer2Output(BaseModel):
    """
    Batch output from Layer 2 for a given analysis window.

    This wraps a collection of suspicious events that Layer 3 will investigate.
    """

    analysis_id: str = Field(
        ...,
        description="Unique identifier for this Layer 2 analysis run."
    )
    timestamp: datetime = Field(
        ...,
        description="When Layer 2 produced this output."
    )
    suspicious_events: list[SuspiciousEvent] = Field(
        ...,
        description="List of suspicious events identified by Layer 2."
    )
    total_events_analyzed: int = Field(
        default=0,
        description="Total number of events Layer 2 analyzed in this window."
    )
    total_suspicious: int = Field(
        default=0,
        description="Number of events flagged as suspicious."
    )
