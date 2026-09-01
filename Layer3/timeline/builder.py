"""
Layer 3 — Timeline Reconstruction.

Builds a chronological timeline for each correlated incident,
preserving all available evidence fields and detecting attack phases.
"""

from Layer3.config.settings import ATTACK_PROGRESSION_PATTERNS
from Layer3.schemas.events import SuspiciousEvent
from Layer3.schemas.incident import TimelineEntry


# Map event types to human-readable attack phase labels
_PHASE_MAP: dict[str, str] = {
    "LOGIN_FAILED": "Initial Access Attempt",
    "AUTH_FAILURE": "Initial Access Attempt",
    "LOGIN_SUCCESS": "Initial Access",
    "AUTH_SUCCESS": "Initial Access",
    "POWERSHELL_EXECUTION": "Execution",
    "PROCESS_EXEC": "Execution",
    "OUTBOUND_CONNECTION": "Command & Control",
    "NETWORK_CONNECTION": "Command & Control",
}


def build_timeline(
    events: list[SuspiciousEvent],
    mitre_map: dict[str, str] | None = None,
) -> list[TimelineEntry]:
    """
    Build a chronological timeline from correlated events.

    Args:
        events: List of correlated suspicious events.
        mitre_map: Optional mapping of event_id → MITRE technique_id.

    Returns:
        Chronologically sorted list of TimelineEntry objects.
    """
    if not events:
        return []

    mitre_map = mitre_map or {}

    # Sort by timestamp
    sorted_events = sorted(events, key=lambda e: e.timestamp)

    timeline: list[TimelineEntry] = []
    for event in sorted_events:
        phase = _determine_phase(event, sorted_events, timeline)

        entry = TimelineEntry(
            timestamp=event.timestamp,
            event_id=event.event_id,
            action=event.action,
            event_type=event.event_type,
            user=event.user,
            source_ip=event.source_ip,
            destination_ip=event.destination_ip,
            hostname=event.hostname,
            process=event.process,
            command_line=event.command_line,
            severity=event.severity,
            mitre_technique=mitre_map.get(event.event_id),
            details=event.details,
            phase=phase,
        )
        timeline.append(entry)

    return timeline


def _determine_phase(
    event: SuspiciousEvent,
    all_events: list[SuspiciousEvent],
    existing_timeline: list[TimelineEntry],
) -> str:
    """
    Determine the attack phase for an event based on its type
    and position in the event sequence.

    Args:
        event: The current event.
        all_events: All events in the correlated group (sorted by time).
        existing_timeline: Timeline entries built so far.

    Returns:
        Human-readable attack phase label.
    """
    event_type = event.event_type.upper()
    return _PHASE_MAP.get(event_type, "Unknown Phase")


def describe_attack_progression(timeline: list[TimelineEntry]) -> str:
    """
    Generate a human-readable description of the attack progression
    observed in the timeline.

    Args:
        timeline: Chronological list of TimelineEntry objects.

    Returns:
        Narrative string describing the attack progression.
    """
    if not timeline:
        return "No events in timeline."

    phases = [entry.phase for entry in timeline if entry.phase]
    unique_phases = list(dict.fromkeys(phases))  # Preserve order, remove dupes

    if len(unique_phases) <= 1:
        return f"Single-phase activity detected: {unique_phases[0] if unique_phases else 'Unknown'}."

    progression = " → ".join(unique_phases)
    return f"Attack progression detected: {progression}."
