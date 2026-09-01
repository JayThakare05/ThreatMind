"""
Layer 3 — Event Correlation Engine.

Groups suspicious events into correlated incident clusters based on:
- Shared entities (user, IP, host, process)
- Temporal proximity (configurable window)
- Related event types
- Attack progression patterns
"""

from datetime import timedelta

from Layer3.config.settings import (
    ATTACK_PROGRESSION_PATTERNS,
    CORRELATION_WEIGHTS,
    CORRELATION_WINDOW_MINUTES,
)
from Layer3.schemas.events import SuspiciousEvent


class CorrelatedGroup:
    """A group of events determined to be part of the same incident."""

    def __init__(self):
        self.events: list[SuspiciousEvent] = []
        self.correlation_strength: float = 0.0
        self.correlation_factors: list[str] = []
        self.attack_progression_detected: bool = False
        self.attack_phases: list[str] = []

    @property
    def event_ids(self) -> list[str]:
        return [e.event_id for e in self.events]

    def add_event(self, event: SuspiciousEvent) -> None:
        self.events.append(event)

    def __repr__(self) -> str:
        return (
            f"CorrelatedGroup(events={len(self.events)}, "
            f"strength={self.correlation_strength:.2f})"
        )


def correlate_events(
    events: list[SuspiciousEvent],
    window_minutes: int | None = None,
) -> list[CorrelatedGroup]:
    """
    Correlate suspicious events into incident groups.

    Uses a greedy approach: for each event, find all other events that share
    entities and fall within the correlation time window, then merge them
    into groups.

    Args:
        events: List of suspicious events from Layer 2.
        window_minutes: Correlation time window in minutes. Uses config default.

    Returns:
        List of CorrelatedGroup objects, each representing a potential incident.
    """
    if not events:
        return []

    window = timedelta(minutes=window_minutes or CORRELATION_WINDOW_MINUTES)

    # Sort events by timestamp
    sorted_events = sorted(events, key=lambda e: e.timestamp)

    # Track which events are already assigned to a group
    assigned: set[str] = set()
    groups: list[CorrelatedGroup] = []

    for event in sorted_events:
        if event.event_id in assigned:
            continue

        # Start a new group with this event
        group = CorrelatedGroup()
        group.add_event(event)
        assigned.add(event.event_id)

        # Find all correlated events
        for candidate in sorted_events:
            if candidate.event_id in assigned:
                continue

            strength, factors = _calculate_correlation(event, candidate, window)
            if strength > 0:
                group.add_event(candidate)
                assigned.add(candidate.event_id)
                group.correlation_factors.extend(factors)

        # Calculate overall group correlation strength
        group.correlation_strength = _calculate_group_strength(group)

        # Check for attack progression
        progression, phases = _detect_attack_progression(group)
        group.attack_progression_detected = progression
        group.attack_phases = phases

        # Deduplicate factors
        group.correlation_factors = list(set(group.correlation_factors))

        groups.append(group)

    return groups


def _calculate_correlation(
    event_a: SuspiciousEvent,
    event_b: SuspiciousEvent,
    window: timedelta,
) -> tuple[float, list[str]]:
    """
    Calculate correlation strength between two events.

    Returns:
        Tuple of (correlation_strength, list_of_matching_factors).
    """
    strength = 0.0
    factors: list[str] = []

    # Temporal proximity check — must be within the correlation window
    time_diff = abs(event_a.timestamp - event_b.timestamp)
    if time_diff > window:
        return 0.0, []

    # Entity matching
    if event_a.user and event_b.user and event_a.user == event_b.user:
        strength += CORRELATION_WEIGHTS["same_user"]
        factors.append(f"same_user:{event_a.user}")

    if (
        event_a.source_ip
        and event_b.source_ip
        and event_a.source_ip == event_b.source_ip
    ):
        strength += CORRELATION_WEIGHTS["same_source_ip"]
        factors.append(f"same_source_ip:{event_a.source_ip}")

    if (
        event_a.hostname
        and event_b.hostname
        and event_a.hostname == event_b.hostname
    ):
        strength += CORRELATION_WEIGHTS["same_hostname"]
        factors.append(f"same_hostname:{event_a.hostname}")

    if (
        event_a.destination_ip
        and event_b.destination_ip
        and event_a.destination_ip == event_b.destination_ip
    ):
        strength += CORRELATION_WEIGHTS["same_destination_ip"]
        factors.append(f"same_destination_ip:{event_a.destination_ip}")

    if (
        event_a.process
        and event_b.process
        and event_a.process == event_b.process
    ):
        strength += CORRELATION_WEIGHTS["same_process"]
        factors.append(f"same_process:{event_a.process}")

    # Temporal proximity bonus (closer = stronger)
    if time_diff <= window and strength > 0:
        proximity_ratio = 1.0 - (time_diff.total_seconds() / window.total_seconds())
        strength += CORRELATION_WEIGHTS["temporal_proximity"] * proximity_ratio
        factors.append("temporal_proximity")

    return strength, factors


def _calculate_group_strength(group: CorrelatedGroup) -> float:
    """Calculate the overall correlation strength of a group."""
    if len(group.events) <= 1:
        return 0.0

    # Average pairwise correlation
    total_strength = 0.0
    pair_count = 0

    window = timedelta(minutes=CORRELATION_WINDOW_MINUTES)

    for i, event_a in enumerate(group.events):
        for event_b in group.events[i + 1:]:
            strength, _ = _calculate_correlation(event_a, event_b, window)
            total_strength += strength
            pair_count += 1

    return total_strength / pair_count if pair_count > 0 else 0.0


def _detect_attack_progression(
    group: CorrelatedGroup,
) -> tuple[bool, list[str]]:
    """
    Check if the correlated group contains known attack progression patterns.

    Returns:
        Tuple of (progression_detected, list_of_matched_phases).
    """
    if len(group.events) < 2:
        return False, []

    # Sort events by timestamp to check progression order
    sorted_events = sorted(group.events, key=lambda e: e.timestamp)
    event_types = [e.event_type.upper() for e in sorted_events]

    matched_phases: list[str] = []
    progression_found = False

    for pattern in ATTACK_PROGRESSION_PATTERNS:
        # Check if pattern appears in order within the event types
        pattern_idx = 0
        for event_type in event_types:
            if pattern_idx < len(pattern) and pattern[pattern_idx] in event_type:
                pattern_idx += 1
        if pattern_idx == len(pattern):
            progression_found = True
            matched_phases.append(" → ".join(pattern))

    return progression_found, matched_phases
