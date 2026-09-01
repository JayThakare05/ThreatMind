"""
Layer 3 — MITRE ATT&CK Mapper.

Maps observed event behaviors to MITRE ATT&CK techniques using
evidence-based rule matching. Each mapping includes:
- Technique ID and name
- Confidence score
- Evidence (event IDs that triggered the match)
- Human-readable reason

The mapper loads technique definitions from techniques.json and
applies detection rules against the event data.
"""

import json
from collections import Counter
from pathlib import Path

from Layer3.schemas.events import SuspiciousEvent
from Layer3.schemas.incident import MitreMapping


_TECHNIQUES_PATH = Path(__file__).parent / "techniques.json"


def _load_techniques() -> list[dict]:
    """Load technique definitions from the local JSON file."""
    with open(_TECHNIQUES_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data.get("techniques", [])


def map_techniques(
    events: list[SuspiciousEvent],
) -> list[MitreMapping]:
    """
    Map observed behaviors to MITRE ATT&CK techniques.

    Applies detection rules from techniques.json against the provided events.
    Each rule specifies event type patterns, counts, sequences, and/or
    command patterns to match.

    Args:
        events: List of suspicious events to analyze.

    Returns:
        List of MitreMapping objects with evidence and confidence.
    """
    if not events:
        return []

    techniques = _load_techniques()
    mappings: list[MitreMapping] = []

    # Pre-compute event type counts and sequences
    event_type_counts: Counter = Counter()
    event_types_ordered: list[str] = []
    for event in sorted(events, key=lambda e: e.timestamp):
        upper_type = event.event_type.upper()
        event_type_counts[upper_type] += 1
        event_types_ordered.append(upper_type)

    for technique in techniques:
        technique_id = technique["technique_id"]
        technique_name = technique["name"]
        tactic = technique.get("tactic", "")

        for rule in technique.get("detection_rules", []):
            matched, evidence_ids, reason = _evaluate_rule(
                rule, events, event_type_counts, event_types_ordered
            )

            if matched:
                # Avoid duplicate technique mappings — keep highest confidence
                existing = next(
                    (m for m in mappings if m.technique_id == technique_id),
                    None,
                )
                if existing:
                    if rule.get("confidence", 0) > existing.confidence:
                        existing.confidence = rule["confidence"]
                        existing.evidence = evidence_ids
                        existing.reason = reason
                    else:
                        # Add any new evidence IDs
                        for eid in evidence_ids:
                            if eid not in existing.evidence:
                                existing.evidence.append(eid)
                else:
                    mappings.append(
                        MitreMapping(
                            technique_id=technique_id,
                            name=technique_name,
                            tactic=tactic,
                            confidence=rule.get("confidence", 0.5),
                            evidence=evidence_ids,
                            reason=reason,
                        )
                    )

    return mappings


def _evaluate_rule(
    rule: dict,
    events: list[SuspiciousEvent],
    type_counts: Counter,
    types_ordered: list[str],
) -> tuple[bool, list[str], str]:
    """
    Evaluate a single detection rule against the events.

    Returns:
        Tuple of (matched, evidence_event_ids, reason_string).
    """
    evidence_ids: list[str] = []
    reason = rule.get("description", "")

    # Rule type 1: Count-based (e.g., multiple failed logins)
    if "event_types" in rule and "min_count" in rule:
        target_types = [t.upper() for t in rule["event_types"]]
        min_count = rule["min_count"]
        total = sum(type_counts.get(t, 0) for t in target_types)

        if total >= min_count:
            evidence_ids = [
                e.event_id
                for e in events
                if e.event_type.upper() in target_types
            ]
            return True, evidence_ids, reason

    # Rule type 2: Sequence-based (e.g., failed → success)
    if "event_types_sequence" in rule:
        sequence = [t.upper() for t in rule["event_types_sequence"]]
        seq_idx = 0

        for event in sorted(events, key=lambda e: e.timestamp):
            if seq_idx < len(sequence) and event.event_type.upper() == sequence[seq_idx]:
                evidence_ids.append(event.event_id)
                seq_idx += 1

        if seq_idx == len(sequence):
            return True, evidence_ids, reason

    # Rule type 3: Command pattern matching (e.g., encoded PowerShell)
    if "command_patterns" in rule and "event_types" not in rule:
        patterns = rule["command_patterns"]
        for event in events:
            cmd = (event.command_line or "").lower()
            details = (event.details or "").lower()
            text = cmd + " " + details

            if any(p.lower() in text for p in patterns):
                evidence_ids.append(event.event_id)

        if evidence_ids:
            return True, evidence_ids, reason

    # Rule type 4: Simple event type match (no count requirement)
    if "event_types" in rule and "min_count" not in rule:
        target_types = [t.upper() for t in rule["event_types"]]

        # Also check command patterns if present
        command_patterns = rule.get("command_patterns", [])

        for event in events:
            if event.event_type.upper() in target_types:
                if command_patterns:
                    cmd = (event.command_line or "").lower()
                    details = (event.details or "").lower()
                    text = cmd + " " + details
                    if any(p.lower() in text for p in command_patterns):
                        evidence_ids.append(event.event_id)
                else:
                    evidence_ids.append(event.event_id)

        if evidence_ids:
            return True, evidence_ids, reason

    return False, [], reason


def get_mitre_event_map(mappings: list[MitreMapping]) -> dict[str, str]:
    """
    Create a mapping of event_id → technique_id for timeline annotation.

    If an event supports multiple techniques, the first match is used.

    Args:
        mappings: List of MitreMapping objects.

    Returns:
        Dict mapping event IDs to their primary MITRE technique ID.
    """
    event_map: dict[str, str] = {}
    for mapping in mappings:
        for event_id in mapping.evidence:
            if event_id not in event_map:
                event_map[event_id] = mapping.technique_id
    return event_map
