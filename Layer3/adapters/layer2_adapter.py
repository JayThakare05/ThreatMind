"""
Layer 3 — Layer 2 Adapter.

Provides a clean boundary between Layer 2 output and Layer 3 input.

Since Layer 2 is not yet implemented, this module includes:
1. An abstract Layer2Provider interface for future integration
2. A MockLayer2Provider that converts sample raw datasets into Layer2Output
   for development and testing

When Layer 2 is ready, implement the Layer2Provider interface and replace
the mock provider with real integration.
"""

import csv
import json
import uuid
import xml.etree.ElementTree as ET
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import Optional

from Layer3.config.settings import (
    DEFAULT_EVENT_SEVERITY,
    EVENT_SEVERITY_MAP,
)
from Layer3.schemas.events import Layer2Output, SuspiciousEvent


class Layer2Provider(ABC):
    """
    Abstract interface for receiving Layer 2 output.

    Layer 2 will implement this interface when it is ready.
    """

    @abstractmethod
    def get_suspicious_events(self) -> Layer2Output:
        """Retrieve the latest batch of suspicious events from Layer 2."""
        ...


class MockLayer2Provider(Layer2Provider):
    """
    Development adapter that converts sample raw datasets into Layer2Output.

    This is NOT a Layer 1 parser. It is a minimal fixture that produces
    properly structured SuspiciousEvent objects so Agent 2 can be developed
    and tested independently.

    Supports loading from: JSON, CSV, or XML sample files.
    """

    def __init__(self, data_path: Optional[Path] = None):
        self._data_path = data_path or Path(__file__).parent.parent / "data"

    def get_suspicious_events(self) -> Layer2Output:
        """Load sample data and produce a mock Layer2Output."""
        events: list[SuspiciousEvent] = []

        # Try JSON first (cleanest sample format)
        json_path = self._data_path / "security_logs.json"
        if json_path.exists():
            events = self._load_from_json(json_path)
        else:
            # Fall back to CSV
            csv_path = self._data_path / "security_logs.csv"
            if csv_path.exists():
                events = self._load_from_csv(csv_path)

        return Layer2Output(
            analysis_id=f"MOCK-{uuid.uuid4().hex[:8].upper()}",
            timestamp=datetime.utcnow(),
            suspicious_events=events,
            total_events_analyzed=len(events),
            total_suspicious=len(events),
        )

    def _load_from_json(self, path: Path) -> list[SuspiciousEvent]:
        """Convert JSON sample data to SuspiciousEvent list."""
        with open(path, "r", encoding="utf-8") as f:
            raw_events = json.load(f)

        events: list[SuspiciousEvent] = []
        for i, raw in enumerate(raw_events, start=1):
            event_type = raw.get("event_type", "UNKNOWN")
            severity = EVENT_SEVERITY_MAP.get(event_type, DEFAULT_EVENT_SEVERITY)

            process = None
            command_line = None
            message = raw.get("message", "")
            if "powershell" in message.lower():
                process = "powershell.exe"
                command_line = message

            events.append(
                SuspiciousEvent(
                    event_id=f"EVT-{i:03d}",
                    timestamp=datetime.fromisoformat(
                        raw["timestamp"].replace("Z", "+00:00")
                    ),
                    event_type=event_type,
                    action=event_type.lower(),
                    severity=severity,
                    confidence=0.95,
                    user=raw.get("username"),
                    source_ip=raw.get("source_ip"),
                    hostname=raw.get("host"),
                    process=process,
                    command_line=command_line,
                    details=message,
                    raw_event=raw,
                    alert_reason=f"Mock triage: {event_type} flagged as suspicious",
                )
            )

        return events

    def _load_from_csv(self, path: Path) -> list[SuspiciousEvent]:
        """Convert CSV sample data to SuspiciousEvent list."""
        events: list[SuspiciousEvent] = []
        with open(path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for i, row in enumerate(reader, start=1):
                event_type = row.get("action", "UNKNOWN")
                severity = EVENT_SEVERITY_MAP.get(event_type, DEFAULT_EVENT_SEVERITY)

                process = None
                command_line = None
                details = row.get("details", "")
                if "powershell" in details.lower():
                    process = "powershell.exe"
                    command_line = details

                events.append(
                    SuspiciousEvent(
                        event_id=f"EVT-{i:03d}",
                        timestamp=datetime.fromisoformat(
                            row["event_time"].replace("Z", "+00:00")
                        ),
                        event_type=event_type,
                        action=event_type.lower(),
                        severity=severity,
                        confidence=0.90,
                        user=row.get("account"),
                        source_ip=row.get("client_ip"),
                        hostname=row.get("hostname"),
                        process=process,
                        command_line=command_line,
                        details=details,
                        raw_event=dict(row),
                        alert_reason=f"Mock triage: {event_type} flagged as suspicious",
                    )
                )

        return events

    def _load_from_xml(self, path: Path) -> list[SuspiciousEvent]:
        """Convert Windows Event XML sample data to SuspiciousEvent list."""
        ns = {"ev": "http://schemas.microsoft.com/win/2004/08/events/event"}
        tree = ET.parse(path)
        root = tree.getroot()

        # Windows Event ID → normalized event type
        event_id_map: dict[str, str] = {
            "4625": "LOGIN_FAILED",
            "4624": "LOGIN_SUCCESS",
            "4688": "PROCESS_EXEC",
        }

        events: list[SuspiciousEvent] = []
        for i, event_elem in enumerate(root.findall("ev:Event", ns), start=1):
            system = event_elem.find("ev:System", ns)
            event_data = event_elem.find("ev:EventData", ns)

            if system is None:
                continue

            win_event_id = system.findtext("ev:EventID", default="0", namespaces=ns)
            event_type = event_id_map.get(win_event_id, "UNKNOWN")
            severity = EVENT_SEVERITY_MAP.get(event_type, DEFAULT_EVENT_SEVERITY)

            timestamp_str = ""
            time_created = system.find("ev:TimeCreated", ns)
            if time_created is not None:
                timestamp_str = time_created.get("SystemTime", "")

            computer = system.findtext("ev:Computer", default=None, namespaces=ns)
            # Extract short hostname from FQDN
            hostname = computer.split(".")[0] if computer else None

            # Parse EventData fields
            data_fields: dict[str, str] = {}
            if event_data is not None:
                for data_elem in event_data.findall("ev:Data", ns):
                    name = data_elem.get("Name", "")
                    value = data_elem.text or ""
                    data_fields[name] = value

            user = data_fields.get("TargetUserName") or data_fields.get(
                "SubjectUserName"
            )
            source_ip = data_fields.get("IpAddress")
            process = data_fields.get("NewProcessName")
            command_line = data_fields.get("CommandLine")
            parent_process = data_fields.get("ParentProcessName")

            events.append(
                SuspiciousEvent(
                    event_id=f"EVT-{i:03d}",
                    timestamp=datetime.fromisoformat(
                        timestamp_str.replace("Z", "+00:00")
                    ),
                    event_type=event_type,
                    action=event_type.lower(),
                    severity=severity,
                    confidence=0.90,
                    user=user,
                    source_ip=source_ip,
                    hostname=hostname,
                    process=process,
                    command_line=command_line,
                    parent_process=parent_process,
                    details=f"Windows Event {win_event_id}",
                    raw_event=data_fields,
                    alert_reason=f"Mock triage: Windows Event {win_event_id} flagged",
                )
            )

        return events
