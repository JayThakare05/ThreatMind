import pytest
from datetime import datetime

from Layer3.schemas.events import SuspiciousEvent

@pytest.fixture
def sample_events():
    return [
        SuspiciousEvent(
            event_id="EVT-001",
            timestamp=datetime(2026, 9, 1, 10, 30, 1),
            event_type="LOGIN_FAILED",
            action="login_failed",
            severity="MEDIUM",
            user="admin",
            source_ip="185.10.20.50",
            hostname="server-01"
        ),
        SuspiciousEvent(
            event_id="EVT-002",
            timestamp=datetime(2026, 9, 1, 10, 30, 5),
            event_type="LOGIN_FAILED",
            action="login_failed",
            severity="MEDIUM",
            user="admin",
            source_ip="185.10.20.50",
            hostname="server-01"
        ),
        SuspiciousEvent(
            event_id="EVT-003",
            timestamp=datetime(2026, 9, 1, 10, 30, 15),
            event_type="LOGIN_SUCCESS",
            action="login_success",
            severity="LOW",
            user="admin",
            source_ip="185.10.20.50",
            hostname="server-01"
        ),
        SuspiciousEvent(
            event_id="EVT-004",
            timestamp=datetime(2026, 9, 1, 10, 31, 2),
            event_type="POWERSHELL_EXECUTION",
            action="powershell_execution",
            severity="HIGH",
            user="admin",
            source_ip="185.10.20.50",
            hostname="server-01",
            process="powershell.exe",
            command_line="powershell.exe -enc SQBFAFgA"
        )
    ]
