# Layer 3 — Development Data

This directory contains sample security datasets used for developing and testing the Agent 2 (Threat Investigation) pipeline.

**Files:**
- `security_logs.csv` — CSV representation of raw events
- `security_logs.json` — JSON representation of raw events
- `security_logs_windows_events.xml` — Windows Event XML representation

> **Note:** These are representations of the *same* incident across different formats. They simulate the raw logs that Layer 1 would ingest and normalize. Since Layer 2 is not yet implemented, the `MockLayer2Provider` adapter reads these files and simulates Layer 2 triage output so Layer 3 can be developed independently.

Do **NOT** commit real API keys or sensitive production logs here.
