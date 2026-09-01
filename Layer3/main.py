"""
Layer 3 — Main Entry Point.

Demonstrates the complete Layer 3 investigation pipeline:

    Sample data → Mock Layer 2 adapter → Agent 2 Investigator →
    Correlation → Timeline → MITRE → Threat Intel → Risk →
    Investigated Incident(s) → JSON output

Usage:
    python -m Layer3.main

No LLM required. No external API keys required.
Uses mock threat intelligence and sample datasets.
"""

import json
import sys
from pathlib import Path

# Ensure the project root is on the path
PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from Layer3.adapters.layer2_adapter import MockLayer2Provider
from Layer3.agent.investigator import ThreatInvestigator


def main() -> None:
    # Ensure stdout handles Unicode characters like '→'
    if sys.stdout.encoding.lower() != 'utf-8':
        sys.stdout.reconfigure(encoding='utf-8')

    """Run the full Layer 3 investigation pipeline on sample data."""
    print("=" * 70)
    print("  ThreatMind — Layer 3: Threat Investigation Agent")
    print("  Phase 1: Deterministic Investigation Engine")
    print("=" * 70)
    print()

    # ── Step 1: Load sample data via mock Layer 2 adapter ─────────────────
    print("[1/3] Loading suspicious events from mock Layer 2 provider...")
    data_path = Path(__file__).parent / "data"
    provider = MockLayer2Provider(data_path=data_path)
    layer2_output = provider.get_suspicious_events()

    print(f"      Analysis ID:        {layer2_output.analysis_id}")
    print(f"      Events analyzed:    {layer2_output.total_events_analyzed}")
    print(f"      Suspicious events:  {layer2_output.total_suspicious}")
    print()

    # ── Step 2: Run investigation ─────────────────────────────────────────
    print("[2/3] Running threat investigation pipeline...")
    investigator = ThreatInvestigator()
    incidents = investigator.investigate(layer2_output)

    print(f"      Incidents produced: {len(incidents)}")
    print()

    # ── Step 3: Output results ────────────────────────────────────────────
    print("[3/3] Investigation results:")
    print("-" * 70)

    for incident in incidents:
        # Pretty-print as JSON
        incident_json = incident.model_dump_json(indent=2)
        print(incident_json)
        print("-" * 70)

        # Concise Summary
        print()
        print(f"  Incident ID:   {incident.incident_id} | Severity: {incident.severity} | Risk Score: {incident.risk_score}/100")
        print(f"  Title:         {incident.title}")
        
        if incident.ai_analysis:
            ai = incident.ai_analysis
            print(f"  AI Assessment: {ai.summary}")
            print(f"  Attack Type:   {ai.attack_type} (Confidence: {ai.confidence})")
            print(f"  Next Steps:    {ai.recommended_investigation[0] if ai.recommended_investigation else 'None'}")
        else:
            print(f"  Assessment:    {incident.assessment}")
        print()

    print("=" * 70)
    print("  Investigation complete.")
    print("=" * 70)


if __name__ == "__main__":
    main()
