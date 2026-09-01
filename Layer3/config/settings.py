"""
Layer 3 — Configuration Settings.

Centralizes all configurable thresholds, weights, and parameters.
Values can be overridden via environment variables or .env file.
"""

import os
from dotenv import load_dotenv

load_dotenv()


# ── Correlation ──────────────────────────────────────────────────────────────

CORRELATION_WINDOW_MINUTES: int = int(
    os.getenv("CORRELATION_WINDOW_MINUTES", "5")
)

# Correlation factors and their weights (must sum conceptually, but are normalized)
CORRELATION_WEIGHTS: dict[str, float] = {
    "same_user": 0.25,
    "same_source_ip": 0.25,
    "same_hostname": 0.15,
    "same_destination_ip": 0.10,
    "same_process": 0.10,
    "temporal_proximity": 0.10,
    "related_event_type": 0.05,
}


# ── Risk Scoring ─────────────────────────────────────────────────────────────

# Risk score contributions (weights — must sum to 1.0)
RISK_WEIGHTS: dict[str, float] = {
    "severity": 0.25,
    "correlation": 0.15,
    "attack_progression": 0.20,
    "mitre": 0.15,
    "threat_intel": 0.15,
    "asset_criticality": 0.10,
}

# Severity label thresholds (upper inclusive bound)
RISK_LOW_THRESHOLD: int = int(os.getenv("RISK_LOW_THRESHOLD", "29"))
RISK_MEDIUM_THRESHOLD: int = int(os.getenv("RISK_MEDIUM_THRESHOLD", "49"))
RISK_HIGH_THRESHOLD: int = int(os.getenv("RISK_HIGH_THRESHOLD", "74"))
RISK_CRITICAL_THRESHOLD: int = int(os.getenv("RISK_CRITICAL_THRESHOLD", "100"))


# ── Event Severity Defaults ──────────────────────────────────────────────────

# Default severity assigned by mock adapter when Layer 2 doesn't provide one
EVENT_SEVERITY_MAP: dict[str, str] = {
    "LOGIN_FAILED": "MEDIUM",
    "AUTH_FAILURE": "MEDIUM",
    "LOGIN_SUCCESS": "LOW",
    "AUTH_SUCCESS": "LOW",
    "POWERSHELL_EXECUTION": "HIGH",
    "PROCESS_EXEC": "HIGH",
    "OUTBOUND_CONNECTION": "MEDIUM",
    "NETWORK_CONNECTION": "MEDIUM",
}

DEFAULT_EVENT_SEVERITY: str = "LOW"

# Numeric severity for scoring
SEVERITY_SCORES: dict[str, int] = {
    "LOW": 10,
    "MEDIUM": 30,
    "HIGH": 60,
    "CRITICAL": 90,
}


# ── Threat Intelligence ──────────────────────────────────────────────────────

THREAT_INTEL_PROVIDER: str = os.getenv("THREAT_INTEL_PROVIDER", "mock")
THREAT_INTEL_API_KEY: str = os.getenv("THREAT_INTEL_API_KEY", "")


# ── AI Investigation (LLM) ───────────────────────────────────────────────────

GROQ_API_KEY: str = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL: str = os.getenv("GROQ_MODEL", "openai/gpt-oss-120b")
# Treat any string that isn't explicitly "false", "0", or "no" as true,
# but default to False if not present (although prompt says default true, we'll parse it)
_ai_enabled = os.getenv("AI_INVESTIGATION_ENABLED", "true").lower()
AI_INVESTIGATION_ENABLED: bool = _ai_enabled not in ("false", "0", "no")


# ── Attack Progression Patterns ──────────────────────────────────────────────

# Ordered sequences that indicate attack progression
# Each pattern is a list of event type keywords to match in order
ATTACK_PROGRESSION_PATTERNS: list[list[str]] = [
    ["LOGIN_FAILED", "LOGIN_SUCCESS"],                # Brute force → success
    ["AUTH_FAILURE", "AUTH_SUCCESS"],                  # Brute force → success (alt)
    ["LOGIN_SUCCESS", "POWERSHELL_EXECUTION"],        # Compromise → execution
    ["AUTH_SUCCESS", "PROCESS_EXEC"],                  # Compromise → execution (alt)
    ["POWERSHELL_EXECUTION", "OUTBOUND_CONNECTION"],  # Execution → exfil
    ["PROCESS_EXEC", "NETWORK_CONNECTION"],            # Execution → exfil (alt)
]


def get_severity_label(risk_score: int) -> str:
    """Map a 0–100 risk score to a severity label."""
    if risk_score <= RISK_LOW_THRESHOLD:
        return "LOW"
    elif risk_score <= RISK_MEDIUM_THRESHOLD:
        return "MEDIUM"
    elif risk_score <= RISK_HIGH_THRESHOLD:
        return "HIGH"
    else:
        return "CRITICAL"
