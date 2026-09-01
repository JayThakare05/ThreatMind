"""
Layer 3 — LLM Investigator.

Adds an AI reasoning capability on top of the deterministic investigation pipeline.
Uses Groq to analyze the structured evidence and produce an AIInvestigationResult.
"""

import json
from typing import Any, Optional

try:
    from groq import Groq
    GROQ_AVAILABLE = True
except ImportError:
    GROQ_AVAILABLE = False

from pydantic import ValidationError

from Layer3.config.settings import (
    AI_INVESTIGATION_ENABLED,
    GROQ_API_KEY,
    GROQ_MODEL,
)
from Layer3.schemas.incident import (
    AIInvestigationResult,
    InvestigatedIncident,
)


class LLMInvestigator:
    """
    LLM-driven Threat Investigator.

    Analyzes structured investigation evidence to provide independent
    reasoning, confidence, and recommendations. Does not overwrite
    deterministic facts.
    """

    def __init__(self):
        self.enabled = AI_INVESTIGATION_ENABLED
        self.client = None

        if self.enabled:
            if not GROQ_AVAILABLE:
                self.enabled = False
            elif not GROQ_API_KEY:
                self.enabled = False
            else:
                try:
                    self.client = Groq(api_key=GROQ_API_KEY)
                except Exception:
                    self.enabled = False

    def analyze(self, incident: InvestigatedIncident) -> Optional[AIInvestigationResult]:
        """
        Analyze the deterministic investigation result using the LLM.

        Args:
            incident: The structured output of the deterministic pipeline.

        Returns:
            An AIInvestigationResult if successful, None if disabled or failed.
        """
        if not self.enabled or not self.client:
            return None

        prompt = self._build_prompt(incident)

        try:
            # We request JSON object output format from Groq
            completion = self.client.chat.completions.create(
                model=GROQ_MODEL,
                messages=[
                    {"role": "system", "content": self._get_system_prompt()},
                    {"role": "user", "content": prompt}
                ],
                response_format={"type": "json_object"},
                temperature=0.1,
                max_tokens=2048
            )
            
            response_text = completion.choices[0].message.content
            if not response_text:
                return None
                
            return self._parse_response(response_text)
            
        except Exception as e:
            # Safely catch all exceptions (timeout, auth, rate limit)
            # and allow deterministic pipeline to continue
            return None

    def _get_system_prompt(self) -> str:
        """Returns the system prompt governing the LLM's behavior."""
        return (
            "You are an experienced SOC threat investigator.\n\n"
            "Analyze only the evidence supplied to you.\n"
            "Do not invent facts, events, indicators, users, hosts, commands, "
            "threat intelligence, or MITRE evidence.\n\n"
            "Separate observed evidence from inference.\n"
            "Identify uncertainty when evidence is insufficient.\n"
            "Explain why your conclusions follow from the evidence.\n"
            "Assess existing MITRE mappings rather than blindly accepting them.\n"
            "Recommend additional investigation steps when useful.\n\n"
            "IMPORTANT: Do not overclaim. Use strict, evidence-grounded wording.\n"
            "For example, do not describe an event as 'remote code execution' unless the evidence "
            "explicitly proves it. Instead, use accurate phrasing like 'suspected account compromise "
            "followed by encoded PowerShell execution'.\n\n"
            "You are an investigation assistant. You must NOT execute remediation "
            "or response actions.\n\n"
            "Provide your response as a structured JSON object matching the requested schema."
        )

    def _build_prompt(self, incident: InvestigatedIncident) -> str:
        """Build an evidence-grounded prompt from the incident data."""
        # Convert incident to a dict, excluding metadata and removing empty lists
        incident_dict = incident.model_dump(exclude={"investigation_metadata", "ai_analysis"})
        
        # Format as JSON string for clear presentation
        evidence_json = json.dumps(incident_dict, indent=2, default=str)
        
        # Describe the required output schema explicitly for JSON mode
        schema_description = (
            "{\n"
            f'  "incident_id": "{incident.incident_id}",\n'
            '  "summary": "Brief summary of what most likely happened",\n'
            '  "attack_type": "The likely attack pattern or category",\n'
            '  "assessment": "Detailed narrative explaining the conclusion",\n'
            '  "confidence": "High, Medium, or Low",\n'
            '  "key_findings": ["Bullet point 1", "Bullet point 2"],\n'
            '  "evidence": ["EVT-001", "EVT-002"],\n'
            '  "attack_progression": "Explanation of how the attack progressed",\n'
            '  "mitre_assessment": "Assessment of whether the deterministic MITRE mappings are accurate",\n'
            '  "uncertainties": ["Things that are uncertain"],\n'
            '  "recommended_investigation": ["Additional steps for analyst"],\n'
            '  "missing_evidence": ["Important missing evidence"]\n'
            "}"
        )

        return (
            "Please analyze the following structured investigation evidence.\n\n"
            "### EVIDENCE ###\n"
            f"{evidence_json}\n\n"
            "### REQUIRED OUTPUT FORMAT ###\n"
            "Return ONLY a valid JSON object matching this schema exactly:\n"
            f"{schema_description}\n"
        )

    def _parse_response(self, response_text: str) -> Optional[AIInvestigationResult]:
        """Parse and validate the JSON response."""
        try:
            data = json.loads(response_text)
            return AIInvestigationResult(**data)
        except (json.JSONDecodeError, ValidationError):
            # If the output is malformed, we just fail gracefully
            return None
