import os
import pytest
from unittest.mock import patch, MagicMock

from Layer3.schemas.incident import InvestigatedIncident, AIInvestigationResult
from Layer3.agent.llm_investigator import LLMInvestigator

@pytest.fixture
def mock_incident():
    """Returns a minimal valid InvestigatedIncident."""
    return InvestigatedIncident(
        incident_id="INC-TEST",
        title="Test Incident",
        severity="LOW",
        risk_score=10,
        confidence=0.5,
    )

def test_llm_investigator_disabled_by_env(mock_incident):
    """Test that LLMInvestigator returns None when disabled."""
    with patch("Layer3.agent.llm_investigator.AI_INVESTIGATION_ENABLED", False):
        investigator = LLMInvestigator()
        assert investigator.enabled is False
        assert investigator.analyze(mock_incident) is None

def test_llm_investigator_missing_api_key(mock_incident):
    """Test that LLMInvestigator disables itself if API key is missing."""
    with patch("Layer3.agent.llm_investigator.AI_INVESTIGATION_ENABLED", True), \
         patch("Layer3.agent.llm_investigator.GROQ_API_KEY", ""):
        investigator = LLMInvestigator()
        assert investigator.enabled is False

def test_llm_investigator_successful_parse(mock_incident):
    """Test that a well-formed JSON response is correctly parsed."""
    with patch("Layer3.agent.llm_investigator.AI_INVESTIGATION_ENABLED", True), \
         patch("Layer3.agent.llm_investigator.GROQ_API_KEY", "test-key"), \
         patch("Layer3.agent.llm_investigator.GROQ_AVAILABLE", True), \
         patch("Layer3.agent.llm_investigator.Groq") as mock_groq_class:
        
        # Setup mock client
        mock_client = MagicMock()
        mock_groq_class.return_value = mock_client
        
        mock_response = MagicMock()
        # Create a valid JSON string matching AIInvestigationResult
        valid_json = '''
        {
            "incident_id": "INC-TEST",
            "summary": "Test summary",
            "attack_type": "Test attack",
            "assessment": "Test assessment",
            "confidence": "High",
            "key_findings": ["Finding 1"],
            "evidence": ["EVT-1"],
            "attack_progression": "A -> B",
            "mitre_assessment": "Accurate",
            "uncertainties": ["Unknown IP"],
            "recommended_investigation": ["Check logs"],
            "missing_evidence": ["Firewall logs"]
        }
        '''
        mock_response.choices = [MagicMock(message=MagicMock(content=valid_json))]
        mock_client.chat.completions.create.return_value = mock_response
        
        investigator = LLMInvestigator()
        result = investigator.analyze(mock_incident)
        
        assert isinstance(result, AIInvestigationResult)
        assert result.incident_id == "INC-TEST"
        assert result.summary == "Test summary"
        assert len(result.key_findings) == 1

def test_llm_investigator_malformed_json(mock_incident):
    """Test that malformed JSON is caught and handled safely."""
    with patch("Layer3.agent.llm_investigator.AI_INVESTIGATION_ENABLED", True), \
         patch("Layer3.agent.llm_investigator.GROQ_API_KEY", "test-key"), \
         patch("Layer3.agent.llm_investigator.GROQ_AVAILABLE", True), \
         patch("Layer3.agent.llm_investigator.Groq") as mock_groq_class:
        
        mock_client = MagicMock()
        mock_groq_class.return_value = mock_client
        
        mock_response = MagicMock()
        mock_response.choices = [MagicMock(message=MagicMock(content="INVALID JSON"))]
        mock_client.chat.completions.create.return_value = mock_response
        
        investigator = LLMInvestigator()
        result = investigator.analyze(mock_incident)
        
        assert result is None
