from Layer3.correlation.correlator import correlate_events
from Layer3.risk.scorer import calculate_risk_score
from Layer3.mitre.mapper import map_techniques

def test_calculate_risk_score(sample_events):
    groups = correlate_events(sample_events)
    group = groups[0]
    
    mitre_mappings = map_techniques(sample_events)
    threat_intel = [] # Empty for this test
    
    score, breakdown, factors = calculate_risk_score(
        group, mitre_mappings, threat_intel, asset_criticality=0.5
    )
    
    assert 0 <= score <= 100
    assert len(factors) > 0
    # Should have severity factor (high severity powershell event)
    assert any("severity" in f.lower() for f in factors)
    # Should have correlation factor
    assert any("correlated" in f.lower() for f in factors)
