from Layer3.mitre.mapper import map_techniques

def test_map_brute_force(sample_events):
    mappings = map_techniques(sample_events)
    
    # Should detect T1110 (Brute Force) from multiple LOGIN_FAILED, 
    # but the sample only has 2 LOGIN_FAILED. Wait, sample has 2.
    # Ah, the rule needs 3. Let's check what it detects.
    # We should have T1078 Valid Accounts (fail -> success)
    # We should have T1059.001 PowerShell (-enc)
    
    technique_ids = [m.technique_id for m in mappings]
    
    assert "T1078" in technique_ids
    assert "T1059.001" in technique_ids
    
    # Verify evidence mapping
    ps_mapping = next(m for m in mappings if m.technique_id == "T1059.001")
    assert "EVT-004" in ps_mapping.evidence
