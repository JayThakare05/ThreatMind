from Layer3.correlation.correlator import correlate_events

def test_correlate_events_groups_by_entity(sample_events):
    # All sample events have the same user and IP, they should be grouped together
    groups = correlate_events(sample_events)
    
    assert len(groups) == 1
    assert len(groups[0].events) == 4
    assert groups[0].correlation_strength > 0
    assert "same_user:admin" in groups[0].correlation_factors

def test_attack_progression_detection(sample_events):
    groups = correlate_events(sample_events)
    group = groups[0]
    
    assert group.attack_progression_detected is True
    # Should detect LOGIN_FAILED -> LOGIN_SUCCESS
    assert any("LOGIN_FAILED" in p and "LOGIN_SUCCESS" in p for p in group.attack_phases)
