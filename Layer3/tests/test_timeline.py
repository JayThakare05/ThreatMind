from Layer3.timeline.builder import build_timeline, describe_attack_progression

def test_build_timeline_chronological(sample_events):
    timeline = build_timeline(sample_events)
    
    assert len(timeline) == 4
    # Ensure chronological order
    assert timeline[0].event_id == "EVT-001"
    assert timeline[-1].event_id == "EVT-004"
    
def test_timeline_phases(sample_events):
    timeline = build_timeline(sample_events)
    
    assert timeline[0].phase == "Initial Access Attempt"
    assert timeline[2].phase == "Initial Access"
    assert timeline[3].phase == "Execution"

def test_describe_progression(sample_events):
    timeline = build_timeline(sample_events)
    description = describe_attack_progression(timeline)
    
    assert "Initial Access Attempt" in description
    assert "Execution" in description
    assert "→" in description
