import pytest
from pysigma import PySigma
from pysigma.aggregation import reset_aggregation_state


def test_count_aggregation():
    """Test count() aggregation - alert when more than N events match."""
    reset_aggregation_state()
    
    sigma = PySigma()
    sigma.add_signature("""
        title: count test
        id: test-count-001
        detection:
            selection:
                EventID: 1234
            condition: selection | count() > 3
    """)
    
    # First 3 events should not trigger (count <= 3)
    event = {'EventID': '1234', 'UtcTime': '2024-01-01 12:00:00.000', 'Data': []}
    assert len(sigma.check_events([event])) == 0
    assert len(sigma.check_events([event])) == 0
    assert len(sigma.check_events([event])) == 0
    
    # 4th event should trigger (count > 3)
    alerts = sigma.check_events([event])
    assert len(alerts) == 1


def test_count_aggregation_with_group_by():
    """Test count() aggregation with group by field."""
    reset_aggregation_state()
    
    sigma = PySigma()
    sigma.add_signature("""
        title: count by source ip
        id: test-count-by-001
        detection:
            selection:
                EventID: 1234
            condition: selection | count() by src_ip > 2
    """)
    
    # Events from different IPs
    event1 = {'EventID': '1234', 'src_ip': '10.0.0.1', 'UtcTime': '2024-01-01 12:00:00.000', 'Data': []}
    event2 = {'EventID': '1234', 'src_ip': '10.0.0.2', 'UtcTime': '2024-01-01 12:00:01.000', 'Data': []}
    
    # First 2 events from same IP - no alert
    assert len(sigma.check_events([event1])) == 0
    assert len(sigma.check_events([event1])) == 0
    
    # 3rd event from same IP - should alert
    alerts = sigma.check_events([event1])
    assert len(alerts) == 1
    
    # Event from different IP - no alert (count for 10.0.0.2 is 1)
    assert len(sigma.check_events([event2])) == 0


def test_sum_aggregation():
    """Test sum() aggregation."""
    reset_aggregation_state()
    
    sigma = PySigma()
    sigma.add_signature("""
        title: sum test
        id: test-sum-001
        detection:
            selection:
                EventID: 1234
            condition: selection | sum(bytes) > 1000
    """)
    
    # Events with byte counts
    event1 = {'EventID': '1234', 'bytes': 400, 'UtcTime': '2024-01-01 12:00:00.000', 'Data': []}
    event2 = {'EventID': '1234', 'bytes': 400, 'UtcTime': '2024-01-01 12:00:01.000', 'Data': []}
    event3 = {'EventID': '1234', 'bytes': 300, 'UtcTime': '2024-01-01 12:00:02.000', 'Data': []}
    
    # First two events sum to 800 - no alert
    assert len(sigma.check_events([event1])) == 0
    assert len(sigma.check_events([event2])) == 0
    
    # Third event makes sum 1100 - should alert
    alerts = sigma.check_events([event3])
    assert len(alerts) == 1


def test_max_aggregation():
    """Test max() aggregation."""
    reset_aggregation_state()
    
    sigma = PySigma()
    sigma.add_signature("""
        title: max test
        id: test-max-001
        detection:
            selection:
                EventID: 1234
            condition: selection | max(response_time) > 100
    """)
    
    # Events with response times
    event1 = {'EventID': '1234', 'response_time': 50, 'UtcTime': '2024-01-01 12:00:00.000', 'Data': []}
    event2 = {'EventID': '1234', 'response_time': 80, 'UtcTime': '2024-01-01 12:00:01.000', 'Data': []}
    event3 = {'EventID': '1234', 'response_time': 120, 'UtcTime': '2024-01-01 12:00:02.000', 'Data': []}
    
    # First two events have max <= 100 - no alert
    assert len(sigma.check_events([event1])) == 0
    assert len(sigma.check_events([event2])) == 0
    
    # Third event has max 120 > 100 - should alert
    alerts = sigma.check_events([event3])
    assert len(alerts) == 1


def test_avg_aggregation():
    """Test avg() aggregation."""
    reset_aggregation_state()
    
    sigma = PySigma()
    sigma.add_signature("""
        title: avg test
        id: test-avg-001
        detection:
            selection:
                EventID: 1234
            condition: selection | avg(score) > 75
    """)
    
    # Events with scores
    event1 = {'EventID': '1234', 'score': 70, 'UtcTime': '2024-01-01 12:00:00.000', 'Data': []}
    event2 = {'EventID': '1234', 'score': 80, 'UtcTime': '2024-01-01 12:00:01.000', 'Data': []}
    event3 = {'EventID': '1234', 'score': 90, 'UtcTime': '2024-01-01 12:00:02.000', 'Data': []}
    
    # First event avg is 70 - no alert
    assert len(sigma.check_events([event1])) == 0
    
    # Second event avg is 75 - no alert (needs to be > 75)
    assert len(sigma.check_events([event2])) == 0
    
    # Third event avg is 80 - should alert
    alerts = sigma.check_events([event3])
    assert len(alerts) == 1


def test_min_aggregation():
    """Test min() aggregation."""
    reset_aggregation_state()
    
    sigma = PySigma()
    sigma.add_signature("""
        title: min test
        id: test-min-001
        detection:
            selection:
                EventID: 1234
            condition: selection | min(response_time) < 20
    """)
    
    # Events with response times
    event1 = {'EventID': '1234', 'response_time': 50, 'UtcTime': '2024-01-01 12:00:00.000', 'Data': []}
    event2 = {'EventID': '1234', 'response_time': 30, 'UtcTime': '2024-01-01 12:00:01.000', 'Data': []}
    event3 = {'EventID': '1234', 'response_time': 10, 'UtcTime': '2024-01-01 12:00:02.000', 'Data': []}
    
    # First two events have min >= 20 - no alert
    assert len(sigma.check_events([event1])) == 0
    assert len(sigma.check_events([event2])) == 0
    
    # Third event has min 10 < 20 - should alert
    alerts = sigma.check_events([event3])
    assert len(alerts) == 1


def test_less_than_comparison():
    """Test aggregation with < operator."""
    reset_aggregation_state()
    
    sigma = PySigma()
    sigma.add_signature("""
        title: less than test
        id: test-lt-001
        detection:
            selection:
                EventID: 1234
            condition: selection | count() < 3
    """)
    
    event = {'EventID': '1234', 'UtcTime': '2024-01-01 12:00:00.000', 'Data': []}
    
    # First two events count < 3 - should alert
    assert len(sigma.check_events([event])) == 1
    assert len(sigma.check_events([event])) == 1
    
    # Third event count is 3 - no alert
    assert len(sigma.check_events([event])) == 0


def test_equals_comparison():
    """Test aggregation with = operator."""
    reset_aggregation_state()
    
    sigma = PySigma()
    sigma.add_signature("""
        title: equals test
        id: test-eq-001
        detection:
            selection:
                EventID: 1234
            condition: selection | count() = 2
    """)
    
    event = {'EventID': '1234', 'UtcTime': '2024-01-01 12:00:00.000', 'Data': []}
    
    # First event count is 1 - no alert
    assert len(sigma.check_events([event])) == 0
    
    # Second event count is 2 - should alert
    alerts = sigma.check_events([event])
    assert len(alerts) == 1
    
    # Third event count is 3 - no alert
    assert len(sigma.check_events([event])) == 0
