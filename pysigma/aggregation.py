"""
Aggregation support for Sigma rules.

Handles aggregation expressions like:
- count() > 5
- count() by src_ip > 10
- min(field) < 100
- max(field) > 1000
- avg(field) > 50
- sum(field) > 10000
"""

from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Callable
from collections import defaultdict


class AggregationState:
    """Manages event state for aggregation queries across multiple events."""
    
    def __init__(self):
        # Store events per rule: {rule_id: [event_dict, ...]}
        self.events: Dict[str, List[Dict]] = defaultdict(list)
        # Store event timestamps per rule for timeframe cleanup
        self.timestamps: Dict[str, List[datetime]] = defaultdict(list)
    
    def add_event(self, rule_id: str, event: Dict, timestamp_field: str = 'UtcTime'):
        """Add an event to the aggregation state for a rule."""
        self.events[rule_id].append(event)
        
        # Extract timestamp
        ts = event.get(timestamp_field)
        if ts:
            try:
                if isinstance(ts, str):
                    dt = datetime.strptime(ts, '%Y-%m-%d %H:%M:%S.%f')
                else:
                    dt = ts
                self.timestamps[rule_id].append(dt)
            except (ValueError, TypeError):
                # If we can't parse timestamp, use current time
                self.timestamps[rule_id].append(datetime.now())
        else:
            self.timestamps[rule_id].append(datetime.now())
    
    def cleanup_old_events(self, rule_id: str, timeframe: str):
        """Remove events older than the specified timeframe."""
        if not timeframe or rule_id not in self.timestamps:
            return
        
        time_limit = self._parse_timeframe(timeframe)
        if time_limit is None:
            return
        
        cutoff_time = datetime.now() - time_limit
        
        # Filter out old events
        new_events = []
        new_timestamps = []
        
        for event, ts in zip(self.events[rule_id], self.timestamps[rule_id]):
            if ts >= cutoff_time:
                new_events.append(event)
                new_timestamps.append(ts)
        
        self.events[rule_id] = new_events
        self.timestamps[rule_id] = new_timestamps
    
    def _parse_timeframe(self, timeframe: str) -> Optional[timedelta]:
        """Parse a Sigma timeframe string into a timedelta."""
        if not timeframe:
            return None
        
        timeframe = str(timeframe).strip()
        
        if timeframe.endswith('M'):
            # Months (approximate as 30 days)
            return timedelta(days=int(timeframe[:-1]) * 30)
        elif timeframe.endswith('d'):
            return timedelta(days=int(timeframe[:-1]))
        elif timeframe.endswith('h'):
            return timedelta(hours=int(timeframe[:-1]))
        elif timeframe.endswith('m'):
            return timedelta(minutes=int(timeframe[:-1]))
        elif timeframe.endswith('s'):
            return timedelta(seconds=int(timeframe[:-1]))
        
        return None
    
    def get_events(self, rule_id: str) -> List[Dict]:
        """Get all stored events for a rule."""
        return self.events[rule_id]
    
    def clear_rule(self, rule_id: str):
        """Clear all events for a specific rule."""
        if rule_id in self.events:
            del self.events[rule_id]
        if rule_id in self.timestamps:
            del self.timestamps[rule_id]


class AggregationEvaluator:
    """Evaluates aggregation expressions against collected events."""
    
    def __init__(self, state: AggregationState):
        self.state = state
    
    def evaluate(self, 
                 rule_id: str,
                 func_name: str, 
                 field: Optional[str], 
                 group_by: Optional[str],
                 comparison_op: str, 
                 threshold: int,
                 timeframe: Optional[str] = None,
                 current_event: Optional[Dict] = None) -> bool:
        """
        Evaluate an aggregation expression.
        
        Args:
            rule_id: The rule identifier
            func_name: One of 'count', 'min', 'max', 'avg', 'sum'
            field: The field to aggregate (None for count)
            group_by: Field to group by (None for no grouping)
            comparison_op: One of '>', '<', '='
            threshold: The value to compare against
            timeframe: Optional timeframe string for windowing
            current_event: The current event being evaluated (needed for group_by)
        
        Returns:
            True if the aggregation condition is met
        """
        # Clean up old events first
        if timeframe:
            self.state.cleanup_old_events(rule_id, timeframe)
        
        events = self.state.get_events(rule_id)
        
        if not events:
            return False
        
        if group_by:
            # Group events by the specified field
            groups = defaultdict(list)
            for event in events:
                key = event.get(group_by, None)
                groups[key].append(event)
            
            # Only check the group of the current event
            if current_event:
                current_group = current_event.get(group_by, None)
                if current_group in groups:
                    group_events = groups[current_group]
                    result = self._compute_aggregation(func_name, field, group_events)
                    return self._compare(result, comparison_op, threshold)
                return False
            else:
                # Fallback: check if any group meets the condition (original behavior)
                for group_key, group_events in groups.items():
                    result = self._compute_aggregation(func_name, field, group_events)
                    if self._compare(result, comparison_op, threshold):
                        return True
                return False
        else:
            # No grouping - evaluate all events together
            result = self._compute_aggregation(func_name, field, events)
            return self._compare(result, comparison_op, threshold)
    
    def _compute_aggregation(self, func_name: str, field: Optional[str], events: List[Dict]) -> float:
        """Compute an aggregation function over a list of events."""
        
        if func_name == 'count':
            return float(len(events))
        
        if not field:
            return 0.0
        
        # Extract values for the field
        values = []
        for event in events:
            val = event.get(field)
            if val is not None:
                try:
                    values.append(float(val))
                except (ValueError, TypeError):
                    pass
        
        if not values:
            return 0.0
        
        if func_name == 'sum':
            return sum(values)
        elif func_name == 'min':
            return min(values)
        elif func_name == 'max':
            return max(values)
        elif func_name == 'avg':
            return sum(values) / len(values)
        
        return 0.0
    
    def _compare(self, value: float, op: str, threshold: int) -> bool:
        """Compare a value against a threshold using the given operator."""
        if op == '>':
            return value > threshold
        elif op == '<':
            return value < threshold
        elif op == '=':
            return value == threshold
        return False


# Global aggregation state instance
aggregation_state = AggregationState()

def get_aggregation_state() -> AggregationState:
    """Get the global aggregation state instance."""
    return aggregation_state

def reset_aggregation_state():
    """Reset the global aggregation state."""
    global aggregation_state
    aggregation_state = AggregationState()
