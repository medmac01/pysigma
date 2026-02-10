"""
This parser uses lark to transform the condition strings from signatures into callbacks that
invoke the right sequence of searches into the rule and logic operations.
"""
from typing import Any, Callable, Dict, Union

from lark import Lark, Transformer, Token

from .aggregation import AggregationEvaluator, get_aggregation_state
from .build_alert import Alert, callback_buildReport, check_timeframe
from .exceptions import UnsupportedFeature
from .sigma_configuration import PRODUCT_CATEGORY_MAPPING
from .sigma_scan import analyze_x_of, match_search_id
from .windows_event_logs import prepare_event_log

# Grammar defined for the condition strings within the Sigma rules
grammar = '''
        start: pipe_rule
        %import common.WORD   // imports from terminal library
        %ignore " "           // Disregard spaces in text
        pipe_rule: or_rule ["|" aggregation_expression]
        or_rule: and_rule (("or"|"OR") and_rule)*
        and_rule: not_rule (("and"|"AND") not_rule)*
        not_rule: [not] atom
        not: "NOT" | "not"
        atom: x_of | search_id | "(" pipe_rule ")"
        search_id: SEARCH_ID
        x: ALL | NUMBER
        x_of: x OF search_pattern
        search_pattern: /[a-zA-Z*_][a-zA-Z0-9*_]*/
        aggregation_expression: aggregation_function "(" [aggregation_field] ")" [ "by" group_field ] comparison_op value
                              | near_aggregation
        aggregation_function: COUNT | MIN | MAX | AVG | SUM
        near_aggregation: "near" or_rule
        aggregation_field: SEARCH_ID
        group_field: SEARCH_ID
        comparison_op: GT | LT | EQ
        GT: ">"
        LT: "<"
        EQ: "="
        value: NUMBER
        NUMBER: /[0-9]+/
        NOT: "NOT"
        SEARCH_ID: /[a-zA-Z_][a-zA-Z0-9_]*/
        ALL: "all"
        OF: "of"
        COUNT: "count"
        MIN: "min"
        MAX: "max"
        AVG: "avg"
        SUM: "sum"
        '''


def check_event(raw_event, rules, aggregation_state=None):
    event = prepare_event_log(raw_event)
    alerts = []
    timed_events = []
    
    if aggregation_state is None:
        aggregation_state = get_aggregation_state()
    
    rules = _get_relevant_rules(event, rules)

    for rule_id, rule_obj in rules.items():
        condition = rule_obj.get_condition()
        rule_name = rule_obj.title
        
        # The condition function now handles aggregation internally
        # It will:
        # 1. Check base condition
        # 2. If true and there's aggregation, add to state and check aggregation
        # 3. Return true only if both pass
        if condition(rule_obj, event, aggregation_state):
            timeframe = rule_obj.get_timeframe()
            if timeframe is not None:
                check_timeframe(rule_obj, rule_name, timed_events, event, alerts)
            else:
                alert = Alert(rule_name, rule_obj.description, event, rule_obj.level,
                              rule_obj.id, rule_obj.file_name, rule_obj.signature_source)
                callback_buildReport(alerts, alert)
    return alerts


def get_category(event):
    channel = event.get("Channel").lower()
    for product, category_spec in PRODUCT_CATEGORY_MAPPING.items():
        if product in channel:
            for category, conditions in category_spec.items():
                # Can't trust verifying against categories with no conditions (ambiguous)
                if not conditions:
                    continue
                condition_valid = True
                for c_name, c_value in conditions.items():
                    # If the event doesn't contain the condition params, ignore it
                    if not event.get(c_name):
                        condition_valid = False
                        break

                    if isinstance(c_value, int):
                        condition_valid = condition_valid & (int(event[c_name]) == c_value)
                    else:
                        condition_valid=condition_valid & (event[c_name] in c_value)
                if condition_valid:
                    return category
    return None

def _get_relevant_rules(event: dict, rules: Dict[str, Any]) -> Dict[str, Any]:
    """
    This method grabs a subset of the Sigma rules that are relevant to the event
    https://github.com/SigmaHQ/sigma/wiki/Specification#log-source
    :param channel: The channel in which the EVTX event was generated
    :param rules: All Sigma rules
    :return: A subset of relevant Sigma rules for the channel
    """
    if not event.get("Channel"):
        return rules

    channel = event.get("Channel").lower()
    event_category = get_category(event)

    relevant_rules: Dict[str, Any] = {}
    for id, signature in rules.items():
        logsource = signature.get_logsource()
        prefilter_items = [logsource.get("product"),
                           logsource.get("service"),
                           ]
        if event_category and not event_category.startswith(str(logsource.get('category'))):
            continue
        if any(element.lower() not in channel for element in prefilter_items if element):
            continue

        relevant_rules[id] = signature

    return relevant_rules

#
# def parse_logfiles(*logfiles):
#     """
#     Main function tests every event against every rule in the provided list of files
#     :param logfiles: paths to each logfile
#     :return: dict of filename <-> event-alert tuples
#     """
#     for evt in logfiles:
#         event_logfiles.append(SCRIPT_LOCATION / Path(evt))
#     print()
#
#     file_event_alerts = {}
#
#     for f in event_logfiles:
#         log_dict = load_events(f)
#         try:
#             # handle single event
#             if type(log_dict['Events']['Event']) is list:
#                 events = log_dict['Events']['Event']
#             else:
#                 events = [log_dict['Events']['Event']]
#         except KeyError:
#             raise ValueError("The input file %s does not contain any events or is improperly formatted")
#
#         file_event_alerts[f.name] = []
#
#         for e in events:
#             alerts = check_event(e)
#             if len(alerts) > 0:
#                 file_event_alerts[f.name].append((e, alerts))
#
#     return file_event_alerts


def true_function(*_state):
    return True


def false_function(*_state):
    return False


class FactoryTransformer(Transformer):
    @staticmethod
    def start(args):
        return args[0]

    @staticmethod
    def search_id(args):
        name = args[0].value

        def match_hits(signature, event, aggregation_state=None):
            return match_search_id(signature, event, name)

        return match_hits

    @staticmethod
    def search_pattern(args):
        return args[0].value

    @staticmethod
    def atom(args):
        if not all((callable(_x) for _x in args)):
            raise ValueError(args)
        return args[0]

    @staticmethod
    def not_rule(args):
        negate, value = args
        assert callable(value)
        if negate is None:
            return value

        def _negate(signature, event, aggregation_state=None):
            return not value(signature, event, aggregation_state)
        return _negate

    @staticmethod
    def and_rule(args):
        if not all((callable(_x) for _x in args)):
            raise ValueError(args)

        if len(args) == 1:
            return args[0]

        def _and_operation(signature, event, aggregation_state=None):
            for component in args:
                if not component(signature, event, aggregation_state):
                    return False
            return True

        return _and_operation

    @staticmethod
    def or_rule(args):
        if not all((callable(_x) for _x in args)):
            raise ValueError(args)

        if len(args) == 1:
            return args[0]

        def _or_operation(signature, event, aggregation_state=None):
            for component in args:
                if component(signature, event, aggregation_state):
                    return True
            return False

        return _or_operation

    @staticmethod
    def pipe_rule(args):
        # args can be [base_condition] or [base_condition, aggregation]
        if len(args) == 1:
            # No aggregation, just return base condition
            return args[0]
        
        # There is an aggregation
        base_condition = args[0]
        aggregation = args[1]
        
        def _pipe_with_aggregation(signature, event, aggregation_state=None):
            # First check base condition
            if callable(base_condition):
                base_result = base_condition(signature, event, aggregation_state)
            else:
                base_result = bool(base_condition)
            
            if not base_result:
                return False
            
            # Base condition matched, add event to state for aggregation
            if aggregation_state is None:
                aggregation_state = get_aggregation_state()
            
            # Track this event before evaluating aggregation
            aggregation_state.add_event(signature.id, event)
            
            # Now evaluate aggregation
            if callable(aggregation):
                return aggregation(signature, event, aggregation_state)
            
            return True
        
        return _pipe_with_aggregation

    @staticmethod
    def x_of(args):
        # Load the left side of the X of statement
        count = None
        if args[0].children[0].type == 'NUMBER':
            count = int(args[0].children[0].value)

        # Load the right side of the X of statement
        selector = str(args[2])
        if selector == "them":
            selector = None

        # Create a closure on our
        def _check_of_sections(signature, event, aggregation_state=None):
            return analyze_x_of(signature, event, count, selector)
        return _check_of_sections

    @staticmethod
    def aggregation_function(args):
        # Return the aggregation function name (count, min, max, avg, sum)
        if args and hasattr(args[0], 'value'):
            return args[0].value.lower()
        return 'count'

    @staticmethod
    def aggregation_field(args):
        # Return the field name for aggregation, or None if not specified
        if args and hasattr(args[0], 'value'):
            return args[0].value
        return None

    @staticmethod
    def group_field(args):
        # Return the group by field name, or None if not specified
        if args and hasattr(args[0], 'value'):
            return args[0].value
        return None

    @staticmethod
    def comparison_op(args):
        # Return the comparison operator (>, <, =)
        if args and hasattr(args[0], 'value'):
            return args[0].value
        return '>'

    @staticmethod
    def value(args):
        # Return the numeric threshold value
        if args and hasattr(args[0], 'value'):
            return int(args[0].value)
        return 1

    @staticmethod
    def aggregation_expression(args):
        # Parse aggregation arguments from the tree
        # args structure: [agg_func, agg_field, group_by, comparison_op, value]
        # or for near aggregation: [near_aggregation]
        
        if len(args) == 1 and callable(args[0]):
            # This is a near aggregation
            return args[0]
        
        # Regular aggregation - extract parameters
        # Note: The aggregation field is optional in the grammar
        agg_func = str(args[0]).lower() if args[0] else 'count'
        
        # Handle different argument patterns based on grammar
        # aggregation_function "(" [aggregation_field] ")" [ "by" group_field ] comparison_op value
        idx = 1
        agg_field = None
        if idx < len(args) and args[idx] is not None:
            agg_field = str(args[idx])
            idx += 1
        else:
            idx += 1  # Skip the None placeholder
        
        group_by = None
        if idx < len(args) and args[idx] is not None:
            group_by = str(args[idx])
            idx += 1
        else:
            idx += 1  # Skip the None placeholder
        
        comparison_op = str(args[idx]) if idx < len(args) and args[idx] else '>'
        idx += 1
        
        threshold = int(args[idx]) if idx < len(args) and args[idx] else 1
        
        def _aggregation_check(signature, event, aggregation_state=None):
            if aggregation_state is None:
                aggregation_state = get_aggregation_state()
            
            # Get timeframe from signature if available
            timeframe = signature.get_timeframe()
            
            # Evaluate the aggregation, passing the current event for group_by logic
            evaluator = AggregationEvaluator(aggregation_state)
            return evaluator.evaluate(
                rule_id=signature.id,
                func_name=agg_func,
                field=agg_field,
                group_by=group_by,
                comparison_op=comparison_op,
                threshold=threshold,
                timeframe=timeframe,
                current_event=event
            )
        
        return _aggregation_check

    @staticmethod
    def near_aggregation(args):
        # Extract the condition from near aggregation
        condition = args[0] if args else None
        
        def _near_aggregation_check(signature, event, aggregation_state=None):
            # For now, near aggregations are not fully implemented
            # They would require tracking event sequences and temporal proximity
            # TODO: Implement proper near aggregation with temporal window checking
            if condition and callable(condition):
                return condition(signature, event, aggregation_state)
            return True
        return _near_aggregation_check


# Create & initialize Lark class instance
factory_parser = Lark(grammar, parser='lalr', transformer=FactoryTransformer(), maybe_placeholders=True)


def prepare_condition(raw_condition: Union[str, list]) -> Callable:
    if isinstance(raw_condition, list):
        raw_condition = '(' + ') or ('.join(raw_condition) + ')'
    return factory_parser.parse(raw_condition)
