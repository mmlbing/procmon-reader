"""
Filter tree builder — converts Procmon-format rules or nested dict DSL
into the filter tree structure consumed by the C++ backend.
"""

import re

# ===========================================================================
# Field name tables
# ===========================================================================

_FIELD_NAME_ALIAS_TABLE: dict = {
    # canonical             aliases
    'event_index':         ['event_index'],
    'event_class':         ['event_class', 'event class', 'eventclass'],
    'operation':           ['operation'],
    'duration':            ['duration'],
    'timestamp':           ['timestamp', 'date_filetime', 'date', 'time',
                            'datetime', 'date and time', 'date_and_time'],
    'result':              ['result'],
    'tid':                 ['tid', 'thread_id', 'thread id'],
    'process_index':       ['process_index'],
    'process_name':        ['process_name', 'processname', 'process name'],
    'pid':                 ['pid', 'process_id'],
    'parent_pid':          ['parent_pid', 'parent pid', 'parentpid', 'ppid'],
    'image_path':          ['image_path', 'imagepath', 'image path'],
    'command_line':        ['command_line', 'commandline', 'command line'],
    'user':                ['user'],
    'company':             ['company'],
    'version':             ['version'],
    'description':         ['description'],
    'integrity':           ['integrity'],
    'session':             ['session'],
    'authentication_id':   ['authentication_id', 'authenticationid',
                            'authentication id'],
    'virtualized':         ['virtualized'],
    'is_64_bit':           ['is_64_bit', 'is_process_64bit', 'architecture'],
    'path':                ['path'],
    'category':            ['category'],
    'detail':              ['detail', 'details'],
    'stacktrace':          ['stacktrace', 'stack trace'],
}
# Reverse lookup: alias (lower) → canonical  (built once at import time)
_FIELD_NAME_ALIASES: dict = {
    alias: canonical
    for canonical, aliases in _FIELD_NAME_ALIAS_TABLE.items()
    for alias in aliases
}


def normalize_field_name(name: str) -> str:
    """Resolve a user-supplied field name to its canonical form.

    Returns the canonical name, or raises ValueError if unknown.
    """
    key = name.lower().strip()
    canonical = _FIELD_NAME_ALIASES.get(key)
    if canonical is None:
        raise ValueError(f"Unknown field: '{name}'")
    return canonical


# ===========================================================================
# Operator tables
# ===========================================================================


# Operator aliases
_OPERATOR_ALIAS_TABLE: dict = {
    # canonical      aliases
    '==':            ['==', 'is', 'equals', 'eq'],
    '!=':            ['!=', 'is_not', 'not_equals', 'ne'],
    '<':             ['<', 'lt', 'less_than'],
    '<=':            ['<=', 'le', 'less_equal', 'lte'],
    '>':             ['>', 'gt', 'more_than', 'greater_than'],
    '>=':            ['>=', 'ge', 'more_equal', 'greater_equal', 'gte'],
    'contains':      ['contains'],
    'starts_with':   ['starts_with'],
    'ends_with':     ['ends_with'],
    'excludes':      ['excludes'],
    'regex':         ['regex'],
}
# Reverse lookup: alias → canonical  (built once at import time)
_OPERATOR_ALIAS: dict = {
    alias: canonical
    for canonical, aliases in _OPERATOR_ALIAS_TABLE.items()
    for alias in aliases
}

# Valid numeric operators — canonical form is already the C++ symbol,
# passed through directly with no conversion.
_NUM_OPS: frozenset = frozenset({'==', '!=', '<', '<=', '>', '>='})

# String operators: canonical → (negated, pattern_builder)
#   negated=False → leaf [field, 'regex', pattern]
#   negated=True  → node {'NOT': [field, 'regex', pattern]}
_STR_OP_TABLE: dict = {
    # positive match
    '==':           (False, lambda v: r'^' + re.escape(v) + r'$'),
    'contains':     (False, lambda v: re.escape(v)),
    'starts_with':  (False, lambda v: r'^' + re.escape(v)),
    'ends_with':    (False, lambda v: re.escape(v) + r'$'),
    'regex':        (False, lambda v: v),
    # negated match
    '!=':           (True,  lambda v: r'^' + re.escape(v) + r'$'),
    'excludes':     (True,  lambda v: re.escape(v)),
}


# ===========================================================================
# Field registry — single source of truth
# ===========================================================================
# Each entry:  field_name → (eval_cost, type)
#   type        'num' | 'str'  — selects the operator table
#   eval_cost   0-6, controls filter-node sort order (lower = evaluated first)
#               Derived from C++ rule types in pml_filter_core.h:
#               0  RT_HEADER_CMP      direct header field compare (cheapest)
#               1  RT_PROCESS_MASK    precomputed bitmask lookup
#               2  RT_RESULT_REGEX    hash lookup + regex
#               3  RT_CATEGORY_REGEX  hash lookup + regex
#               4  RT_OP_REGEX        operation name resolution + regex
#               5  RT_PATH_REGEX      binary detail block parse + regex
#               6  RT_DETAIL_REGEX    full detail JSON parse (most expensive)
# ===========================================================================
_FIELD_REGISTRY: dict = {
    # field               cost  type
    # --- cost 0: direct header integer compare ---
    'event_class':       (0, 'num'),
    'event_index':       (0, 'num'),
    'timestamp':         (0, 'num'),
    'duration':          (0, 'num'),
    'tid':               (0, 'num'),
    # --- cost 1: process-table bitmask lookup ---
    'pid':               (1, 'num'),
    'parent_pid':        (1, 'num'),
    'session':           (1, 'num'),
    'authentication_id': (1, 'num'),
    'virtualized':       (1, 'num'),
    'is_64_bit':         (1, 'num'),
    'process_name':      (1, 'str'),
    'image_path':        (1, 'str'),
    'command_line':      (1, 'str'),
    'user':              (1, 'str'),
    'company':           (1, 'str'),
    'version':           (1, 'str'),
    'description':       (1, 'str'),
    'integrity':         (1, 'str'),
    # --- cost 2: per-event hash lookup + regex ---
    'result':            (2, 'str'),
    'category':          (3, 'str'),
    'operation':         (4, 'str'),
    'path':              (5, 'str'),
    'detail':            (6, 'str'),
}


# ===========================================================================
# Event class tables
# ===========================================================================


# Event class aliases
_EVENT_CLASS_ALIAS_TABLE: dict = {
    'File System': ['File System', 'File_System', 'FileSystem', 'fs'],
    'Registry':    ['Registry', 'reg'],
    'Process':     ['Process', 'proc'],
    'Network':     ['Network', 'net'],
    'Profiling':   ['Profiling', 'prof']
}
# Reverse lookup: alias (lower) → canonical  (built once at import time)
_EVENT_CLASS_ALIAS: dict = {
    alias.lower(): canonical
    for canonical, aliases in _EVENT_CLASS_ALIAS_TABLE.items()
    for alias in aliases
}


# ===========================================================================
# Leaf normalisation
# ===========================================================================

def _normalize_leaf_op(field: str, op: str, value):
    """Resolve a [field, op, value] leaf to the form the C++ backend expects.

    Returns:
        list  [field, canonical_op, value]         — positive match leaf
        dict  {'NOT': [field, 'regex', pattern]}   — negated string match
    """
    op_key = _OPERATOR_ALIAS.get(op.lower().strip(), op.lower().strip())

    canonical_field = normalize_field_name(field)
    meta = _FIELD_REGISTRY.get(canonical_field)
    if meta is None:
        raise ValueError(f"Field '{field}' is not filterable")

    _, field_type = meta

    # --- event_class: accept name string or int, validate early ---
    if canonical_field == 'event_class':
        if op_key not in _NUM_OPS:
            raise ValueError(
                f"Operator '{op}' is not supported for field 'event_class'. "
                f"Accepted: {', '.join(sorted(_NUM_OPS))}"
            )
        val_str = str(value).lower().strip()
        ec = _EVENT_CLASS_ALIAS.get(val_str)
        if ec is None:
            # Accept numeric values (0-5)
            try:
                iv = int(value)
                if 0 <= iv <= 5:
                    return [canonical_field, op_key, iv]
            except (ValueError, TypeError):
                pass
            raise ValueError(
                f"Unknown event_class '{value}'. "
                f"Accepted: {', '.join(_EVENT_CLASS_ALIAS_TABLE)}"
            )
        return [canonical_field, op_key, ec]

    if field_type == 'num':
        if op_key not in _NUM_OPS:
            raise ValueError(
                f"Operator '{op}' is not supported for numeric field '{field}'. "
                f"Accepted: {', '.join(sorted(_NUM_OPS))}"
            )
        return [canonical_field, op_key, value]

    entry = _STR_OP_TABLE.get(op_key)
    if entry is None:
        raise ValueError(
            f"Operator '{op}' is not supported for field '{field}'. "
            f"Accepted: {', '.join(sorted(_STR_OP_TABLE))}"
        )
    negated, pattern_fn = entry
    pattern = pattern_fn(str(value))
    return ({'NOT': [canonical_field, 'regex', pattern]} if negated
            else [canonical_field, 'regex', pattern])


# ===========================================================================
# Procmon format → filter tree
# ===========================================================================
_VALID_ACTIONS = frozenset({'include', 'exclude'})


def _is_procmon_rule(item) -> bool:
    """Check if an item looks like a [field, op, value, action] Procmon rule."""
    return (isinstance(item, (list, tuple))
            and len(item) == 4
            and isinstance(item[0], str)
            and isinstance(item[3], str))


def _procmon_to_tree(rules: list):
    """Convert Procmon-style rules to a filter tree dict.

    Each rule is ``[field, operator, value, 'include'|'exclude']``.

    Same-field include rules are OR'd; different-field include rules are AND'd.
    Exclude rules are OR'd then wrapped in NOT.
    Negated string operators (is_not, excludes, …) become standalone AND branches.

    Returns a nested dict/list tree, or None if rules is empty.
    """
    if not rules:
        return None

    include_by_field: dict = {}  # field_key → [leaf, ...]
    neg_include_nodes: list = [] # {'NOT': ...} nodes from negated string ops
    exclude_leaves:    list = [] # [field, op, val] leaves for exclude action

    for rule in rules:
        if not _is_procmon_rule(rule):
            raise ValueError(
                f"Procmon filter rule must be "
                f"[field, operator, value, 'include'|'exclude'], got: {rule!r}"
            )
        field_raw, op_raw, val_raw, action_raw = rule
        action = action_raw.lower().strip()
        if action not in _VALID_ACTIONS:
            raise ValueError(
                f"Rule action must be 'include' or 'exclude', got: '{action_raw}'"
            )

        leaf = _normalize_leaf_op(str(field_raw), str(op_raw), val_raw)

        if action == 'include':
            if isinstance(leaf, dict):
                # NOT node — cannot be grouped by field; kept as standalone branch
                neg_include_nodes.append(leaf)
            else:
                key = leaf[0]  # canonical field name
                include_by_field.setdefault(key, []).append(leaf)
        else:
            exclude_leaves.append(leaf)

    # Build include tree: same-field leaves → OR, then all branches → AND
    include_tree = None
    if include_by_field or neg_include_nodes:
        field_nodes = []
        for _key, field_leaves in include_by_field.items():
            field_nodes.append(field_leaves[0] if len(field_leaves) == 1
                               else {"OR": field_leaves})
        field_nodes.extend(neg_include_nodes)
        include_tree = (field_nodes[0] if len(field_nodes) == 1
                        else {"AND": field_nodes})

    # Build exclude tree: all leaves OR'd, then NOT'd
    exclude_node = None
    if exclude_leaves:
        exclude_node = ({"NOT": exclude_leaves[0]} if len(exclude_leaves) == 1
                        else {"NOT": {"OR": exclude_leaves}})

    if include_tree is not None and exclude_node is not None:
        return {"AND": [include_tree, exclude_node]}
    return include_tree if include_tree is not None else exclude_node


# ===========================================================================
# Nested dict DSL: validation & normalisation
# ===========================================================================

def _validate_dsl(dsl):
    """Validate a nested dict DSL filter tree structure.

    Raises ValueError on invalid structure.  Returns the tree unchanged.
    """
    if isinstance(dsl, dict):
        keys = list(dsl.keys())
        if len(keys) != 1:
            raise ValueError(
                f"Filter dict must have exactly one key ('AND', 'OR', or 'NOT'), "
                f"got: {keys}"
            )
        key = keys[0].upper()
        if key not in ('AND', 'OR', 'NOT'):
            raise ValueError(
                f"Unknown filter combinator '{keys[0]}'. Expected AND, OR, or NOT."
            )
        value = dsl[keys[0]]
        if key == 'NOT':
            _validate_dsl(value)
        else:
            if not isinstance(value, list):
                raise ValueError(f"'{keys[0]}' value must be a list")
            if len(value) < 1:
                raise ValueError(f"'{keys[0]}' requires at least 1 element")
            for item in value:
                _validate_dsl(item)
    elif isinstance(dsl, (list, tuple)):
        if len(dsl) != 3 or not isinstance(dsl[0], str):
            raise ValueError(
                f"Leaf rule must be [field, op, value] (3 elements, string field), "
                f"got: {dsl!r}"
            )
    else:
        raise ValueError(
            f"Filter element must be a dict or [field, op, value] list, "
            f"got {type(dsl).__name__}: {dsl!r}"
        )
    return dsl


def _normalize_dsl(dsl):
    """Walk a validated DSL tree and normalise all leaf operators.

    Returns a new tree; structure is unchanged except leaves may become
    {'NOT': leaf} nodes when a negated string operator is used.
    """
    if isinstance(dsl, dict):
        key = list(dsl.keys())[0]
        value = dsl[key]
        if key.upper() == 'NOT':
            return {key: _normalize_dsl(value)}
        children = [_normalize_dsl(item) for item in value]
        if len(children) == 1:
            return children[0]
        return {key: children}
    if isinstance(dsl, (list, tuple)):
        return _normalize_leaf_op(str(dsl[0]), str(dsl[1]), dsl[2])
    return dsl


# ===========================================================================
# Public entry point
# ===========================================================================

def build_filter_tree(filters):
    """Build a filter tree from user input.

    Args:
        filters: One of:
            - Procmon-format list: [[field, op, value, 'include'|'exclude'], ...]
            - Nested dict DSL: {"AND": [...]} / {"OR": [...]} / {"NOT": ...}
              AND/OR accept 1+ children; single-child AND/OR collapses to the child.
            - None or [] (no filter — matches all events)

    Returns:
        A nested dict/list filter tree for the C++ backend, or None.
    """
    if filters is None or (isinstance(filters, list) and len(filters) == 0):
        return None

    if isinstance(filters, list):
        if (isinstance(filters[0], (list, tuple))
                and len(filters[0]) == 4):
            return _optimize_tree(_procmon_to_tree(filters))
        raise ValueError(
            "filters list must be a Procmon rules list: [[field, op, value, 'include'|'exclude'], ...]"
        )

    if isinstance(filters, dict):
        _validate_dsl(filters)
        return _optimize_tree(_normalize_dsl(filters))

    raise ValueError(
        f"filters must be a list or dict, got {type(filters).__name__}"
    )


# ===========================================================================
# Filter tree optimiser — sort children cheapest-first
# ===========================================================================

_FIELD_COST: dict = {f: c for f, (c, _t) in _FIELD_REGISTRY.items()}


def _leaf_cost(leaf) -> int:
    return _FIELD_COST.get(str(leaf[0]).lower().strip(), 4)


def _node_cost(node) -> int:
    if isinstance(node, (list, tuple)):
        return _leaf_cost(node)
    if isinstance(node, dict):
        key = next(iter(node))
        if key.upper() == 'NOT':
            return _node_cost(node[key])  # NOT doesn't add eval cost
    return 100   # AND / OR subtree — sort after leaves


def _optimize_tree(tree):
    """Recursively sort AND/OR children cheapest-first for short-circuit gain."""
    if tree is None or isinstance(tree, (list, tuple)):
        return tree
    key = next(iter(tree))
    if key.upper() == 'NOT':
        return {key: _optimize_tree(tree[key])}
    children = [_optimize_tree(c) for c in tree[key]]
    children.sort(key=_node_cost)
    return {key: children}
