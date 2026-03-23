"""
Filter tree builder — converts Procmon-format rules or nested dict DSL
into the filter tree structure consumed by the C++ backend.
"""

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

    Returns a nested dict/list tree with raw string values.
    """
    if not rules:
        return None

    include_by_field = {}  # canonical_key → [[field, op, val], ...]
    exclude_leaves = []    # [[field, op, val], ...]

    for rule in rules:
        if not _is_procmon_rule(rule):
            raise ValueError(
                f"Procmon filter rule must be [field, operator, value, "
                f"'include'|'exclude'], got: {rule!r}"
            )
        field_raw, op_raw, val_raw, action_raw = rule
        action = action_raw.lower().strip()
        if action not in _VALID_ACTIONS:
            raise ValueError(
                f"Rule action must be 'include' or 'exclude', got: '{action_raw}'"
            )

        leaf = [str(field_raw), str(op_raw), val_raw]

        if action == 'include':
            key = str(field_raw).lower().strip()
            include_by_field.setdefault(key, []).append(leaf)
        else:
            exclude_leaves.append(leaf)

    # Build include tree: same field → OR, different fields → AND
    include_tree = None
    if include_by_field:
        field_nodes = []
        for _key, field_leaves in include_by_field.items():
            if len(field_leaves) == 1:
                field_nodes.append(field_leaves[0])
            else:
                field_nodes.append({"OR": field_leaves})
        if len(field_nodes) == 1:
            include_tree = field_nodes[0]
        else:
            include_tree = {"AND": field_nodes}

    # Build exclude tree: all rules OR'd, then NOT'd
    exclude_node = None
    if exclude_leaves:
        if len(exclude_leaves) == 1:
            exclude_node = {"NOT": exclude_leaves[0]}
        else:
            exclude_node = {"NOT": {"OR": exclude_leaves}}

    # Combine
    if include_tree is not None and exclude_node is not None:
        return {"AND": [include_tree, exclude_node]}
    elif include_tree is not None:
        return include_tree
    elif exclude_node is not None:
        return exclude_node
    else:
        return None


def _validate_dsl(dsl):
    """Validate a nested dict DSL filter tree structure.

    Raises ValueError on invalid structure.
    Returns the validated tree (unchanged).
    """
    if isinstance(dsl, dict):
        keys = list(dsl.keys())
        if len(keys) != 1:
            raise ValueError(
                f"Filter dict must have exactly one key: 'AND', 'OR', or 'NOT'. "
                f"Got: {keys}"
            )
        key = keys[0].upper()
        if key not in ('AND', 'OR', 'NOT'):
            raise ValueError(
                f"Unknown filter key: '{keys[0]}'. Expected 'AND', 'OR', or 'NOT'"
            )
        value = dsl[keys[0]]

        if key == 'NOT':
            _validate_dsl(value)
        else:
            if not isinstance(value, list):
                raise ValueError(f"'{keys[0]}' value must be a list")
            if len(value) < 2:
                raise ValueError(f"'{keys[0]}' requires at least 2 elements")
            for item in value:
                _validate_dsl(item)

    elif isinstance(dsl, (list, tuple)):
        if len(dsl) != 3 or not isinstance(dsl[0], str):
            raise ValueError(
                f"Leaf rule must be [field, op, value] (3 elements with string field), "
                f"got: {dsl!r}"
            )
    else:
        raise ValueError(
            f"Filter element must be a dict or [field, op, value] list, "
            f"got {type(dsl).__name__}: {dsl!r}"
        )
    return dsl


def build_filter_tree(filters):
    """Build a filter tree from user input.

    Args:
        filters: Procmon-format list, dict DSL, None, or empty list.

    Returns:
        A nested dict/list tree with raw string values, or None.
    """
    if filters is None or (isinstance(filters, list) and len(filters) == 0):
        return None

    if isinstance(filters, list):
        # Check if it's a single leaf [field, op, value] or Procmon rules
        if (len(filters) >= 1 and isinstance(filters[0], (list, tuple))
                and len(filters[0]) == 4):
            # Procmon format
            return _optimize_tree(_procmon_to_tree(filters))
        # Could be a single leaf
        if len(filters) == 3 and isinstance(filters[0], str):
            return filters
        raise ValueError(
            f"filters list must contain Procmon rules [field, op, value, action] "
            f"or be a single [field, op, value] leaf"
        )

    if isinstance(filters, dict):
        _validate_dsl(filters)
        return _optimize_tree(filters)

    raise ValueError(
        f"filters must be a list (Procmon format) or dict "
        f"(DSL format), got {type(filters).__name__}"
    )


# ===========================================================================
# Filter tree optimiser
# ===========================================================================

# Evaluation cost per field name (lower = cheaper).
# Matches C++ rule types:
#   0 = RT_HEADER_CMP  (event_class, timestamp, duration, tid, event_index)
#   1 = RT_PROCESS_MASK (process_name, pid, parent_pid, user, …)
#   3 = RT_OP_REGEX
#   4 = RT_RESULT_REGEX
#   5 = RT_PATH_REGEX   (expensive: must parse binary detail section)
#   6 = RT_CATEGORY_REGEX
#   7 = RT_DETAIL_REGEX (most expensive: full detail JSON parse)
_FIELD_COST = {
    'event_class':        0,
    'event_index':        0,
    'timestamp':          0,
    'duration':           0,
    'tid':                0,
    'result':             1,   # often exact → RT_HEADER_CMP; may be regex → 4
    'process_name':       1,
    'pid':                1,
    'parent_pid':         1,
    'user':               1,
    'company':            1,
    'version':            1,
    'description':        1,
    'integrity':          1,
    'session':            1,
    'authentication_id':  1,
    'virtualized':        1,
    'is_64_bit':          1,
    'image_path':         2,
    'command_line':       2,
    'operation':          3,
    'path':               5,
    'category':           6,
    'detail':             7,
}


def _leaf_cost(leaf) -> int:
    field = str(leaf[0]).lower().strip()
    return _FIELD_COST.get(field, 4)


def _node_cost(node) -> int:
    """Cost estimate for sorting: leaves by field, compound nodes last."""
    if isinstance(node, (list, tuple)):
        return _leaf_cost(node)
    return 100   # AND / OR / NOT subtree


def _optimize_tree(tree):
    """Recursively optimize a filter tree dict/list.

    Sort children cheapest-first for better short-circuit evaluation.

    Leaves and NOT nodes are returned unchanged.
    """
    if tree is None or isinstance(tree, (list, tuple)):
        return tree

    key = next(iter(tree))        # 'AND' / 'OR' / 'NOT'
    ukey = key.upper()

    if ukey == 'NOT':
        return {key: _optimize_tree(tree[key])}

    # Recurse on children first
    children = [_optimize_tree(c) for c in tree[key]]

    # Sort cheapest-first (stable to preserve semantics)
    children.sort(key=_node_cost)

    return {key: children}
