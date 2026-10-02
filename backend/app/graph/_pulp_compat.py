"""Small PuLP 3.x/4.x compatibility surface used by the label-cut ILP."""
from __future__ import annotations


def make_binary(problem, name: str):
    """Create and register a binary variable without PuLP's deprecated path."""
    import pulp

    add_variable = getattr(problem, "add_variable", None)
    if callable(add_variable):
        return add_variable(name, lowBound=0, upBound=1, cat=pulp.LpBinary)
    try:
        variable = pulp.LpVariable(
            name, lowBound=0, upBound=1, cat=pulp.LpBinary,
            _skip_v4_deprecation=True,
        )
    except TypeError:  # PuLP 4 removes the private transition argument.
        variable = pulp.LpVariable(name, lowBound=0, upBound=1, cat=pulp.LpBinary)
    return variable


def pick_solver(pulp_module):
    """Return the first available quiet MILP solver, with a safe default."""
    for name in ("COIN_CMD", "HiGHS_CMD"):
        cls = getattr(pulp_module, name, None)
        if cls is None:
            continue
        try:
            solver = cls(msg=False)
            if solver.available():
                return solver
        except Exception:
            continue
    default = getattr(pulp_module, "LpSolverDefault", None)
    if default is not None and default.available():
        default.msg = False
        return default
    # Transition fallback for installations whose bundled solver is exposed
    # only through the legacy constructor. PuLP 3.3 accepts the private flag;
    # PuLP 4 removes both the warning and the flag.
    cls = pulp_module.PULP_CBC_CMD
    try:
        return cls(msg=False, _skip_v4_deprecation=True)
    except TypeError:
        return cls(msg=False)
