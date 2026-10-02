"""Register the app.engines.intel modules under their bare names too, so tests
that do `patch("webpage_analyzer...")` (flat module-path strings) resolve, mapped
flat form (``url_analyzer``, looked up dynamically via ``importlib`` in parts of
the suite), and the historical ``intelligence.url_analyzer`` form — and crucially
map all three to the SAME module object, so a ``monkeypatch.setattr`` on one name
is seen by code that imported under another.
"""
import importlib
import os
import sys
import types

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

_MODULES = (
    "url_analyzer", "email_analyzer", "webpage_analyzer",
    "reputation", "domain_analyzer", "ip_analyzer",
)

# Register an `intelligence` package that points at this directory before any
# module (which may do `from .reputation import ...` / `from intelligence...`)
# is imported.
if "intelligence" not in sys.modules:
    _intel = types.ModuleType("intelligence")
    _intel.__path__ = [_HERE]
    sys.modules["intelligence"] = _intel

for _name in _MODULES:
    _mod = importlib.import_module(f"app.engines.intel.{_name}")
    sys.modules[_name] = _mod
    sys.modules[f"intelligence.{_name}"] = _mod
    setattr(sys.modules["intelligence"], _name, _mod)
