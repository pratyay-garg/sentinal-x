"""Deterministic remediation knowledge supplied alongside live evidence."""

GENERIC = {
    "fix_pattern": "Fix the data/control-flow root cause at the trust boundary; prefer framework-native safe APIs.",
    "anti_patterns": "Do not blacklist one payload, hide errors, or rely on client-side validation.",
    "virtual_patch_template": "Constrain the vulnerable parameter by type, length and grammar; log and reject violations.",
    "regression_risks": "Preserve valid encodings, authorization rules, error handling and existing API clients.",
}

KNOWLEDGE_BASE = {
    "sqli": {
        "fix_pattern": "Use parameterized queries/prepared statements; allow-list dynamic identifiers separately.",
        "anti_patterns": "Escaping alone, quote removal, payload signatures, or string-built SQL.",
        "virtual_patch_template": "Require the parameter's business type/length and reject SQL metacharacter structures, not a captured literal.",
        "regression_risks": "Search wildcards, Unicode, pagination and legitimate apostrophes need regression coverage.",
    },
    "xss_reflected": {
        "fix_pattern": "Apply context-aware output encoding at the sink and avoid unsafe HTML/DOM APIs.",
        "anti_patterns": "Input-only filtering, stripping script tags, or blocking one marker.",
        "virtual_patch_template": "Enforce the parameter's expected grammar and block structural markup/event-handler patterns.",
        "regression_risks": "Rich text, localization, URL contexts and double-encoding must be tested.",
    },
    "ssti": {
        "fix_pattern": "Never compile user-controlled template source; pass input only as template data in a sandboxed engine.",
        "anti_patterns": "Blocking braces or selected function names.",
        "virtual_patch_template": "Restrict input to its business grammar and reject template-expression structure.",
        "regression_risks": "Legitimate formatting syntax and localization placeholders may be affected.",
    },
    "security_misconfig_headers": {
        "fix_pattern": "Set the missing header centrally at the reverse proxy/framework middleware and test all response paths.",
        "anti_patterns": "Adding it on one route or duplicating contradictory header values.",
        "virtual_patch_template": "Inject a single policy header at the trusted edge after removing conflicting upstream values.",
        "regression_risks": "CSP can block required assets; HSTS must only be enabled after complete HTTPS readiness.",
    },
    "idor": {
        "fix_pattern": "Authorize every object operation against the authenticated subject and tenant, independent of object identifiers.",
        "anti_patterns": "Opaque IDs, hidden UI controls, or existence checks without ownership checks.",
        "virtual_patch_template": "Require authenticated identity and enforce subject-to-object policy before forwarding.",
        "regression_risks": "Administrative/support roles and cross-tenant workflows need explicit tests.",
    },
}


def guidance(vuln_class: str) -> dict[str, str]:
    return {**GENERIC, **KNOWLEDGE_BASE.get(vuln_class, {})}
