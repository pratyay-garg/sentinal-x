# ADR-0005: Nuclei as the primary web scanner (ZAP optional stretch)

- Status: accepted
- Date: 2026-09-08

## Context
We should not reinvent a scanner (the value is in correlation, not scanner building).
We need real findings fast, with machine-parseable output.

## Decision
Use Nuclei with curated templates as the primary discovery scanner, consumed via its
JSON output in `app/tools/`. nmap covers infra/service scanning; subfinder/amass cover
asset enumeration. OWASP ZAP (daemon/API mode) is an optional stretch if time allows.

## Consequences
Fast, clean JSON to map into Finding records; one wrapper file isolates output-format
changes. If the evaluation target needs ZAP's deeper active scan, add it behind the
same tools interface without touching engines.
