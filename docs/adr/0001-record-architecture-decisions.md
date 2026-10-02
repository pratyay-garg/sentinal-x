# ADR-0001: Record architecture decisions

- Status: accepted
- Date: 2026-09-08

## Context
A 12-day, 6-person build fails when decisions made early are silently re-made
differently later, drifting the codebase and forcing structure-breaking re-patches.

## Decision
We record every significant architectural decision as a short ADR in `docs/adr/`.
Before reversing any recorded decision, we update its ADR first, then change code.
CLAUDE.md points here so every session re-reads the locked decisions.

## Consequences
Decisions stay made. The AI and the team share one memory of "why it is this way,"
which prevents the re-invention that corrupts structure mid-build.
