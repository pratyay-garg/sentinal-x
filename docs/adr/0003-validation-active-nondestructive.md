# ADR-0003: Validation is active but strictly non-destructive

- Status: accepted
- Date: 2026-09-08

## Context
Autonomous pentest validation is the largest single mark bucket (15). The rules
prohibit destructive exploitation, persistence, and credential theft. Passive-only
checks give a weak confidence story; full exploit chains are disallowed.

## Decision
Confirm exploitability with harmless markers only: a unique reflected string for
reflected/DOM XSS (detected via headless browser), boolean/time-based diff for SQLi,
controlled parameter tampering with an authorized test account for IDOR/BOLA, and
passive signature checks for misconfigurations. Every confirmation produces an
evidence bundle (request, response, diff, screenshot) and a 0-100 confidence score.
All of it runs behind the scope allow-list and honors the kill-switch.

## Consequences
Real exploitability evidence with zero destructive action; safe to run against the
authorized target; directly answers the graded "is it actually exploitable" question.
