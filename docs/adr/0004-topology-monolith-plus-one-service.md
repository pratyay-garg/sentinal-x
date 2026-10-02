# ADR-0004: Monolith backend + one isolated phishing service (Approach C)

- Status: accepted
- Date: 2026-09-08

## Context
Discovery, validation, correlation, prioritization, remediation, and retest all share
the Security Graph constantly. Full microservices add Docker-networking overhead that
eats limited time and is hard to debug live. Phishing/URL/email intel is logically
independent and low mark weight.

## Decision
Keep all graph-sharing engines in one FastAPI monolith. Split only the
phishing/URL/email intel into a separate lightweight service. Ship everything with a
single docker-compose (backend, worker, postgres, redis, frontend, phishing-service),
satisfying "Dockerization is preferred" without full-microservice coordination cost.

## Consequences
Fast to build and demo; natural integration (a monolith integrates by construction);
one obvious deploy target; the independent module can be owned by a smaller sub-team.
