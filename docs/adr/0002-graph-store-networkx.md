# ADR-0002: Use networkx + Postgres for the Security Graph (not Neo4j)

- Status: accepted
- Date: 2026-09-08

## Context
Attack-path intelligence and break-the-chain are graph problems (entry point ->
chain -> critical asset). We need shortest paths, simple-path enumeration, and
betweenness centrality. Scale is hundreds of nodes, not millions.

## Decision
Model the graph in `networkx` in-process. Persist nodes/edges as rows/JSON in
Postgres and rebuild the graph object when needed. Do NOT deploy Neo4j.

## Consequences
- No extra database to deploy, learn (Cypher), or debug live during evaluation.
- Path ranking and centrality are a few lines of Python.
- If node counts ever explode (they will not at hackathon scale) we would revisit.
