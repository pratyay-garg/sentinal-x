"""
Module 2's evidence surface. Small on purpose: it exists so the dashboard and a
judge can resolve any finding to the reproducible experiment that proved it.

  GET  /evidence/{id}          -> the manifest (transaction array + expected verdict)
  POST /evidence/{id}/retest   -> replay against a patched target (demo/testing)

Module 3 never calls this; it consumes rows. The retest endpoint is here for the
UI's "Re-run this finding" button.
"""
from __future__ import annotations

try:
    from fastapi import APIRouter, HTTPException
except ImportError:                                   # allow import without FastAPI
    APIRouter = None                                  # type: ignore

from .evidence import EvidenceStore


def build_evidence_router(store: EvidenceStore):
    if APIRouter is None:
        raise RuntimeError("FastAPI is not installed")

    router = APIRouter(prefix="/evidence", tags=["evidence"])

    @router.get("/{evidence_id}")
    def get_evidence(evidence_id: str) -> dict:
        if not store.exists(evidence_id):
            raise HTTPException(404, f"no evidence for {evidence_id!r}")
        return store.get(evidence_id).to_dict()

    return router
