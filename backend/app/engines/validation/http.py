"""
Minimal HTTP value types shared by the control engine and every oracle.

Kept transport-agnostic on purpose. A `Fetcher` is anything that turns a
`Request` into a `Response`: in production it is a thin httpx adapter that first
passes the URL through the scope gate and acquires the target limiter; in tests
it is the in-process `MockTarget`. Because the logic never imports httpx, the
whole control engine is testable offline with zero network and zero flake.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class Request:
    method: str = "GET"
    url: str = "/"
    params: tuple[tuple[str, str], ...] = ()      # ordered, hashable
    headers: tuple[tuple[str, str], ...] = ()
    body: str | None = None

    @staticmethod
    def get(url: str, **params) -> "Request":
        return Request(method="GET", url=url,
                       params=tuple(sorted(params.items())))


@dataclass(frozen=True)
class Response:
    status: int
    body: str = ""
    headers: tuple[tuple[str, str], ...] = ()
    elapsed_ms: float = 0.0

    @property
    def is_2xx(self) -> bool:
        return 200 <= self.status < 300


class Fetcher(Protocol):
    def __call__(self, request: Request) -> Response: ...
