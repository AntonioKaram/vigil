"""Shared HTTP defaults."""
from __future__ import annotations

import httpx

USER_AGENT = "vigil/0.1 (cyber-signal brief; read-only)"


def get(url: str, *, timeout: float = 30.0, params: dict | None = None,
        headers: dict | None = None) -> httpx.Response:
    h = {"User-Agent": USER_AGENT}
    if headers:
        h.update(headers)
    r = httpx.get(url, timeout=timeout, follow_redirects=True,
                  params=params, headers=h)
    r.raise_for_status()
    return r
