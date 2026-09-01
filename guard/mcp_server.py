"""MCP server exposing the Stale-Retrieval Guard as an agent tool.

An agent that already calls a memory system's MCP tool can be protected without any
application change: point it at this server instead. The server forwards the query to
whatever backend is configured, runs `stale_guard` over the response, and returns the
filtered set plus what was withheld.

    agent ──MCP──► search_memory_guarded ──HTTP──► existing memory backend
                          │
                          └─ stale_guard: drop revoked / superseded, annotate

Backends are configured, never hardcoded. `GUARD_BACKEND` selects an adapter and the
matching `GUARD_BACKEND_*` variables configure it; adding a backend means adding one
function here and one block in `.env`.

Run:
    uv run --with mcp --with httpx python guard/mcp_server.py           # stdio
    GUARD_TRANSPORT=http GUARD_PORT=8100 uv run ... python guard/mcp_server.py

The tool returns, alongside the facts:
  * `withheld`  : what was removed and why. Never dropped silently: an agent that needs
                  history can still ask for it, and an operator can audit the filter.
  * `notes`     : a one-line summary suitable for surfacing to a user.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from stale_guard import GuardConfig, guard  # noqa: E402


def _env(key: str, default: str = '') -> str:
    v = os.getenv(key)
    return v if v not in (None, '') else default


CFG = GuardConfig(
    subject_overlap=float(_env('GUARD_SUBJECT_OVERLAP', '0.45')),
    require_opposition=_env('GUARD_REQUIRE_OPPOSITION', 'true').lower() != 'false',
    trust_explicit_fields=_env('GUARD_TRUST_EXPLICIT', 'true').lower() != 'false',
    max_withheld_ratio=float(_env('GUARD_MAX_WITHHELD_RATIO', '0.6')),
)

BACKEND = _env('GUARD_BACKEND', 'http').lower()
BACKEND_URL = _env('GUARD_BACKEND_URL')
BACKEND_KEY = _env('GUARD_BACKEND_KEY')
BACKEND_AUTH_SCHEME = _env('GUARD_BACKEND_AUTH_SCHEME', 'Bearer')
BACKEND_QUERY_FIELD = _env('GUARD_BACKEND_QUERY_FIELD', 'query')
BACKEND_RESULT_PATH = _env('GUARD_BACKEND_RESULT_PATH', 'results')


def _dig(payload: Any, path: str) -> list:
    """Walk a dotted path into the backend's response. Backends disagree about where
    the list lives (`results`, `data.facts`, or the top level), so it is configured."""
    if not path:
        return payload if isinstance(payload, list) else [payload]
    node = payload
    for part in path.split('.'):
        if isinstance(node, dict) and part in node:
            node = node[part]
        else:
            return payload if isinstance(payload, list) else []
    return node if isinstance(node, list) else [node]


def fetch_http(query: str, limit: int, extra: dict | None) -> list:
    """Generic adapter: POST the query to an OpenAI-style JSON search endpoint."""
    import httpx
    if not BACKEND_URL:
        raise RuntimeError('GUARD_BACKEND_URL is not set')
    headers = {'Content-Type': 'application/json'}
    if BACKEND_KEY:
        headers['Authorization'] = f'{BACKEND_AUTH_SCHEME} {BACKEND_KEY}'
    body = {BACKEND_QUERY_FIELD: query, 'limit': limit}
    body.update(extra or {})
    with httpx.Client(timeout=float(_env('GUARD_BACKEND_TIMEOUT', '120'))) as c:
        r = c.post(BACKEND_URL, json=body, headers=headers)
        r.raise_for_status()
        return _dig(r.json(), BACKEND_RESULT_PATH)


BACKENDS = {'http': fetch_http}


def search_guarded(query: str, limit: int = 10, extra: dict | None = None) -> dict:
    """Retrieve from the configured backend, then withhold superseded facts."""
    fetch = BACKENDS.get(BACKEND)
    if fetch is None:
        raise RuntimeError(f'GUARD_BACKEND={BACKEND!r} unknown; known: {list(BACKENDS)}')
    raw = fetch(query, limit, extra)
    res = guard(raw, CFG)
    return {
        'facts': res.texts,
        'withheld': res.withheld,
        'notes': res.notes,
        'n_retrieved': len(raw),
        'n_returned': len(res.kept),
    }


def build_server():
    from mcp.server.fastmcp import FastMCP
    mcp = FastMCP('stale-retrieval-guard')

    @mcp.tool()
    def search_memory_guarded(query: str, limit: int = 10) -> str:
        """Search long-term memory, excluding facts that have been superseded or revoked.

        Returns current facts only. Anything withheld is reported separately with the
        reason, so nothing is lost silently; ask for it explicitly if history is needed.
        """
        return json.dumps(search_guarded(query, limit), indent=2)

    @mcp.tool()
    def explain_guard() -> str:
        """Describe the active filtering policy and its thresholds."""
        return json.dumps({
            'backend': BACKEND,
            'stages': ['explicit revocation fields', 'pairwise contradiction', 'annotate'],
            'config': CFG.__dict__,
            'caveat': 'Heuristic mitigation. It cannot recover information the backend '
                      'never recorded, and contradiction detection has both false '
                      'positives and false negatives.',
        }, indent=2)

    return mcp


if __name__ == '__main__':
    server = build_server()
    if _env('GUARD_TRANSPORT', 'stdio').lower() == 'http':
        server.settings.port = int(_env('GUARD_PORT', '8100'))
        server.run(transport='streamable-http')
    else:
        server.run()
