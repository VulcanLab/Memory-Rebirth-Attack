"""Retrieval probe for Zep CE. See adapters/README.md for the stdin/stdout protocol.

Run (isolated env; needs the stack from config/zep_ce.compose.yaml):
    uv run --with httpx --with neo4j python adapters/zep_probe.py

Zep is the productised form of Graphiti and the most important non-Graphiti target:
it shows whether the flaw survives packaging, or whether the product layer adds a
mitigation the engine lacks.

Two things make Zep a stronger case than Graphiti, not a weaker one:

  1. `POST /sessions/search` returns facts ranked by relevance with no temporal
     condition, so revoked facts come back exactly as in Graphiti.
  2. Zep's fact payload (`apidata.Fact`) carries only uuid / created_at / fact; the
     `ExpiredAt` and `InvalidAt` columns it maintains internally are **never sent to
     the caller**. A Graphiti user can at least filter client-side; a Zep user cannot
     see which returned fact is dead.

Because of (2) the probe reads revocation state straight from Zep's own Neo4j to
*label* the results. That is an instrumentation step for measurement only; it is not
a capability Zep offers an application, which is precisely the finding. The "defense"
arm below is therefore hypothetical: it shows what a temporal filter would achieve if
Zep exposed one.

Only `natural` mode applies: Zep has no API to insert a pre-revoked fact, so the
revocation must arise from its own contradiction handling, the same path an attacker
would have to induce.
"""

from __future__ import annotations

import json
import os
import sys
import time
import uuid

from pathlib import Path

import httpx
from neo4j import GraphDatabase

# All probes import the SAME episode text from core/situations.py. Natural-mode
# ingestion must be word-for-word identical across projects or a difference in
# retrieval could just be a difference in what was written.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'core'))
from situations import episodes_for  # noqa: E402


REQ = json.load(sys.stdin)
SITUATIONS = REQ['situations']
MODE = REQ.get('mode', 'natural')
VARIANT = REQ.get('variant', 'default')

# All Zep connection details come from the environment; see .env.example.
BASE = os.getenv('ZEP_BASE', 'http://localhost:8020/api/v2')
SECRET = os.getenv('ZEP_API_SECRET', '')
# CE authenticates with the "Api-Key" scheme, not "Bearer".
HDRS = {'Authorization': f'Api-Key {SECRET}', 'Content-Type': 'application/json'}
NEO_URI = os.getenv('ZEP_NEO4J_URI', 'bolt://localhost:7689')
NEO_AUTH = (os.getenv('ZEP_NEO4J_USER', 'neo4j'), os.getenv('ZEP_NEO4J_PASSWORD', ''))
# Zep ingests asynchronously through its graphiti worker; facts only become
# searchable, and contradictions only get resolved, after that finishes.
SETTLE_S = float(os.getenv('ZEP_SETTLE_S', '45'))


def revocation_map(driver) -> dict[str, bool]:
    """fact text -> is revoked, read from Zep's own store (API does not expose it)."""
    q = ('MATCH ()-[e:RELATES_TO]->() '
         'RETURN e.fact AS fact, e.expired_at AS expired, e.invalid_at AS invalid')
    with driver.session() as sess:
        return {r['fact']: bool(r['expired'] or r['invalid'])
                for r in sess.run(q) if r['fact']}


def wipe(driver):
    with driver.session() as sess:
        sess.run('MATCH (n) DETACH DELETE n')


def run() -> dict:
    results = []
    driver = GraphDatabase.driver(NEO_URI, auth=NEO_AUTH)
    with httpx.Client(timeout=180.0, headers=HDRS) as c:
        for s in SITUATIONS:
            wipe(driver)                       # isolate situations from each other
            uid = f'u{uuid.uuid4().hex[:10]}'
            sid = f's{uuid.uuid4().hex[:10]}'
            c.post(f'{BASE}/users', json={'user_id': uid})
            c.post(f'{BASE}/sessions', json={'session_id': sid, 'user_id': uid})

            for text in episodes_for(s):
                c.post(f'{BASE}/sessions/{sid}/memory',
                       json={'messages': [{'role': 'user', 'role_type': 'user',
                                           'content': text}]})
                time.sleep(SETTLE_S)

            r = c.post(f'{BASE}/sessions/search?limit=10',
                       json={'text': s['query'], 'user_id': uid})
            payload = r.json() if r.status_code == 200 else {}
            hits = payload.get('results', []) if isinstance(payload, dict) else []

            revoked_by_text = revocation_map(driver)
            attack, defense, records, revoked_rank = [], [], [], None
            for h in hits:
                fact = (h or {}).get('fact') or {}
                text = fact.get('fact') if isinstance(fact, dict) else None
                if not text:
                    continue
                attack.append(text)
                # Pass through EXACTLY the metadata the API gives an application, no
                # more. Zep returns a creation timestamp but no revocation fields, and
                # that asymmetry is what a backend-agnostic guard has to work with.
                records.append({k: v for k, v in fact.items()
                                if k in ('fact', 'uuid', 'created_at')})
                if revoked_by_text.get(text):
                    if revoked_rank is None:
                        revoked_rank = len(attack)
                else:
                    defense.append(text)

            results.append({
                'situation': s['name'],
                'attack_facts': attack,
                'attack_records': records,
                'defense_facts': defense,
                'r_asr': revoked_rank is not None,
                'revoked_rank': revoked_rank,
                'revocation_mechanism': 'soft_expired_at',
                'note': 'defense arm is hypothetical: Zep exposes no temporal filter '
                        'and does not return expired_at/invalid_at to callers',
            })
    driver.close()
    return {'project': 'zep', 'runtime': True, 'variant': VARIANT, 'mode': MODE,
            'results': results}


try:
    out = run()
except Exception as e:
    out = {'project': 'zep', 'runtime': False, 'variant': VARIANT, 'mode': MODE,
           'error': f'{type(e).__name__}: {e}', 'results': []}

print('__RESULT__ ' + json.dumps(out))
