"""Retrieval probe for Graphiti, the primary target. Protocol: adapters/README.md.

Run (in the main mwe env, which already has graphiti_core):
    uv run python adapters/graphiti_probe.py

Two seeding modes, and the difference between them matters for the threat model:

`direct`   The harness writes v1 with `expired_at`/`invalid_at` set in the past, using
           the same EntityEdge API the library uses internally. This is the controlled
           experiment: revocation state is exact, repeatable and free of LLM variance,
           so any difference between cells is attributable to retrieval, not to how
           reliably the extractor noticed the contradiction.

`natural`  The harness only supplies plain text through `add_episode`: an older policy
           memo, then an update that contradicts it, and Graphiti's own extraction and
           invalidation logic decides that v1 is superseded and stamps `expired_at`
           itself. Nothing in this path requires database access, which is what the
           threat model actually grants the attacker (they can only cause text to be
           ingested). `natural` is therefore the end-to-end feasibility evidence and
           `direct` is the controlled measurement; both are reported.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
for sub in ('core', 'attacks'):
    sys.path.insert(0, str(ROOT / sub))

REQ = json.load(sys.stdin)
SITUATIONS = REQ['situations']
MODE = REQ.get('mode', 'direct')
VARIANT = REQ.get('variant', 'default')

from graphiti_core.edges import EntityEdge  # noqa: E402
from graphiti_core.nodes import EntityNode, EpisodeType  # noqa: E402
from graphiti_core.search.search_filters import (  # noqa: E402
    ComparisonOperator, DateFilter, SearchFilters,
)

from mwe_common import GROUP_ID, build_graphiti  # noqa: E402
from situations import episodes_for  # noqa: E402

NOW = datetime.now(timezone.utc)
PAST = NOW - timedelta(days=90)
ACTIVE_ONLY = SearchFilters(
    expired_at=[[DateFilter(comparison_operator=ComparisonOperator.is_null)]])


async def wipe(g):
    await g.driver.execute_query(
        'MATCH (n {group_id: $gid}) DETACH DELETE n', gid=GROUP_ID)


async def seed_direct(g, s):
    emb = g.clients.embedder
    a = EntityNode(name='Policy subject', group_id=GROUP_ID, labels=['Entity'],
                   created_at=PAST, summary='')
    b = EntityNode(name='Policy rule', group_id=GROUP_ID, labels=['Entity'],
                   created_at=PAST, summary='')
    for n in (a, b):
        await n.generate_name_embedding(emb)
        await n.save(g.driver)

    async def mk(fact, revoked, when):
        e = EntityEdge(name='POLICY', fact=fact, group_id=GROUP_ID,
                       source_node_uuid=a.uuid, target_node_uuid=b.uuid,
                       created_at=when, valid_at=when,
                       expired_at=(NOW - timedelta(days=1)) if revoked else None,
                       invalid_at=(NOW - timedelta(days=1)) if revoked else None)
        await e.generate_embedding(emb)
        await e.save(g.driver)

    await mk(s['v1'], True, PAST)
    await mk(s['v2'], False, NOW)
    for d in s.get('distractors', []):
        await mk(d, False, NOW)


async def seed_natural(g, s):
    """Text-only ingestion: Graphiti must revoke v1 on its own."""
    eps = episodes_for(s)
    for i, text in enumerate(eps):
        await g.add_episode(
            name=f'{s["name"]}_ep{i}',
            episode_body=text,
            source=EpisodeType.text,
            source_description='policy feed',
            reference_time=PAST if i == 0 else NOW,
            group_id=GROUP_ID,
        )


async def run() -> dict:
    g = build_graphiti(with_llm=(MODE == 'natural'))
    await g.build_indices_and_constraints()
    results = []
    try:
        for s in SITUATIONS:
            await wipe(g)
            if MODE == 'direct':
                await seed_direct(g, s)
            else:
                await seed_natural(g, s)

            atk = await g.search(query=s['query'], group_ids=[GROUP_ID], num_results=10)
            dfn = await g.search(query=s['query'], group_ids=[GROUP_ID], num_results=10,
                                 search_filter=ACTIVE_ONLY)

            revoked_idx = [i for i, e in enumerate(atk) if e.expired_at is not None]
            results.append({
                'situation': s['name'],
                'attack_facts': [e.fact for e in atk],
                # Records as an application would see them: Graphiti DOES expose the
                # revocation fields, so a backend-agnostic guard can use them here.
                'attack_records': [
                    {'fact': e.fact,
                     'expired_at': e.expired_at.isoformat() if e.expired_at else None,
                     'invalid_at': e.invalid_at.isoformat() if e.invalid_at else None,
                     'valid_at': e.valid_at.isoformat() if e.valid_at else None,
                     'created_at': e.created_at.isoformat() if e.created_at else None}
                    for e in atk],
                'defense_facts': [e.fact for e in dfn],
                'r_asr': bool(revoked_idx),
                'revoked_rank': (revoked_idx[0] + 1) if revoked_idx else None,
                'n_revoked_returned': len(revoked_idx),
                'revocation_mechanism': 'soft_expired_at',
                'note': '',
            })
    finally:
        await g.close()
    return {'project': 'graphiti', 'runtime': True, 'variant': VARIANT, 'mode': MODE,
            'results': results}


try:
    out = asyncio.run(run())
except Exception as e:
    out = {'project': 'graphiti', 'runtime': False, 'variant': VARIANT, 'mode': MODE,
           'error': f'{type(e).__name__}: {e}', 'results': []}

print('__RESULT__ ' + json.dumps(out))
