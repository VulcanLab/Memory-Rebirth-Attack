"""Retrieval probe for mem0. See adapters/README.md for the stdin/stdout protocol.

Run (isolated env):
    uv run --with mem0ai --with qdrant-client python adapters/mem0_probe.py

mem0 is the most informative non-Graphiti system in this study because it offers a soft
revocation marker whose visibility is a single retrieval-time boolean:

  * soft expiry   : `add(..., expiration_date=...)` marks a memory expired but keeps
                    the row, and `search()` hides it *only because* `show_expired`
                    defaults to False.

It also has an LLM-driven consolidation step that may add, update or delete a memory when
new content resembles stored content. Note that this step is a decision, not a guarantee:
in our natural-seeding runs it consistently chose to add the new policy without retiring
the contradicted one, leaving both retrievable. We therefore label the natural arm by what
was observed (`llm_consolidation`) rather than asserting a delete that did not occur.

So mem0 lets us test the central claim as a controlled A/B inside one system: the same
store, the same data, one boolean apart.

  variant "default"      search(show_expired=False)  -> predicted R-ASR 0
  variant "show_expired" search(show_expired=True)   -> predicted R-ASR 1

If flipping that single default reproduces the attack, the vulnerability is a property
of the *retrieval policy*, not of any particular implementation.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from datetime import date, timedelta

# mem0 maintains its own bookkeeping store under MEM0_DIR at a FIXED path, separate from
# whatever vector-store path the config specifies. Constructing more than one client in a
# process makes the second one fail on a storage lock, which silently costs the whole
# system's results. Give this run a private directory before mem0 is imported.
os.environ.setdefault('MEM0_TELEMETRY', 'false')
os.environ['MEM0_DIR'] = tempfile.mkdtemp(prefix='mem0_home_')

REQ = json.load(sys.stdin)
SITUATIONS = REQ['situations']
MODE = REQ.get('mode', 'direct')
VARIANT = REQ.get('variant', 'default')

# Endpoint settings arrive as provider-neutral variables resolved by core/endpoints.py
# and exported by the harness. This probe therefore contains no provider name, no
# hostname and no model id; switching providers is a .env edit, nothing here changes.
BASE = (os.getenv('MWE_LLM_BASE') or '').rstrip('/')
KEY = os.getenv('MWE_LLM_KEY') or 'x'
MODEL = os.getenv('MWE_LLM_MODEL') or ''
EMBED_BASE = (os.getenv('MWE_EMBED_BASE') or 'http://localhost:11434/v1').rstrip('/')
EMBED_MODEL = os.getenv('MWE_EMBED_MODEL') or ''
EMBED_DIM = int(os.getenv('MWE_EMBED_DIM') or '768')

# mem0 reads OpenAI creds from the environment for both LLM and embedder.
os.environ['OPENAI_API_KEY'] = KEY
os.environ['OPENAI_BASE_URL'] = BASE

from pathlib import Path  # noqa: E402

# All probes import the SAME episode text from core/situations.py. Natural-mode
# ingestion must be word-for-word identical across projects or a difference in
# retrieval could just be a difference in what was written.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'core'))
from situations import asserts_revoked, episodes_for  # noqa: E402

from mem0 import Memory  # noqa: E402

CONFIG = {
    'llm': {'provider': 'openai',
            'config': {'model': MODEL, 'openai_base_url': BASE, 'api_key': KEY}},
    # Embeddings come from local Ollama, same embedder family as the Graphiti arm,
    # so retrieval quality is not a confound across projects.
    'embedder': {'provider': 'ollama',
                 'config': {'model': EMBED_MODEL, 'embedding_dims': EMBED_DIM,
                            'ollama_base_url': EMBED_BASE.replace('/v1', '')}},
    # Fresh store path per run: qdrant's local mode persists a collection (and its
    # vector width) under a fixed default path, which would otherwise leak state
    # between situations and between runs.
    'vector_store': {'provider': 'qdrant',
                     'config': {'on_disk': False, 'embedding_model_dims': EMBED_DIM,
                                'path': tempfile.mkdtemp(prefix='mem0_probe_')}},
}

USER = 'rebirth_probe'
YESTERDAY = (date.today() - timedelta(days=1)).isoformat()


def items_of(hits) -> list[dict]:
    return hits.get('results', hits) if isinstance(hits, dict) else hits


def facts_of(hits) -> list[str]:
    return [h.get('memory', '') for h in items_of(hits)]


# Fields mem0 actually returns to a caller. The guard is evaluated on what an
# application receives, so it gets these and nothing more; passing only the text would
# understate what a backend-agnostic filter can do on a store that does expose expiry.
RECORD_FIELDS = ('created_at', 'updated_at', 'expiration_date')


def records_of(hits) -> list[dict]:
    out = []
    for h in items_of(hits):
        rec = {'fact': h.get('memory', '')}
        rec.update({k: h[k] for k in RECORD_FIELDS if h.get(k)})
        out.append(rec)
    return out


def run() -> dict:
    results = []
    for s in SITUATIONS:
        cfg = json.loads(json.dumps(CONFIG))
        cfg['vector_store']['config']['path'] = tempfile.mkdtemp(prefix='mem0_probe_')
        m = Memory.from_config(cfg)

        if MODE == 'direct':
            # Explicit soft revocation: v1 carries a past expiration_date, v2 does not.
            # infer=False stores the text verbatim so the seeded fact is exactly ours.
            m.add(s['v1'], user_id=USER, infer=False, expiration_date=YESTERDAY)
            m.add(s['v2'], user_id=USER, infer=False)
            for d in s.get('distractors', []):
                m.add(d, user_id=USER, infer=False)
        else:
            # Natural: plain contradicting text; mem0's own consolidation step decides
            # what to do with the older memory. Whether it retires it is the system's
            # call, and is part of what this arm measures.
            for text in episodes_for(s):
                m.add(text, user_id=USER)

        show_expired = (VARIANT == 'show_expired')
        flt = {'user_id': USER}
        attack_hits = m.search(s['query'], filters=flt, limit=10,
                               show_expired=show_expired)
        attack = facts_of(attack_hits)
        # Defense arm: always hide expired records, whatever the variant asked for.
        defense = facts_of(m.search(s['query'], filters=flt, limit=10,
                                    show_expired=False))

        present = [i for i, f in enumerate(attack)
                   if asserts_revoked(f, s['v1'], s['v2'])]
        results.append({
            'situation': s['name'],
            'attack_facts': attack,
            'attack_records': records_of(attack_hits),
            'defense_facts': defense,
            'r_asr': bool(present),
            'revoked_rank': (present[0] + 1) if present else None,
            # Label what this arm actually exercised, not what the system can do in
            # principle. Under `direct` the harness sets expiration_date, so the soft
            # marker is genuinely in play. Under `natural` nothing is set by us: mem0's
            # own LLM-driven consolidation decides whether to add, update or delete, and
            # calling that 'hard_delete' would assert an outcome we did not observe;
            # in this study it consistently added without retiring the prior fact.
            'revocation_mechanism': ('soft_expiration_date' if MODE == 'direct'
                                     else 'llm_consolidation'),
            'note': '',
        })
    return {'project': 'mem0', 'runtime': True, 'variant': VARIANT, 'mode': MODE,
            'results': results}


try:
    out = run()
except Exception as e:  # surface the failure instead of pretending a clean 0
    out = {'project': 'mem0', 'runtime': False, 'variant': VARIANT, 'mode': MODE,
           'error': f'{type(e).__name__}: {e}', 'results': []}

print('__RESULT__ ' + json.dumps(out))
