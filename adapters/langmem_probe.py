"""Retrieval probe for langmem. See adapters/README.md for the stdin/stdout protocol.

Run (isolated env):
    uv run --with langmem --with langchain-openai python adapters/langmem_probe.py

langmem stores memories in a LangGraph `BaseStore` and updates them through an
LLM-driven manager. It has no `expired_at` / `invalid_at` concept at all: an update
either overwrites a memory in place or (when `enable_deletes=True`) removes it. There
is therefore no revoked row for retrieval to leak, which is exactly why langmem is the
study's **negative control**: it isolates the causal claim to the soft-revoke design
rather than to "agent memory" in general.

Both arms hit the same store because there is nothing to filter; the defense arm being
identical to the attack arm IS the result, not a missing implementation.
"""

from __future__ import annotations

import json
import os
import sys

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
os.environ['OPENAI_API_KEY'] = KEY
os.environ['OPENAI_BASE_URL'] = BASE

from langchain_openai import ChatOpenAI, OpenAIEmbeddings  # noqa: E402
from langgraph.store.memory import InMemoryStore  # noqa: E402
from pathlib import Path  # noqa: E402

# All probes import the SAME episode text from core/situations.py. Natural-mode
# ingestion must be word-for-word identical across projects or a difference in
# retrieval could just be a difference in what was written.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'core'))
from situations import asserts_revoked, episodes_for  # noqa: E402

from langmem import create_memory_store_manager  # noqa: E402

NS = ('rebirth', 'policies')


def new_store() -> InMemoryStore:
    # Same local embedder as every other arm, so retrieval quality is not a confound.
    emb = OpenAIEmbeddings(model=EMBED_MODEL, base_url=EMBED_BASE,
                           api_key='ollama', check_embedding_ctx_length=False)
    return InMemoryStore(index={'dims': EMBED_DIM, 'embed': emb})


def run() -> dict:
    llm = ChatOpenAI(model=MODEL, base_url=BASE, api_key=KEY, temperature=0)
    results = []
    for s in SITUATIONS:
        store = new_store()
        if MODE == 'direct':
            # Direct arm = "revoke v1 using this system's OWN revocation primitive".
            # langmem has no soft marker; its primitive is delete/overwrite. Writing
            # v1 and v2 side by side would instead model a developer who never revoked
            # anything, and would make langmem look vulnerable for the wrong reason.
            v1_key = str(abs(hash(s['v1'])))
            for txt in [s['v1']] + list(s.get('distractors', [])):
                store.put(NS, str(abs(hash(txt))), {'content': txt})
            store.put(NS, str(abs(hash(s['v2']))), {'content': s['v2']})
            store.delete(NS, v1_key)          # <- the revocation
        else:
            # Natural arm: let langmem's own manager ingest the contradicting turns
            # and decide how to reconcile them.
            mgr = create_memory_store_manager(llm, namespace=NS, store=store,
                                              enable_deletes=True)
            for text in episodes_for(s):
                mgr.invoke({'messages': [{'role': 'user', 'content': text}]})

        hits = store.search(NS, query=s['query'], limit=10)
        facts = [str(h.value.get('content', h.value)) for h in hits]
        # Whatever the store surfaces to a caller. langmem carries no revocation field,
        # so these records deliberately show the guard a backend that offers timestamps
        # and nothing else.
        records = []
        for h in hits:
            rec = {'fact': str(h.value.get('content', h.value))}
            for attr in ('created_at', 'updated_at'):
                v = getattr(h, attr, None)
                if v:
                    rec[attr] = v.isoformat() if hasattr(v, 'isoformat') else str(v)
            records.append(rec)

        present = [i for i, f in enumerate(facts)
                   if asserts_revoked(f, s['v1'], s['v2'])]
        results.append({
            'situation': s['name'],
            'attack_facts': facts,
            'attack_records': records,
            # No revocation marker exists -> nothing for a filter to remove.
            'defense_facts': facts,
            'r_asr': bool(present),
            'revoked_rank': (present[0] + 1) if present else None,
            'revocation_mechanism': 'hard_delete',
            'note': 'no soft-revocation marker exists; defense arm == attack arm by design',
        })
    return {'project': 'langmem', 'runtime': True, 'variant': VARIANT, 'mode': MODE,
            'results': results}


try:
    out = run()
except Exception as e:
    out = {'project': 'langmem', 'runtime': False, 'variant': VARIANT, 'mode': MODE,
           'error': f'{type(e).__name__}: {e}', 'results': []}

print('__RESULT__ ' + json.dumps(out))
