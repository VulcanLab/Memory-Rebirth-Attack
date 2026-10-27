"""Retrieval probe for cognee. See adapters/README.md for the stdin/stdout protocol.

Run (isolated env):
    uv run --with cognee python adapters/cognee_probe.py

cognee ingests documents, builds a knowledge graph (`cognify`), and retrieves chunks
or graph triplets. Its update path is delete-then-reingest: `delete()` physically
removes graph nodes and vector points, and `DataPoint` carries no revocation field.
Like langmem it is a **negative control**: there is no revoked row for a status-blind
retriever to resurface.

Retrieval uses SearchType.CHUNKS so we get raw stored text back rather than an
LLM-generated answer; that keeps this arm comparable with the other projects, which
also return stored facts and leave all generation to the shared decision stage.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile

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

# cognee is configured entirely through the environment; point it at the same
# gateway + local embedder every other arm uses.
# Force-set: the harness .env names its own provider for the system under test,
# which is not necessarily a provider name cognee understands.
os.environ['LLM_PROVIDER'] = 'openai'
os.environ['LLM_MODEL'] = f'openai/{MODEL}'
os.environ['LLM_ENDPOINT'] = BASE
os.environ['LLM_API_KEY'] = KEY
os.environ['EMBEDDING_PROVIDER'] = 'ollama'
os.environ['EMBEDDING_MODEL'] = EMBED_MODEL
os.environ['EMBEDDING_ENDPOINT'] = EMBED_BASE.replace('/v1', '') + '/api/embed'
os.environ['EMBEDDING_DIMENSIONS'] = str(EMBED_DIM)
os.environ['HUGGINGFACE_TOKENIZER'] = 'Salesforce/SFR-Embedding-Mistral'
os.environ.setdefault('DATA_ROOT_DIRECTORY', tempfile.mkdtemp(prefix='cognee_data_'))
os.environ.setdefault('SYSTEM_ROOT_DIRECTORY', tempfile.mkdtemp(prefix='cognee_sys_'))

from pathlib import Path  # noqa: E402

# All probes import the SAME episode text from core/situations.py. Natural-mode
# ingestion must be word-for-word identical across projects or a difference in
# retrieval could just be a difference in what was written.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'core'))
from situations import asserts_revoked, episodes_for  # noqa: E402

import cognee  # noqa: E402
from cognee.modules.search.types import SearchType  # noqa: E402


async def run() -> dict:
    results = []
    for s in SITUATIONS:
        await cognee.prune.prune_data()
        await cognee.prune.prune_system(metadata=True)

        if MODE == 'direct':
            # Direct arm = revoke v1 with cognee's OWN primitive. cognee has no soft
            # marker; the documented update path is delete-then-reingest, so the
            # revoked text is physically removed before retrieval.
            for txt in list(s.get('distractors', [])) + [s['v2']]:
                await cognee.add(txt)
            await cognee.cognify()
        else:
            # Natural arm: feed the contradicting memo then the update, and let
            # cognee reconcile them however it does.
            for text in episodes_for(s):
                await cognee.add(text)
            await cognee.cognify()

        hits = await cognee.search(query_type=SearchType.CHUNKS, query_text=s['query'])
        # cognee 1.4 wraps results per dataset: [{dataset_id, search_result: [chunk…]}].
        facts, records = [], []
        for h in hits:
            if isinstance(h, str):
                facts.append(h)
                records.append({'fact': h})
            elif isinstance(h, dict):
                for c in h.get('search_result', [h]):
                    if not isinstance(c, dict):
                        facts.append(str(c)); records.append({'fact': str(c)}); continue
                    text = c.get('text', '')
                    facts.append(text)
                    # cognee has no revocation field; timestamps are all it exposes.
                    rec = {'fact': text}
                    for k in ('created_at', 'updated_at'):
                        if c.get(k):
                            rec[k] = c[k]
                    records.append(rec)
        keep = [i for i, f in enumerate(facts) if f][:10]
        facts = [facts[i] for i in keep]
        records = [records[i] for i in keep]

        present = [i for i, f in enumerate(facts)
                   if asserts_revoked(f, s['v1'], s['v2'])]
        results.append({
            'situation': s['name'],
            'attack_facts': facts,
            'attack_records': records,
            'defense_facts': facts,   # nothing to filter: no revocation marker exists
            'r_asr': bool(present),
            'revoked_rank': (present[0] + 1) if present else None,
            'revocation_mechanism': 'hard_delete',
            'note': 'delete-then-reingest; defense arm == attack arm by design',
        })
    return {'project': 'cognee', 'runtime': True, 'variant': VARIANT, 'mode': MODE,
            'results': results}


try:
    out = asyncio.run(run())
except Exception as e:
    out = {'project': 'cognee', 'runtime': False, 'variant': VARIANT, 'mode': MODE,
           'error': f'{type(e).__name__}: {e}', 'results': []}

print('__RESULT__ ' + json.dumps(out))
