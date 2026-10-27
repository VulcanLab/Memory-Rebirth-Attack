"""Probe an OpenAI-compatible endpoint for models that are ACTUALLY usable.

Why this is a required first step
---------------------------------
A model listed by an endpoint is not necessarily a model you can run an experiment on.
A listed route may be unroutable upstream, retired, out of quota, or unable to produce
the output shape the experiment consumes. Selecting evaluation models from a raw
model-list is how you end up with silently empty cells halfway through a long run.

So every candidate is tested on exactly the two capabilities this study depends on:

  T1  chat  : a minimal completion. Does the model answer at all?
  T2  json  : a completion under `response_format={"type":"json_object"}`.
              The memory systems' extraction clients parse their reply with
              `json.loads`; a model that wraps JSON in a markdown fence, or that
              spends its whole budget on hidden reasoning tokens and returns an
              empty message, breaks extraction outright.

Latency varies by two orders of magnitude across routes (a small hosted model answers
in under a second; a large local or self-hosted model can take minutes). The probe
therefore uses a generous per-model deadline, retries once without a token cap for
models that return empty, and records the observed latency so slow-but-working models
can be kept with an appropriate timeout rather than being mistaken for dead ones.

Configuration comes entirely from the environment; no endpoint, key, or model-name
prefix is hardcoded. Point it at any OpenAI-compatible gateway:

    PROBE_BASE=<endpoint>/v1  PROBE_KEY=<key>  uv run python tools/probe_models.py

If PROBE_BASE / PROBE_KEY are unset it falls back to the configured decision endpoint
(DECISION_BASE / DECISION_KEY), then to the generic OpenAI-compatible one.

Outputs
    results/model_probe.json  full per-model record (endpoint host is not recorded)
    docs/MODELS.md            human-readable catalogue of what works
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from dotenv import load_dotenv
from openai import OpenAI

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / '.env')
sys.path.insert(0, str(ROOT / 'core'))
from sanitize import public_text  # noqa: E402


def _env(*names: str, default: str = '') -> str:
    for n in names:
        v = os.getenv(n)
        if v:
            return v
    return default


BASE = _env('PROBE_BASE', 'DECISION_BASE', 'OPENAI_BASE').rstrip('/')
KEY = _env('PROBE_KEY', 'DECISION_KEY', 'OPENAI_API_KEY', default='x')
if BASE and not BASE.endswith('/v1'):
    BASE += '/v1'

CHAT_PROMPT = 'Reply with exactly: ok'
JSON_PROMPT = 'Return JSON only: {"status":"ok"}'

# Routes we deliberately do not evaluate, with the reason recorded in the output so the
# exclusion is auditable rather than silent. Set EXCLUDE_MODELS in .env (comma-separated
# substrings); nothing is hardcoded to a particular vendor in the logic below.
EXCLUDE = [e.strip() for e in (os.getenv('EXCLUDE_MODELS', '') or '').split(',') if e.strip()]


def _call(client: OpenAI, model: str, prompt: str, json_mode: bool, timeout: float):
    """One tiny completion -> (ok, text, error, seconds).

    Retries once without `max_tokens` because reasoning models can consume the whole
    cap on hidden tokens and return an empty message; that is a usable model with an
    unusable token budget, not a dead route.
    """
    kwargs = dict(model=model, messages=[{'role': 'user', 'content': prompt}],
                  timeout=timeout)
    if json_mode:
        kwargs['response_format'] = {'type': 'json_object'}
    t0 = time.time()
    for attempt in (0, 1):
        try:
            k = dict(kwargs)
            if attempt == 0:
                k['max_tokens'] = 64
            r = client.chat.completions.create(**k)
            txt = (r.choices[0].message.content or '').strip()
            if not txt:
                if attempt == 0:
                    continue
                return False, '', 'empty_response', round(time.time() - t0, 2)
            return True, txt[:200], None, round(time.time() - t0, 2)
        except Exception as e:  # noqa: BLE001 (the upstream message is the diagnosis)
            err = f'{type(e).__name__}: {e}'
            if attempt == 0 and 'max_tokens' in err:
                continue
            return False, '', err[:300], round(time.time() - t0, 2)
    return False, '', 'unreachable', round(time.time() - t0, 2)


def classify(chat_err: str | None, json_err: str | None) -> str:
    """Group failures so the catalogue explains *why* a route is unusable."""
    e = (chat_err or json_err or '').lower()
    if not e:
        return 'usable'
    for needle, label in [
        ('credit balance', 'no quota on this account'),
        ('insufficient credit', 'no quota on this account'),
        ('suspended', 'no quota on this account'),
        ('end of life', 'retired upstream'),
        ('410', 'retired upstream'),
        ('404', 'route not served'),
        ('does not exist', 'route not served'),
        ('not found', 'route not served'),
        ('invalid model', 'route not served'),
        ('timed out', 'timeout'),
        ('timeout', 'timeout'),
        ('cannot connect', 'backend unreachable'),
        ('429', 'rate limited'),
        ('not_valid_json', 'answers, but cannot emit strict JSON'),
        ('empty_response', 'answers empty (reasoning budget)'),
    ]:
        if needle in e:
            return label
    return 'other error'


def probe(model: str, timeout: float, verbose: bool) -> dict:
    client = OpenAI(base_url=BASE, api_key=KEY)
    chat_ok, chat_txt, chat_err, t_chat = _call(client, model, CHAT_PROMPT, False, timeout)

    json_ok, json_txt, json_err, t_json = False, '', 'not attempted (chat failed)', None
    if chat_ok:
        json_ok, json_txt, json_err, t_json = _call(client, model, JSON_PROMPT, True, timeout)
        if json_ok:
            try:
                json.loads(json_txt)
            except Exception:
                json_ok, json_err = False, 'not_valid_json'

    usable = chat_ok and json_ok
    reason = classify(chat_err, json_err)
    if verbose:
        state = 'OK  ' if usable else ('CHAT' if chat_ok else 'DEAD')
        print(f'{state}  {model:56s} chat={t_chat}s json={t_json}s  '
              f'{"" if usable else reason}', flush=True)
    return {'model': model, 'usable': usable, 'reason': reason,
            'chat_ok': chat_ok, 'chat_latency_s': t_chat, 'chat_sample': chat_txt,
            'json_ok': json_ok, 'json_latency_s': t_json, 'json_sample': json_txt,
            'error': chat_err or json_err,
            'latency_s': round((t_chat or 0) + (t_json or 0), 2)}


def write_catalogue(rows: list[dict]) -> str:
    usable = [r for r in rows if r['usable']]
    chat_only = [r for r in rows if r['chat_ok'] and not r['json_ok']]
    dead = [r for r in rows if not r['chat_ok']]

    lat = [r['latency_s'] for r in usable if r['latency_s']]
    med = statistics.median(lat) if lat else 0

    out = [
        '# Model catalogue: what the configured endpoint can actually run',
        '',
        '_Generated by `tools/probe_models.py`. Do not edit by hand._',
        '',
        'A model appearing in an endpoint\'s model list is not evidence that it works.',
        'Each route below was sent two real requests: a minimal completion, and a',
        'completion constrained to strict JSON (the shape the memory systems\' extraction',
        'clients parse with `json.loads`). A route counts as **usable** only if both',
        'succeed.',
        '',
        f'| total routes | usable | answer but no strict JSON | unreachable |',
        f'|---|---|---|---|',
        f'| {len(rows)} | **{len(usable)}** | {len(chat_only)} | {len(dead)} |',
        '',
        f'Median round-trip for a usable route: **{med:.1f}s** for both probe calls.',
        '',
        '## Usable',
        '',
        '| model | chat | strict JSON |',
        '|---|---|---|',
    ]
    for r in sorted(usable, key=lambda r: r['latency_s']):
        out.append(f"| `{r['model']}` | {r['chat_latency_s']}s | {r['json_latency_s']}s |")

    if chat_only:
        out += ['', '## Answers, but cannot emit strict JSON', '',
                'Usable as a *decision* model (the action parser tolerates prose) but NOT',
                'as an *extraction* model, because the memory systems require parseable',
                'JSON to build their graph.', '',
                '| model | what it returned |', '|---|---|']
        for r in chat_only:
            sample = (r['json_sample'] or '').replace('\n', ' ')[:60]
            out.append(f"| `{r['model']}` | `{sample}` |")

    if dead:
        out += ['', '## Unreachable', '', '| model | reason |', '|---|---|']
        for r in sorted(dead, key=lambda r: r['reason']):
            out.append(f"| `{r['model']}` | {r['reason']} |")

    out += ['', '## How to use this file', '',
            'Put chosen model ids in `.env`:', '',
            '```ini',
            '# extraction model used by the memory systems under test',
            'LLM_MODEL=<one usable id>',
            '# comma-separated evaluation models; every one is run on every cell',
            'DECISION_MODELS=<id>,<id>,<id>',
            '```', '',
            'Model ids are endpoint-specific strings. Nothing in the codebase assumes any',
            'particular naming scheme or prefix; whatever this catalogue lists is what',
            'the code will send.', '']
    return '\n'.join(out) + '\n'


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument('--workers', type=int, default=8,
                    help='parallel probes; lower it if the endpoint rate-limits')
    ap.add_argument('--timeout', type=float, default=180.0,
                    help='per-request deadline; large or self-hosted models are slow')
    ap.add_argument('--only', default='', help='comma-separated substring filter')
    ap.add_argument('--quiet', action='store_true')
    args = ap.parse_args()

    if not BASE:
        sys.exit('No endpoint configured. Set PROBE_BASE (or DECISION_BASE) in .env')

    client = OpenAI(base_url=BASE, api_key=KEY)
    models = sorted(m.id for m in client.models.list().data)
    if args.only:
        pats = [p.strip() for p in args.only.split(',') if p.strip()]
        models = [m for m in models if any(p in m for p in pats)]

    skipped = [m for m in models if any(x in m for x in EXCLUDE)]
    models = [m for m in models if m not in skipped]
    if not args.quiet:
        print(f'probing {len(models)} routes (excluded {len(skipped)} by EXCLUDE_MODELS), '
              f'workers={args.workers}, per-request timeout={args.timeout}s\n')

    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        rows = list(ex.map(lambda m: probe(m, args.timeout, not args.quiet), models))

    for m in skipped:
        rows.append({'model': m, 'usable': False, 'reason': 'excluded by EXCLUDE_MODELS',
                     'chat_ok': False, 'json_ok': False, 'latency_s': 0,
                     'chat_latency_s': None, 'json_latency_s': None,
                     'chat_sample': '', 'json_sample': '', 'error': None})

    out_dir = Path(os.getenv('RESULTS_DIR') or (ROOT.parent / 'private' / 'results'))
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / 'model_probe.json').write_text(json.dumps({
        # The endpoint host is deliberately not recorded: it is deployment detail, and
        # these artifacts are committed.
        'probed_at': time.strftime('%Y-%m-%dT%H:%M:%S%z'),
        'per_request_timeout_s': args.timeout,
        'counts': {'total': len(rows),
                   'usable': sum(r['usable'] for r in rows),
                   'chat_only': sum(r['chat_ok'] and not r['json_ok'] for r in rows),
                   'dead': sum(not r['chat_ok'] for r in rows)},
        'usable_models': [r['model'] for r in rows if r['usable']],
        'results': rows,
    }, indent=2))

    # The catalogue IS published, so strip the deployment's private routing namespace
    # from every id before writing it. The model family stays: a reader cannot evaluate
    # a cross-model claim without it.
    (ROOT / 'docs').mkdir(exist_ok=True)
    (ROOT / 'docs' / 'MODELS.md').write_text(public_text(write_catalogue(rows)))

    print(f"\nusable={sum(r['usable'] for r in rows)}/{len(rows)}  "
          f"-> {out_dir}/model_probe.json (raw, not published), docs/MODELS.md (published)")


if __name__ == '__main__':
    main()
