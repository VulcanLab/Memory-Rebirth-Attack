"""Record exactly which versions the measurements ran against.

A reported rate is only checkable later if the thing it was measured on can be
identified. This resolves, from the machine rather than from memory:

  memory systems   the installed distribution version of each client library, taken
                   from the same isolated environment the probe for that system runs
                   in, plus the container image tag for the services that have one
  models           the id each model reports back in its own response, which is what
                   the serving layer actually routed to, alongside the id we asked for
  environment      Python, the embedding model, and the resolver lock hash

Everything is resolved live. Nothing here is written down by hand, because a version
table that is maintained by hand is the first thing to go stale.

Run: uv run python tools/pin_versions.py            # table to stdout
     uv run python tools/pin_versions.py --json     # machine-readable
"""

from __future__ import annotations

import hashlib
import json
import platform
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'core'))

from mwe_common import _env                                         # noqa: E402
from endpoints import decision_endpoint, decision_models            # noqa: E402

ROOT = Path(__file__).resolve().parent.parent

# Each memory system, the distribution to ask about, and the isolated environment the
# probe for it runs in. The version has to come from that environment: asking the
# project environment would report a different resolution, or nothing at all.
SYSTEMS = {
    'graphiti': ('graphiti-core', ['uv', 'run']),
    'mem0': ('mem0ai', ['uv', 'run', '--with', 'mem0ai', '--with', 'qdrant-client',
                        '--with', 'ollama']),
    'langmem': ('langmem', ['uv', 'run', '--with', 'langmem',
                            '--with', 'langchain-openai']),
    'cognee': ('cognee', ['uv', 'run', '--with', 'cognee']),
}

# Supporting distributions worth pinning: they decide how text is embedded and stored,
# so a change in them changes retrieval even with every client version held.
ALSO = {
    'graphiti': ['neo4j', 'openai'],
    'mem0': ['qdrant-client'],
    'langmem': ['langchain-core', 'langgraph'],
    'cognee': ['lancedb'],
}

# The distribution names arrive as arguments rather than being formatted into the
# source: a probe that builds its own code by string substitution is one stray brace
# away from not running at all.
PROBE = (
    'import json,sys,importlib.metadata as md\n'
    'out={}\n'
    'for d in sys.argv[1:]:\n'
    '    try: out[d]=md.version(d)\n'
    '    except Exception as e: out[d]="unresolved: "+type(e).__name__\n'
    'print("__V__"+json.dumps(out))\n'
)


def dist_versions(argv: list[str], dists: list[str]) -> dict[str, str]:
    try:
        p = subprocess.run(argv + ['python', '-c', PROBE, *dists],
                           cwd=ROOT, capture_output=True, text=True, timeout=900)
    except subprocess.TimeoutExpired:
        return {d: 'timeout' for d in dists}
    for line in reversed(p.stdout.splitlines()):
        if line.startswith('__V__'):
            return json.loads(line[5:])
    return {d: f'unresolved: {(p.stderr or p.stdout)[-120:]}' for d in dists}


def container_images() -> dict[str, str]:
    """Image tags for the services that run as containers."""
    out: dict[str, str] = {}
    try:
        p = subprocess.run(['docker', 'ps', '--format', '{{.Names}}\t{{.Image}}'],
                           capture_output=True, text=True, timeout=30)
        for line in p.stdout.splitlines():
            if '\t' in line:
                name, image = line.split('\t', 1)
                out[name] = image
    except Exception as e:                                          # noqa: BLE001
        out['_error'] = f'{type(e).__name__}: {e}'

    # Zep runs from a compose file, so its pin is in the file whether or not the
    # container happens to be up right now.
    compose = ROOT / 'config' / 'zep_ce.compose.yaml'
    if compose.exists():
        for m in re.finditer(r'image:\s*([^\s#]+)', compose.read_text()):
            out.setdefault(f'compose:{m.group(1).split("/")[-1]}', m.group(1))
    return out


def model_identities() -> list[dict]:
    """What each model reports when asked, next to what we asked for.

    A gateway maps a requested id onto whatever it is currently routing to, so the id
    in the config is a request and the id in the response is the answer.
    """
    from openai import OpenAI                                       # noqa: PLC0415
    base, key = decision_endpoint()
    cl = OpenAI(base_url=base, api_key=key, timeout=90.0, max_retries=1)
    rows = []
    for m in decision_models():
        row = {'requested': m}
        try:
            r = cl.chat.completions.create(
                model=m, max_tokens=16,
                messages=[{'role': 'user', 'content': 'Reply with the single word: ok'}])
            row['served'] = getattr(r, 'model', None)
            row['system_fingerprint'] = getattr(r, 'system_fingerprint', None)
            row['created'] = getattr(r, 'created', None)
            row['reachable'] = True
        except Exception as e:                                      # noqa: BLE001
            row['reachable'] = False
            row['error'] = f'{type(e).__name__}: {str(e)[:160]}'
        rows.append(row)
    return rows


def lock_digest() -> dict:
    out = {}
    for name in ('uv.lock', 'pyproject.toml'):
        f = ROOT / name
        if f.exists():
            out[name] = {'sha256': hashlib.sha256(f.read_bytes()).hexdigest()[:16],
                         'bytes': f.stat().st_size}
    return out


def collect(with_models: bool = True) -> dict:
    systems = {}
    for name, (dist, argv) in SYSTEMS.items():
        wanted = [dist] + ALSO.get(name, [])
        print(f'[versions] resolving {name} ...', file=sys.stderr, flush=True)
        systems[name] = dist_versions(argv, wanted)

    return {
        'resolved_at': datetime.now(timezone.utc).isoformat(timespec='seconds'),
        'python': platform.python_version(),
        'platform': f'{platform.system()} {platform.release()} {platform.machine()}',
        'memory_systems': systems,
        'containers': container_images(),
        'embedding': {'provider': _env('EMBED_PROVIDER', ''),
                      'model': _env('OLLAMA_EMBED_MODEL', ''),
                      'dim': _env('OLLAMA_EMBED_DIM', '')},
        'decision_endpoint': decision_endpoint()[0],
        'models': model_identities() if with_models else [],
        'lock': lock_digest(),
    }


def as_markdown(v: dict) -> str:
    out = [f"Resolved {v['resolved_at']} on {v['platform']}, Python {v['python']}.", '']
    out += ['### Memory systems', '',
            '| system | client | version | supporting |', '|---|---|---|---|']
    for name, dists in v['memory_systems'].items():
        client = SYSTEMS[name][0]
        extra = ', '.join(f'{k} {val}' for k, val in dists.items() if k != client)
        out.append(f"| {name} | {client} | {dists.get(client, '?')} | {extra or '-'} |")

    out += ['', '### Services', '', '| service | image |', '|---|---|']
    for k, val in sorted(v['containers'].items()):
        if not k.startswith('_'):
            out.append(f'| {k} | {val} |')

    out += ['', '### Decision models', '',
            '| requested | served | fingerprint |', '|---|---|---|']
    for m in v['models']:
        out.append(f"| {m['requested']} | {m.get('served') or '-'} | "
                   f"{m.get('system_fingerprint') or '-'} |")

    e = v['embedding']
    out += ['', '### Embedding and resolver', '',
            f"Embeddings: {e['provider']} {e['model']} at {e['dim']} dimensions.", '']
    for k, d in v['lock'].items():
        out.append(f"`{k}` sha256 `{d['sha256']}` ({d['bytes']} bytes)")
    return '\n'.join(out)


def main() -> None:
    v = collect(with_models='--no-models' not in sys.argv)
    if '--json' in sys.argv:
        print(json.dumps(v, indent=2))
    else:
        print(as_markdown(v))


if __name__ == '__main__':
    main()
