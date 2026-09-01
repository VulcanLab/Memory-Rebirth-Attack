"""Resolve the configured LLM / embedding endpoints into provider-neutral values.

Everything about *which* provider, *which* endpoint and *which* model is configuration.
Nothing here, and nothing in `adapters/`, contains a provider name, a hostname, or a
model-id prefix. Swapping providers is a `.env` edit.

Two layers:

1. `.env` holds one block per provider (`OLLAMA_*`, `OPENAI_*`, `LITELLM_*`, ...), and
   `LLM_PROVIDER` / `EMBED_PROVIDER` select which block is live. Providers can be mixed
   (e.g. a hosted LLM with a local embedder) because the two selectors are separate.

2. The selected block is resolved once, here, into neutral names:

       MWE_LLM_BASE / MWE_LLM_KEY / MWE_LLM_MODEL / MWE_LLM_MAX_TOKENS
       MWE_EMBED_BASE / MWE_EMBED_KEY / MWE_EMBED_MODEL / MWE_EMBED_DIM

   The per-system retrieval probes read ONLY those. They run as subprocesses in their
   own dependency environments, so `export_env()` hands the resolved values down. A new
   provider therefore needs a new `.env` block and nothing else; no probe changes.

Model ids are opaque strings passed through verbatim. Endpoints name their routes in
whatever scheme they like, so the code must never pattern-match, prefix, or rewrite an
id, and must never ship a default one, since a default from one endpoint is a
guaranteed 404 on another.
"""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

# Load .env here rather than relying on the caller: this module is imported directly by
# tools that do not go through the main harness, and a silently-unloaded .env resolves
# to whatever the defaults happen to be, which fails much later and confusingly.
load_dotenv(Path(__file__).resolve().parent.parent / '.env')

# provider key -> (env prefix, default base url, default api key)
# The defaults are only sensible fallbacks for locally-hosted services; hosted
# providers have no default and must be configured.
PROVIDERS = {
    'ollama': ('OLLAMA', 'http://localhost:11434/v1', 'ollama'),
    'openai': ('OPENAI', 'https://api.openai.com/v1', ''),
    'openrouter': ('OPENROUTER', 'https://openrouter.ai/api/v1', ''),
    'litellm': ('LITELLM', 'http://localhost:4000/v1', ''),
    # Reached over its OpenAI-compatible surface, so it needs no separate code path;
    # it is listed here only so the endpoint and credential come from a named block
    # rather than from whichever gateway happens to front it.
    'anthropic': ('ANTHROPIC', 'https://api.anthropic.com/v1', ''),
    'custom': ('CUSTOM', '', ''),
}
# Providers reached through a native SDK rather than an OpenAI-compatible HTTP surface.
NATIVE = {'gemini': 'GEMINI'}


class ConfigError(RuntimeError):
    pass


def _env(key: str, default: str | None = None) -> str | None:
    v = os.getenv(key)
    return v if v not in ('', None) else default


def _provider(role: str) -> str:
    key = 'LLM_PROVIDER' if role == 'LLM' else 'EMBED_PROVIDER'
    p = (_env(key, 'ollama') or 'ollama').lower()
    if p not in PROVIDERS and p not in NATIVE:
        raise ConfigError(
            f'{key}={p!r} is not a known provider. '
            f'Known: {", ".join(sorted(set(PROVIDERS) | set(NATIVE)))}. '
            f'Add a new one by adding a {p.upper()}_* block to .env and listing it here.')
    return p


def resolve(role: str) -> dict:
    """role is 'LLM' or 'EMBED'. Returns neutral endpoint settings."""
    provider = _provider(role)
    if provider in NATIVE:
        prefix = NATIVE[provider]
        return {'provider': provider, 'native': True, 'prefix': prefix,
                'base': None, 'key': _env(f'{prefix}_API_KEY'),
                'model': _env(f'{prefix}_{role}_MODEL'),
                'dim': int(_env(f'{prefix}_EMBED_DIM', '768')),
                'max_tokens': None}

    prefix, base_default, key_default = PROVIDERS[provider]
    base = _env(f'{prefix}_BASE', base_default)
    key = _env(f'{prefix}_API_KEY', key_default)
    model = _env(f'{prefix}_{role}_MODEL')
    mt = _env(f'{prefix}_MAX_TOKENS')

    if not base:
        raise ConfigError(f'{prefix}_BASE is not set but {role}_PROVIDER={provider}.')
    if not model:
        # A wrong model id fails deep inside a library with an opaque error, often only
        # after minutes of setup. Fail here instead, naming the exact variable.
        raise ConfigError(
            f'{prefix}_{role}_MODEL is not set. Model ids are endpoint-specific and have '
            f'no safe default; run `uv run python tools/probe_models.py` and copy a '
            f'verified id from docs/MODELS.md.')

    return {'provider': provider, 'native': False, 'prefix': prefix,
            'base': base.rstrip('/'), 'key': key, 'model': model,
            'dim': int(_env(f'{prefix}_EMBED_DIM', '768')),
            'max_tokens': int(mt) if mt else None}


def export_env() -> dict[str, str]:
    """Neutral variables to hand to a subprocess probe. Never provider-specific."""
    llm, emb = resolve('LLM'), resolve('EMBED')
    out = {
        'MWE_LLM_BASE': llm['base'] or '',
        'MWE_LLM_KEY': llm['key'] or '',
        'MWE_LLM_MODEL': llm['model'] or '',
        'MWE_EMBED_BASE': emb['base'] or '',
        'MWE_EMBED_KEY': emb['key'] or '',
        'MWE_EMBED_MODEL': emb['model'] or '',
        'MWE_EMBED_DIM': str(emb['dim']),
    }
    if llm['max_tokens']:
        out['MWE_LLM_MAX_TOKENS'] = str(llm['max_tokens'])
    return out


def decision_endpoint() -> tuple[str, str]:
    """Endpoint for the evaluation (decision) models.

    Defaults to the LLM endpoint so a single-endpoint setup needs no extra config, but
    can be pointed elsewhere with DECISION_BASE / DECISION_KEY when the models under
    evaluation live somewhere other than the extraction model.
    """
    base = _env('DECISION_BASE')
    key = _env('DECISION_KEY')
    if base:
        return base.rstrip('/'), (key or 'x')
    llm = resolve('LLM')
    if llm['native']:
        raise ConfigError(
            'DECISION_BASE must be set when LLM_PROVIDER uses a native SDK: the '
            'evaluation harness speaks the OpenAI-compatible protocol only.')
    return llm['base'], (llm['key'] or 'x')


def decision_models() -> list[str]:
    models = [m.strip() for m in (_env('DECISION_MODELS', '') or '').split(',') if m.strip()]
    if not models:
        raise ConfigError(
            'DECISION_MODELS is empty. Set it to a comma-separated list of model ids '
            'verified by tools/probe_models.py (see docs/MODELS.md).')
    return models
