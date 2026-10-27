"""Shared config/factory for the Memory Rebirth Attack MWE.

ALL secrets, endpoints, and model names come from .env (never hardcoded).
Cross-platform: pure Python + pathlib, no OS-specific paths.

Providers are switchable per role via LLM_PROVIDER / EMBED_PROVIDER. Everything
except Gemini is OpenAI-compatible and shares one code path; only the env block
differs, so adding a new endpoint is just new .env values:

    ollama      local Ollama            (OLLAMA_*)
    gemini      Google Gemini           (GEMINI_*)          [native SDK]
    openrouter  OpenRouter / OpenCode   (OPENROUTER_*)      [OpenAI-compatible]
    litellm     LiteLLM proxy           (LITELLM_*)         [OpenAI-compatible]
    openai      OpenAI or any compatible endpoint (OPENAI_*)[OpenAI-compatible]

Mixing is allowed, e.g. LLM_PROVIDER=openrouter + EMBED_PROVIDER=ollama.
(OpenRouter has no embeddings endpoint; use it for LLM, embed via ollama/gemini/openai.)

Importing this module also applies the non-invasive runtime harness patches
(Gemini safety-off + call throttle) via mwe_patch; Graphiti source stays pristine.
"""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

# Load .env from the project root (parent of core/). Cross-platform.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / '.env')
# Where run artifacts are written. Default is OUTSIDE the published tree: raw output
# records model ids, endpoint behaviour and full retrieved contexts, none of which is
# published. Override with RESULTS_DIR in .env.
_rd = os.getenv('RESULTS_DIR')
# A relative RESULTS_DIR must be anchored to the project, not to the process's working
# directory: a caller that chdirs would otherwise silently relocate research data,
# including into the published tree, which is exactly what the setting exists to prevent.
RESULTS_DIR = ((PROJECT_ROOT / _rd).resolve() if _rd and not os.path.isabs(_rd)
               else Path(_rd) if _rd
               else PROJECT_ROOT.parent / 'private' / 'results')
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

# Apply non-invasive runtime patches (safety-off + throttle). Must be after
# load_dotenv so env-driven behavior sees the configured values.
import mwe_patch  # noqa: E402,F401

from graphiti_core import Graphiti  # noqa: E402
from graphiti_core.embedder.openai import OpenAIEmbedder, OpenAIEmbedderConfig  # noqa: E402
from graphiti_core.llm_client.config import LLMConfig  # noqa: E402
from graphiti_core.llm_client.openai_generic_client import OpenAIGenericClient  # noqa: E402
from graphiti_core.cross_encoder.openai_reranker_client import OpenAIRerankerClient  # noqa: E402


def _env(key: str, default: str | None = None) -> str | None:
    v = os.getenv(key, default)
    return v if v not in ('', None) else default


# ---- Neo4j ----
NEO4J_URI = _env('NEO4J_URI', 'bolt://localhost:7688')
NEO4J_USER = _env('NEO4J_USER', 'neo4j')
NEO4J_PASSWORD = _env('NEO4J_PASSWORD', 'mwepassword123')
GROUP_ID = _env('MWE_GROUP_ID', 'mwe_rebirth')

LLM_PROVIDER = (_env('LLM_PROVIDER', 'ollama') or 'ollama').lower()
EMBED_PROVIDER = (_env('EMBED_PROVIDER', 'ollama') or 'ollama').lower()

# Per-provider env prefixes for OpenAI-compatible endpoints.
# (base_default, key_default)
_OPENAI_COMPAT = {
    'ollama': ('OLLAMA', 'http://localhost:11434/v1', 'ollama'),
    'openrouter': ('OPENROUTER', 'https://openrouter.ai/api/v1', 'openrouter'),
    'litellm': ('LITELLM', 'http://localhost:4000/v1', 'litellm'),
    'openai': ('OPENAI', 'https://api.openai.com/v1', 'openai'),
}


def _compat_cfg(provider: str, role: str):
    """Return (base_url, api_key, model, dim, max_tokens) for an OpenAI-compatible
    provider. role is 'LLM' or 'EMBED'. max_tokens=None means use client default;
    set {PREFIX}_MAX_TOKENS to cap it (needed for credit-limited endpoints)."""
    prefix, base_default, key_default = _OPENAI_COMPAT[provider]
    base = _env(f'{prefix}_BASE', base_default)
    key = _env(f'{prefix}_API_KEY', key_default)
    model = _env(f'{prefix}_{role}_MODEL')
    dim = int(_env(f'{prefix}_EMBED_DIM', '768'))
    mt = _env(f'{prefix}_MAX_TOKENS')
    return base, key, model, dim, (int(mt) if mt else None)


# ------------------------------------------------------------------ embedders
def build_embedder():
    if EMBED_PROVIDER == 'gemini':
        from graphiti_core.embedder.gemini import GeminiEmbedder, GeminiEmbedderConfig
        return GeminiEmbedder(
            config=GeminiEmbedderConfig(
                api_key=_env('GEMINI_API_KEY'),
                embedding_model=_env('GEMINI_EMBED_MODEL', 'embedding-001'),
                embedding_dim=int(_env('GEMINI_EMBED_DIM', '768')),
            )
        )
    base, key, model, dim, _ = _compat_cfg(EMBED_PROVIDER, 'EMBED')
    return OpenAIEmbedder(
        config=OpenAIEmbedderConfig(
            api_key=key, base_url=base, embedding_model=model, embedding_dim=dim
        )
    )


# ------------------------------------------------------------------ llm + reranker
def build_llm_and_reranker():
    if LLM_PROVIDER == 'gemini':
        from graphiti_core.llm_client.gemini_client import GeminiClient
        from graphiti_core.cross_encoder.gemini_reranker_client import GeminiRerankerClient
        key = _env('GEMINI_API_KEY')
        model = _env('GEMINI_LLM_MODEL', 'gemini-flash-latest')
        llm = GeminiClient(config=LLMConfig(api_key=key, model=model, small_model=model))
        reranker = GeminiRerankerClient(config=LLMConfig(api_key=key, model=model))
        return llm, reranker

    base, key, model, _, max_tokens = _compat_cfg(LLM_PROVIDER, 'LLM')
    cfg = LLMConfig(api_key=key, base_url=base, model=model, small_model=model)
    # max_tokens caps the per-request output (credit-limited endpoints reject large
    # requests, e.g. OpenRouter 402). None -> client default (16384).
    llm = (
        OpenAIGenericClient(config=cfg, max_tokens=max_tokens)
        if max_tokens is not None
        else OpenAIGenericClient(config=cfg)
    )
    reranker = OpenAIRerankerClient(client=llm, config=cfg)
    return llm, reranker


def build_graphiti(with_llm: bool = True) -> Graphiti:
    embedder = build_embedder()
    llm, reranker = build_llm_and_reranker()
    return Graphiti(
        uri=NEO4J_URI,
        user=NEO4J_USER,
        password=NEO4J_PASSWORD,
        llm_client=llm,
        embedder=embedder,
        cross_encoder=reranker,
    )


def decision_client_for(model: str):
    """Return (OpenAI-compatible client, model_id) for a decision/agent LLM.

    Prefix a DECISION_MODELS entry with 'ollama:' to run it on the LOCAL Ollama
    endpoint (unlimited, no API quota); otherwise it goes through OpenRouter.
    Examples: 'ollama:qwen2.5:3b-instruct', 'nvidia/nemotron-3-super-120b-a12b:free'.
    """
    from openai import OpenAI
    if model.startswith('ollama:'):
        return (
            OpenAI(base_url=_env('OLLAMA_BASE', 'http://localhost:11434/v1'),
                   api_key=_env('OLLAMA_API_KEY', 'ollama')),
            model.split(':', 1)[1],
        )
    return (
        OpenAI(base_url=_env('OPENROUTER_BASE', 'https://openrouter.ai/api/v1'),
               api_key=_env('OPENROUTER_API_KEY')),
        model,
    )


def provider_banner() -> str:
    return f'LLM_PROVIDER={LLM_PROVIDER}  EMBED_PROVIDER={EMBED_PROVIDER}  group_id={GROUP_ID}'
