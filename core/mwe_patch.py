"""Non-invasive runtime patches for the MWE harness.

IMPORTANT: this does NOT modify Graphiti's source. `graphiti_core` on disk is the
pristine upstream code. Importing this module applies two cross-cutting, research-
only behaviors at runtime by monkeypatching client methods / the Gemini SDK:

  1. Call throttle  : a random pre-call delay before every LLM / embedder /
     reranker request (longer for local models). Pure timing; touches no logic.
  2. Gemini safety off: inject BLOCK_NONE on all four adjustable Gemini safety
     categories, which the Gemini API natively supports as a per-request option.

Neither touches the retrieval / versioning / soft-delete code that the Memory
Rebirth Attack exercises; the attack runs on 100% original Graphiti behavior.
Both are env-driven and read at call time:

    CALL_DELAY_ENABLED (default true), CLOUD_DELAY_MIN/MAX, LOCAL_DELAY_MIN/MAX
    GEMINI_DISABLE_SAFETY (default true)

Idempotent: importing more than once patches only once.
"""

from __future__ import annotations

import asyncio
import functools
import os
import random

_APPLIED = False


def _truthy(v: str | None) -> bool:
    return (v or '').lower() in ('1', 'true', 'yes')


def _base_url_is_local(base_url) -> bool:
    if not base_url:
        return False
    return any(t in str(base_url) for t in ('localhost', '127.0.0.1', '11434', '0.0.0.0'))


async def _precall_delay(is_local: bool) -> None:
    if not _truthy(os.getenv('CALL_DELAY_ENABLED', 'true')):
        return
    if is_local:
        lo = float(os.getenv('LOCAL_DELAY_MIN', '2.0'))
        hi = float(os.getenv('LOCAL_DELAY_MAX', '6.0'))
    else:
        lo = float(os.getenv('CLOUD_DELAY_MIN', '0.5'))
        hi = float(os.getenv('CLOUD_DELAY_MAX', '2.5'))
    if hi > 0:
        await asyncio.sleep(random.uniform(max(0.0, lo), hi))


def _wrap_method(cls, method_name: str, local_hint):
    """Wrap an async method so it sleeps a jittered delay before running.

    local_hint: True/False, or a callable(self)->bool to detect local endpoints.
    """
    orig = getattr(cls, method_name, None)
    if orig is None or getattr(orig, '_mwe_wrapped', False):
        return

    @functools.wraps(orig)
    async def wrapper(self, *args, **kwargs):
        is_local = local_hint(self) if callable(local_hint) else bool(local_hint)
        await _precall_delay(is_local)
        return await orig(self, *args, **kwargs)

    wrapper._mwe_wrapped = True
    setattr(cls, method_name, wrapper)


def _detect_local(self) -> bool:
    return _base_url_is_local(getattr(getattr(self, 'config', None), 'base_url', None))


def _apply_throttle():
    # OpenAI-compatible embedder (Ollama / OpenRouter / LiteLLM / OpenAI)
    try:
        from graphiti_core.embedder.openai import OpenAIEmbedder
        _wrap_method(OpenAIEmbedder, 'create', _detect_local)
        _wrap_method(OpenAIEmbedder, 'create_batch', _detect_local)
    except Exception:
        pass
    # OpenAI-compatible LLM
    try:
        from graphiti_core.llm_client.openai_generic_client import OpenAIGenericClient
        _wrap_method(OpenAIGenericClient, 'generate_response', _detect_local)
    except Exception:
        pass
    # OpenAI reranker
    try:
        from graphiti_core.cross_encoder.openai_reranker_client import OpenAIRerankerClient
        _wrap_method(OpenAIRerankerClient, 'rank', _detect_local)
    except Exception:
        pass
    # Gemini (always remote)
    try:
        from graphiti_core.llm_client.gemini_client import GeminiClient
        _wrap_method(GeminiClient, 'generate_response', False)
    except Exception:
        pass
    try:
        from graphiti_core.embedder.gemini import GeminiEmbedder
        _wrap_method(GeminiEmbedder, 'create', False)
        _wrap_method(GeminiEmbedder, 'create_batch', False)
    except Exception:
        pass
    try:
        from graphiti_core.cross_encoder.gemini_reranker_client import GeminiRerankerClient
        _wrap_method(GeminiRerankerClient, 'rank', False)
    except Exception:
        pass


def _apply_gemini_safety():
    """Default-inject BLOCK_NONE safety_settings into every GenerateContentConfig.

    Patches the google-genai SDK type (a dependency), not Graphiti. The Gemini API
    natively supports per-request safety_settings; this only sets them.
    """
    try:
        from google.genai import types as gtypes
    except Exception:
        return
    orig = getattr(gtypes, 'GenerateContentConfig', None)
    if orig is None or getattr(orig, '_mwe_safety_wrapped', False):
        return

    def factory(*args, **kwargs):
        if _truthy(os.getenv('GEMINI_DISABLE_SAFETY', 'true')) and not kwargs.get('safety_settings'):
            kwargs['safety_settings'] = [
                gtypes.SafetySetting(category=c, threshold=gtypes.HarmBlockThreshold.BLOCK_NONE)
                for c in (
                    gtypes.HarmCategory.HARM_CATEGORY_HARASSMENT,
                    gtypes.HarmCategory.HARM_CATEGORY_HATE_SPEECH,
                    gtypes.HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT,
                    gtypes.HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT,
                )
            ]
        return orig(*args, **kwargs)

    factory._mwe_safety_wrapped = True
    gtypes.GenerateContentConfig = factory


def apply():
    global _APPLIED
    if _APPLIED:
        return
    _apply_throttle()
    _apply_gemini_safety()
    _APPLIED = True


apply()
