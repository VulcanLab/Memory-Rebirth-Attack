"""One-call check that the configured Anthropic block works, and reports why if not.

Separate from `probe_models.py` because that script catalogues a whole gateway; this
answers a single question: does this credential authenticate against this endpoint, and
does the model emit the strict JSON the decision parser needs, before anything expensive
is launched against it. Credential *type* is the usual failure here, so an auth error is
reported with the distinction spelled out rather than as a bare 401.

Run: uv run python tools/probe_anthropic.py
"""

from __future__ import annotations

import sys
from pathlib import Path

import httpx
from openai import OpenAI

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'core'))

from endpoints import resolve, _env, ConfigError                # noqa: E402


def main() -> int:
    base = _env('ANTHROPIC_BASE')
    key = _env('ANTHROPIC_API_KEY')
    model = _env('ANTHROPIC_LLM_MODEL')
    missing = [n for n, v in (('ANTHROPIC_BASE', base), ('ANTHROPIC_API_KEY', key),
                              ('ANTHROPIC_LLM_MODEL', model)) if not v]
    if missing:
        print(f'not configured: {", ".join(missing)} unset in .env')
        return 2

    kind = ('interactive OAuth token (sk-ant-oat01-)' if key.startswith('sk-ant-oat01-')
            else 'programmatic API key (sk-ant-api03-)' if key.startswith('sk-ant-api03-')
            else 'unrecognised credential form')
    print(f'endpoint {base}\nmodel    {model}\ncredential {kind}')

    client = OpenAI(base_url=base, api_key=key,
                    timeout=httpx.Timeout(60.0, connect=15.0), max_retries=0)
    try:
        r = client.chat.completions.create(
            model=model, max_tokens=64,
            messages=[{'role': 'user', 'content':
                       'Reply with strict JSON only: {"action": "OK", "reason": "probe"}'}])
    except Exception as e:                                       # noqa: BLE001
        msg = str(e)
        print(f'\nFAILED: {type(e).__name__}: {msg[:400]}')
        # Match on the status code, not on words in the body. An earlier version keyed on
        # the substring "invalid", which appears in a rate-limit body too, so a 429 was
        # reported as an authentication failure, the opposite conclusion, since a 429
        # means the credential was accepted.
        status = getattr(e, 'status_code', None) or getattr(
            getattr(e, 'response', None), 'status_code', None)
        if status in (401, 403):
            print('\nThe credential was rejected. An OAuth-form token belongs to an '
                  'interactive subscription client and is not accepted here; issue an API '
                  'key from the console and set ANTHROPIC_API_KEY to it.'
                  if key.startswith('sk-ant-oat01-') else
                  '\nCheck that the key is current and that the endpoint is the '
                  'OpenAI-compatible surface rather than the native one.')
        elif status == 429:
            print('\nThe credential AUTHENTICATED: a rate limit is refusing the call, not '
                  'the key. If this is a subscription token, its quota is shared with '
                  'whatever interactive client is using it, so a batch run competes with '
                  'that client and will stall unpredictably. Use a separate API key with '
                  'its own limit for measurement runs.')
        elif status == 404:
            print(f'\nThe endpoint answered but does not serve {model!r}. Model ids are '
                  'endpoint-specific; check the id against this provider\'s catalogue.')
        return 1

    text = (r.choices[0].message.content or '').strip() if r.choices else ''
    print(f'\nOK, reply: {text[:200]}')
    print('strict JSON: ' + ('yes' if text.startswith('{') and text.endswith('}') else
                             'no, the decision parser falls back to substring matching, '
                             'which works but is looser'))
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except ConfigError as e:
        print(f'config error: {e}')
        sys.exit(2)
