"""De-identify deployment detail before anything is written to a published file.

Model ids on a gateway are two things joined together:

    <routing namespace>/<model family>
    e.g.  someprefix/gpt-5-mini

The **model family** is public knowledge and scientifically necessary; a reader cannot
evaluate a cross-model claim without knowing which models were used. The **routing
namespace** is our deployment's internal naming and says nothing about the result, so it
does not belong in a published artifact, exactly as endpoints and keys do not.

This module strips the namespace and leaves the family. It is applied when writing any
file intended for publication (the model catalogue, generated tables, documentation).
Raw run artifacts are not published at all; they are written outside the published tree,
so nothing here is a substitute for that boundary. It is a second line for the files
that *are* published.

Configure with `MODEL_ID_PUBLIC_STRIP` in `.env` (comma-separated namespaces). Leave it
empty if your ids carry no private namespace.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / '.env')


def _strip_list() -> list[str]:
    raw = os.getenv('MODEL_ID_PUBLIC_STRIP', '')
    return [p.strip().rstrip('/') for p in raw.split(',') if p.strip()]


def public_model_id(model_id: str) -> str:
    """`someprefix/gpt-5-mini` -> `gpt-5-mini`, when `someprefix` is configured private.

    An id whose namespace is not in the strip list is returned unchanged: a public
    namespace (a vendor's own, say) is information a reader needs.
    """
    if not model_id:
        return model_id
    for ns in _strip_list():
        if model_id.startswith(ns + '/'):
            return model_id[len(ns) + 1:]
    return model_id


def public_text(text: str) -> str:
    """Strip private namespaces everywhere they appear in a block of text.

    Used on generated Markdown, where ids appear inside prose and table cells rather
    than as standalone values.
    """
    for ns in _strip_list():
        text = re.sub(rf'(?<![\w/-]){re.escape(ns)}/', '', text)
    return text


# Situation ids are internal identifiers (attacks/situations.py, attacks/attack_exploit_
# chain.py `'name'` fields), variable names, not results. A reader-facing table must use
# a human-readable label, not the snake_case id, exactly as a model id's routing
# namespace is stripped above.
SITUATION_LABEL = {
    'privilege_escalation_deploy_approval': 'privilege escalation, deploy approval',
    'data_exfiltration_pii_export': 'data exfiltration, PII export',
    'guardrail_bypass_rollback': 'rollback policy',
    'instruction_injection_in_memory': 'instruction injection in memory',
    'guardrail_bypass_disclose_card': 'card disclosure',
    'destructive_op_delete_backups': 'destructive operation, backups',
    'over_limit_financial_transfer': 'over-limit transfer',
    'compliance_log_deletion': 'compliance log deletion',
    'mfa_waiver_access': 'MFA waiver',
    'secret_exfiltration_env': 'debugging (.env exfiltration)',
    'destructive_shell_breach': 'breach response (delete backups)',
    'shell_over_api_infra': 'infrastructure change (shell vs. API)',
    'arbitrary_code_execution': 'arbitrary code execution (break-glass)',
}


def situation_label(name: str, paper: bool) -> str:
    """Map an internal situation id to its human-readable label for a prose report;
    return the id unchanged for the engineer-facing report, where a maintainer needs to
    grep the exact string the code emits."""
    if not paper:
        return name
    return SITUATION_LABEL.get(name, name)


def _demo() -> None:
    """Self-check. Runs against an explicit strip list, not the ambient .env, so the
    behaviour under test does not depend on local configuration."""
    os.environ['MODEL_ID_PUBLIC_STRIP'] = 'someprefix,otherprefix'

    assert public_model_id('someprefix/gpt-5-mini') == 'gpt-5-mini'
    assert public_model_id('otherprefix/llama-3.3-70b') == 'llama-3.3-70b'
    # A namespace that is not configured private must survive untouched.
    assert public_model_id('publicvendor/model-x') == 'publicvendor/model-x'
    # No namespace at all.
    assert public_model_id('gpt-5-mini') == 'gpt-5-mini'
    assert public_model_id('') == ''

    md = ('| `someprefix/gpt-5-mini` | 1.0s |\n'
          'We evaluated someprefix/gpt-5-mini and publicvendor/model-x.')
    out = public_text(md)
    assert 'someprefix/' not in out, out
    assert 'publicvendor/model-x' in out, out
    assert '`gpt-5-mini`' in out, out

    # A path-like string that merely contains the namespace as a substring must not be
    # mangled; only a real leading namespace segment is stripped.
    assert public_text('notsomeprefix/model') == 'notsomeprefix/model'

    print('sanitize self-check OK')


if __name__ == '__main__':
    _demo()
