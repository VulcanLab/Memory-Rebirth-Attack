"""Stale-Retrieval Guard: filter superseded facts out of a retrieval result.

Backend-agnostic by construction: the input is a list of records, each of which needs
only a text field. Everything else is optional and used when present. See guard/README.md
for the rationale and the honest scope.

Three stages, cheapest and most reliable first:

  1. EXPLICIT   If the record carries a revocation field the backend already set, drop
                it. This reproduces the store-level filter for backends that expose the
                metadata, and costs nothing.

  2. CONFLICT   Group the remaining records by what they are *about*, then within a
                group find pairs that assert incompatible things. Keep the newer, hold
                back the older. This is the stage that needs no backend cooperation,
                and the only one that can catch content nothing ever marked as revoked.

  3. ANNOTATE   Return what was withheld and why, so the caller can surface a conflict
                instead of silently losing history.

The conflict rule combines two signals, because neither alone is sound:

  * high lexical overlap on subject terms  -> the two facts are about the same thing
  * an antonym / negation / quantity mismatch -> they disagree

Requiring both keeps "PII must never leave the network" from being judged to conflict
with "support hours are 9am to 6pm" (different subject), and keeps two paraphrases of
the same current policy from being treated as a disagreement (same subject, no
opposition). The thresholds are configurable and their effect is measured, not assumed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Sequence

# Field names different backends use for "this record is no longer valid".
REVOCATION_FIELDS = ('expired_at', 'invalid_at', 'valid_to', 'deleted_at',
                     'revoked_at', 'expiration_date', 'invalidated_at')
# Field names used for recency, most authoritative first.
TIME_FIELDS = ('valid_at', 'updated_at', 'created_at', 'timestamp', 'ts')

_STOP = {
    'this', 'that', 'with', 'from', 'they', 'have', 'been', 'were', 'which', 'their',
    'there', 'when', 'what', 'shall', 'will', 'into', 'over', 'under', 'than', 'then',
    'only', 'also', 'must', 'may', 'can', 'are', 'is', 'the', 'and', 'for', 'any',
    'all', 'per', 'policy', 'standard', 'procedure', 'runbook', 'states', 'state',
    'approved', 'current', 'issued', 'requires', 'require', 'required', 'governs',
}

# Word pairs whose co-occurrence across two facts about the same subject signals that
# the facts disagree rather than elaborate on each other.
OPPOSITES: tuple[tuple[str, str], ...] = (
    ('never', 'may'), ('never', 'permitted'), ('never', 'allowed'), ('never', 'can'),
    ('must', 'never'), ('prohibited', 'permitted'), ('prohibited', 'allowed'),
    ('denied', 'granted'), ('deny', 'grant'), ('denied', 'allowed'),
    ('block', 'monitor'), ('blocked', 'monitored'), ('blocked', 'allowed'),
    ('delete', 'retain'), ('deleted', 'retained'), ('delete', 'keep'),
    ('immediately', 'first'), ('automatically', 'approval'),
    ('waived', 'required'), ('waiver', 'required'), ('skip', 'required'),
    ('single', 'dual'), ('one', 'two'), ('without', 'requires'),
    ('disclose', 'refuse'), ('export', 'internal'), ('rollback', 'investigate'),
)

NEGATIONS = ('never', 'not', 'no ', 'without', 'prohibit', 'forbid', 'must not',
             'may not', 'cannot')


def _stem(w: str) -> str:
    """Crude suffix strip. "reviewer"/"reviewers" and "block"/"blocked" must match, or
    two statements about the same subject look like two different subjects."""
    for suf in ('ies', 'ing', 'ed', 'es', 's'):
        if len(w) > 4 and w.endswith(suf):
            return w[: -len(suf)] + ('y' if suf == 'ies' else '')
    return w


def _tokens(text: str) -> set[str]:
    return {_stem(w) for w in re.findall(r'[a-z0-9$]+', text.lower())
            if len(w) > 2 and w not in _STOP}


def _numbers(text: str) -> set[str]:
    """Quantities are a strong disagreement signal ($10,000 vs $1,000,000; 1 vs 2)."""
    return set(re.findall(r'\$?\d[\d,]*', text.lower()))


def _negation_count(text: str) -> int:
    t = text.lower()
    return sum(t.count(n) for n in NEGATIONS)


@dataclass
class GuardConfig:
    """Thresholds. Tuned to be conservative: prefer letting a fact through over
    withholding a current policy, since a false positive removes real information."""
    subject_overlap: float = 0.45      # min containment on content words = "same subject"
    require_opposition: bool = True    # same subject alone is not enough to withhold
    trust_explicit_fields: bool = True
    max_withheld_ratio: float = 0.6    # never withhold most of the result set
    annotate: bool = True


@dataclass
class GuardResult:
    kept: list[Any] = field(default_factory=list)
    withheld: list[dict] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def texts(self) -> list[str]:
        return [_text_of(r) for r in self.kept]


def _text_of(rec: Any) -> str:
    if isinstance(rec, str):
        return rec
    if isinstance(rec, dict):
        for k in ('fact', 'text', 'content', 'memory', 'body'):
            v = rec.get(k)
            if isinstance(v, str) and v:
                return v
        return str(rec)
    for k in ('fact', 'text', 'content', 'memory'):
        v = getattr(rec, k, None)
        if isinstance(v, str) and v:
            return v
    return str(rec)


def _field(rec: Any, names: Sequence[str]):
    for n in names:
        v = rec.get(n) if isinstance(rec, dict) else getattr(rec, n, None)
        if v not in (None, ''):
            return v
    return None


def _explicitly_revoked(rec: Any) -> str | None:
    """Return the field name that marks this record revoked, if any.

    `expiration_date` is a *scheduled* expiry, so it only counts once it is in the past;
    the others are set at the moment of revocation and count immediately.
    """
    for n in REVOCATION_FIELDS:
        v = rec.get(n) if isinstance(rec, dict) else getattr(rec, n, None)
        if v in (None, ''):
            continue
        if n == 'expiration_date':
            try:
                d = v if isinstance(v, datetime) else datetime.fromisoformat(str(v))
                if d.tzinfo is None:
                    d = d.replace(tzinfo=timezone.utc)
                if d > datetime.now(timezone.utc):
                    continue
            except Exception:
                pass
        return n
    return None


def _timestamp(rec: Any) -> float | None:
    """Recency, or None when the backend gave us nothing to go on.

    Returning None matters: result order is a RELEVANCE ranking, not a chronology, so
    treating position as recency would let the guard keep whichever conflicting fact
    happened to rank higher. That is how a filter meant to remove stale content ends up
    removing the current policy instead, observed in testing against a backend that
    returns no metadata. Absence of evidence is represented as absence, and handled
    explicitly by `guard`.
    """
    v = _field(rec, TIME_FIELDS)
    if v is None:
        return None
    if isinstance(v, datetime):
        return v.timestamp()
    try:
        return datetime.fromisoformat(str(v).replace('Z', '+00:00')).timestamp()
    except Exception:
        return None


def contradicts(a: str, b: str, cfg: GuardConfig) -> tuple[bool, str]:
    """Do these two facts assert incompatible things about the same subject?"""
    ta, tb = _tokens(a), _tokens(b)
    if not ta or not tb:
        return False, ''
    # Containment, not Jaccard: a terse current policy and a verbose superseded one
    # are about the same subject even when their lengths differ a lot, and Jaccard
    # punishes exactly that case.
    overlap = len(ta & tb) / min(len(ta), len(tb))
    if overlap < cfg.subject_overlap:
        return False, ''
    if not cfg.require_opposition:
        return True, f'same subject (overlap {overlap:.2f})'

    la, lb = a.lower(), b.lower()
    for x, y in OPPOSITES:
        if (x in la and y in lb) or (y in la and x in lb):
            return True, f'opposing terms "{x}"/"{y}" (subject overlap {overlap:.2f})'

    na, nb = _numbers(a), _numbers(b)
    if na and nb and not (na & nb):
        return True, f'conflicting quantities {sorted(na)} vs {sorted(nb)}'

    if abs(_negation_count(a) - _negation_count(b)) >= 1 and overlap >= 0.45:
        return True, f'polarity mismatch (subject overlap {overlap:.2f})'

    return False, ''


def guard(records: Iterable[Any], cfg: GuardConfig | None = None) -> GuardResult:
    """Filter superseded records out of one retrieval result."""
    cfg = cfg or GuardConfig()
    recs = list(records)
    res = GuardResult()
    if not recs:
        return res

    # ---- stage 1: explicit revocation the backend already recorded
    surviving: list[tuple[int, Any]] = []
    for i, r in enumerate(recs):
        marked = _explicitly_revoked(r) if cfg.trust_explicit_fields else None
        if marked:
            res.withheld.append({'text': _text_of(r), 'reason': f'backend marked {marked}',
                                 'stage': 'explicit'})
        else:
            surviving.append((i, r))

    # ---- stage 2: pairwise contradiction among what is left
    #
    # A fact is withheld only when it both conflicts with a kept fact AND is demonstrably
    # older. Without a timestamp on both sides there is no basis for deciding which one
    # is stale, so the pair is KEPT and the conflict reported. Guessing would risk
    # withholding the current policy and leaving the revoked one, which is strictly worse
    # than doing nothing.
    stamped = [(i, r, _timestamp(r)) for i, r in surviving]
    # Newest first where we know; unknown timestamps keep their original position, since
    # they are neither promoted nor demoted by a value we do not have.
    order = sorted(stamped, key=lambda t: (t[2] is not None, t[2] or 0), reverse=True)

    kept_idx: list[tuple[int, Any]] = []
    # Cap total withholding. If most of a result set looks conflicting, the heuristic is
    # more likely wrong than the store is, and dropping most of the context would break
    # the agent in a different way.
    max_withhold = int(len(recs) * cfg.max_withheld_ratio)
    for i, r, ts in order:
        text = _text_of(r)
        conflict = None
        for _, kr in kept_idx:
            hit, why = contradicts(text, _text_of(kr), cfg)
            if not hit:
                continue
            kts = _timestamp(kr)
            if ts is not None and kts is not None and ts < kts:
                conflict = (why, _text_of(kr))          # demonstrably older -> withhold
            else:
                # Conflict is real but we cannot tell which is current. Keep both and say so.
                res.notes.append(
                    f'unresolved conflict ({why}); both facts kept because the backend '
                    f'supplied no usable timestamp to order them')
            break
        if conflict and len(res.withheld) < max_withhold:
            res.withheld.append({'text': text, 'reason': f'superseded: {conflict[0]}',
                                 'stage': 'conflict', 'superseded_by': conflict[1]})
        else:
            kept_idx.append((i, r))

    # restore the backend's original ranking for whatever survived
    res.kept = [r for _, r in sorted(kept_idx, key=lambda p: p[0])]

    if cfg.annotate and res.withheld:
        res.notes.append(
            f'{len(res.withheld)} of {len(recs)} retrieved facts withheld as superseded '
            f'or revoked; they remain in the store and are listed in `withheld`.')
    return res


def guarded_search(search_fn: Callable[..., Iterable[Any]],
                   cfg: GuardConfig | None = None) -> Callable[..., GuardResult]:
    """Wrap any search callable. The backend call itself is untouched."""
    def wrapped(*args, **kwargs) -> GuardResult:
        return guard(search_fn(*args, **kwargs), cfg)
    return wrapped


def _demo() -> None:
    """Self-check: the guard must withhold a revoked policy and keep unrelated facts."""
    now = datetime.now(timezone.utc)
    old = now.replace(year=now.year - 1)

    # (a) backend exposes revocation -> stage 1
    recs = [{'fact': 'All TOR logins must be blocked.', 'expired_at': old.isoformat()},
            {'fact': 'TOR logins with anomalies are monitored, not blocked.'}]
    r = guard(recs)
    assert len(r.kept) == 1 and 'monitored' in r.texts[0], r.texts
    assert r.withheld[0]['stage'] == 'explicit'

    # (b) backend exposes NOTHING (the Zep case) -> stage 2 must still catch it
    recs = [{'fact': 'Deployment approval requires only one reviewer.',
             'created_at': old.isoformat()},
            {'fact': 'Deployment approval requires two independent reviewers.',
             'created_at': now.isoformat()}]
    r = guard(recs)
    assert len(r.kept) == 1, r.texts
    assert 'two independent' in r.texts[0], r.texts
    assert r.withheld[0]['stage'] == 'conflict'

    # (c) unrelated facts must survive; withholding real information is the failure
    #     mode that matters most
    recs = [{'fact': 'Support hours are 9am to 6pm.'},
            {'fact': 'Refund requests over 30 days require a manager note.'},
            {'fact': 'Customer PII must never leave the internal network.'}]
    r = guard(recs)
    assert len(r.kept) == 3, r.withheld

    # (d) NO timestamps anywhere: the guard must not guess which is current. Keeping a
    #     stale fact is bad; withholding the CURRENT one is worse, so it keeps both and
    #     reports the conflict. This is the exact case that made the guard harmful
    #     against a backend which returns text only.
    recs = [{'fact': 'A single operator may execute transfers up to $1,000,000.'},
            {'fact': 'Single-operator transfers are capped at $10,000.'}]
    r = guard(recs)
    assert len(r.kept) == 2, r.withheld
    assert any('unresolved conflict' in n for n in r.notes), r.notes

    # (e) quantity conflict with no opposing words
    recs = [{'fact': 'A single operator may execute transfers up to $1,000,000.',
             'created_at': old.isoformat()},
            {'fact': 'Single-operator transfers are capped at $10,000.',
             'created_at': now.isoformat()}]
    r = guard(recs)
    assert len(r.kept) == 1 and '10,000' in r.texts[0], r.texts

    print('stale_guard self-check OK')


if __name__ == '__main__':
    _demo()
