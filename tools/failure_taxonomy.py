"""Separate the ways revocation fails, per system and per seeding mode.

"No system enforces revocation by default" collapses four different situations that a
deployment would act on differently, and they are worth telling apart:

  deleted            the contradicted record is not in the store at all. Revocation
                     did not fail; history did. Nothing can be resurfaced, and nothing
                     can be audited either.
  update failure     the record is in the store and carries no revocation mark,
                     because the system never recognised the contradiction. There is
                     nothing for any read-time control to act on.
  exposure failure   the record is marked, and the mark does not reach the caller, so
                     an application cannot filter on what the store knows.
  enforcement        the record is marked, the mark is readable, and the default read
                     path returns it anyway.

A fifth case is not a failure of the system at all and is reported separately:

  configuration      the default read path does filter, and the exposure reported
                     under that system came from a non-default retrieval setting. The
                     number is then a statement about that configuration, not about
                     the product as shipped.

Everything here is derived from `result_matrix.json`; nothing is re-run and nothing is
asserted that the recorded run does not support.

Run: uv run python tools/failure_taxonomy.py             # table
     uv run python tools/failure_taxonomy.py --json
"""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'core'))

from mwe_common import RESULTS_DIR, PROJECT_ROOT                    # noqa: E402

# Where a matrix run may have landed. RESULTS_DIR has pointed outside the published
# tree for a while, and runs from before that are still where they were written, so
# both are searched rather than requiring the older one to be moved.
SEARCH = [RESULTS_DIR, PROJECT_ROOT / 'private' / 'results']


def find_matrix(explicit: str | None) -> Path | None:
    if explicit:
        p = Path(explicit)
        return p if p.exists() else None
    for d in SEARCH:
        p = d / 'result_matrix.json'
        if p.exists():
            return p
    return None

# A system whose default retrieval hides what a non-default setting reveals is a
# configuration case, not a default-enforcement case. The pairs are declared rather
# than guessed so the distinction cannot quietly follow from a naming convention.
DEFAULT_OF = {('mem0', 'show_expired'): ('mem0', 'default')}

# Mechanisms that keep the contradicted record, as the adapters report them.
RETAINING = {'soft_expired_at', 'soft_expiration_date'}


def classify(row: dict, peer_default: dict | None) -> tuple[str, str]:
    """(category, why) for one system, variant and seeding mode."""
    mech = row['mechanism']
    exposed, n = row['exposed'], row['n']

    if peer_default is not None and peer_default['exposed'] == 0 and exposed > 0:
        return ('configuration',
                f'the default configuration exposed 0/{peer_default["n"]}; this arm '
                f'exposed {exposed}/{n} only after a retrieval setting was changed')

    if mech not in RETAINING:
        if exposed == 0:
            return ('deleted',
                    'the contradicted record is not retained, so nothing can be '
                    'resurfaced and nothing can be audited')
        return ('update failure',
                f'the record was retained and carries no revocation mark, and the '
                f'default read path returned it in {exposed}/{n} situations')

    if exposed == 0:
        return ('enforced',
                'the record is retained and marked, and the default read path did '
                'not return it')

    if not row['status_visible']:
        return ('exposure failure',
                f'the record is retained and marked, the mark does not reach the '
                f'caller, and the default read path returned it in {exposed}/{n}')

    return ('enforcement failure',
            f'the record is retained, the mark is readable, and the default read path '
            f'returned it in {exposed}/{n} situations')


def collect(path: Path) -> dict:
    data = json.loads(path.read_text())

    rows: dict[tuple, dict] = {}
    agg = defaultdict(lambda: {'exposed': 0, 'n': 0, 'rank1': 0, 'mech': set(),
                               'caught': 0, 'revoked': 0, 'held_current': 0,
                               'current': 0})
    for r in data.get('retrieval', []):
        if not r.get('runtime'):
            continue
        k = (r['project'], r['variant'], r['mode'])
        a = agg[k]
        a['exposed'] += bool(r.get('r_asr'))
        a['n'] += 1
        a['rank1'] += (r.get('revoked_rank') == 1)
        a['mech'].add(r.get('revocation_mechanism', ''))
        a['caught'] += r.get('guard_caught_revoked') or 0
        a['revoked'] += r.get('guard_n_revoked') or 0
        a['held_current'] += r.get('guard_withheld_current') or 0
        a['current'] += r.get('n_facts_filtered') or 0

    # Whether the store hands the caller a usable status field. Zep is the one system
    # that returns the record and withholds the mark, which the adapter records by
    # reporting a retaining mechanism while the store-level filter has nothing to act
    # on: its filtered set is the same size as its default set.
    for k, a in agg.items():
        mech = sorted(m for m in a['mech'] if m) or ['']
        rows[k] = {
            'project': k[0], 'variant': k[1], 'mode': k[2],
            'mechanism': mech[0] if len(mech) == 1 else '|'.join(mech),
            'exposed': a['exposed'], 'n': a['n'], 'rank1': a['rank1'],
            'status_visible': k[0] != 'zep',
            'guard_caught': a['caught'], 'guard_revoked': a['revoked'],
            'guard_withheld_current': a['held_current'], 'n_current': a['current'],
        }

    out = []
    for k, row in sorted(rows.items()):
        peer = DEFAULT_OF.get((k[0], k[1]))
        peer_row = rows.get((peer[0], peer[1], k[2])) if peer else None
        cat, why = classify(row, peer_row)
        out.append({**row, 'category': cat, 'why': why})

    # Per-arm unsafe rates, so the taxonomy sits next to what each case cost.
    per_system = {}
    for key, v in data.get('summary', {}).items():
        if key.startswith('_'):
            continue
        per_system[key] = {arm: v.get(arm, {}) for arm in
                           ('attack', 'retrieval_filter', 'guard')}

    return {'source': str(path), 'rows': out, 'unsafe_by_system': per_system}


def as_markdown(v: dict) -> str:
    out = ['| system | variant | seeding | mechanism | exposed | rank 1 | category |',
           '|---|---|---|---|---|---|---|']
    for r in v['rows']:
        out.append(f"| {r['project']} | {r['variant']} | {r['mode']} | "
                   f"{r['mechanism']} | {r['exposed']}/{r['n']} | {r['rank1']} | "
                   f"**{r['category']}** |")
    out += ['', '### Why each was classified that way', '']
    for r in v['rows']:
        out.append(f"- `{r['project']}[{r['variant']}]/{r['mode']}`: {r['why']}.")
    out += ['', '### Guard behaviour on the same runs', '',
            '| system | variant | seeding | revoked caught | current withheld |',
            '|---|---|---|---|---|']
    for r in v['rows']:
        out.append(f"| {r['project']} | {r['variant']} | {r['mode']} | "
                   f"{r['guard_caught']}/{r['guard_revoked']} | "
                   f"{r['guard_withheld_current']}/{r['n_current']} |")
    return '\n'.join(out)


def main() -> None:
    explicit = next((a.split('=', 1)[1] for a in sys.argv if a.startswith('--input=')),
                    None)
    path = find_matrix(explicit)
    if path is None:
        where = ' or '.join(str(d / 'result_matrix.json') for d in SEARCH)
        print(f'no matrix results at {where}; run the matrix first, or pass '
              f'--input=<path>', file=sys.stderr)
        sys.exit(2)
    v = collect(path)
    print(json.dumps(v, indent=2) if '--json' in sys.argv else as_markdown(v))


if __name__ == '__main__':
    main()
