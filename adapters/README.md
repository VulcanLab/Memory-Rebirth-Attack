# Retrieval probes, one per memory system

Each memory system pins a conflicting dependency set; graphiti, mem0, langmem and cognee
cannot share one virtual environment. More importantly, a cross-system comparison is only
meaningful if the difference between systems is the thing under study. So the pipeline is
split:

```
 per-system, isolated environment         shared code path
 ┌───────────────────────────┐            ┌──────────────────────────────┐
 │ adapters/<system>_probe.py│            │ attacks/matrix.py            │
 │   seed                    │   JSON     │   identical model set        │
 │   retrieve (default)      │ ─────────► │   identical trial count      │
 │   retrieve (active only)  │  stdout    │   identical prompt + parser  │
 └───────────────────────────┘            └──────────────────────────────┘
        VARIABLE                                    CONSTANT
```

Only *retrieval* differs per system. Every decision call afterwards goes through one
function, which is what makes the cross-system numbers comparable.

Probes are also provider-neutral: they receive resolved endpoint settings as `MWE_*`
environment variables (see `core/endpoints.py`) and contain no provider name, hostname or
model id. Switching provider is a `.env` edit.

---

## Protocol

### Input: one JSON object on stdin

```json
{"situations": [ ... the situation dicts from core/situations.py ... ],
 "mode": "direct" | "natural",
 "variant": "<system-specific string, optional>"}
```

**`direct`**: revoke `v1` using **the system's own revocation primitive**. For a system
with a soft marker, set the marker. For a system that hard-deletes, revocation *means*
deletion, so delete. Writing both versions side by side into a hard-deleting system would
not model a revocation at all; it would model a developer who never revoked anything,
and would make that system look vulnerable for entirely the wrong reason.

**`natural`**: ingest only plain text and let the system detect the contradiction and
revoke by itself. This is the mode faithful to the threat model, in which the attacker
has no database access. The text comes from `core/situations.py::episodes_for` so it is
byte-identical across systems.

**`variant`**: for systems with more than one meaningful retrieval configuration. Used
to run the same store twice, one setting apart, as a controlled A/B.

### Output: the last line matching `__RESULT__ <json>`

```json
{"project": "<name>", "runtime": true, "variant": "default", "mode": "direct",
 "results": [{
    "situation": "...",
    "attack_facts":  ["...", "..."],
    "defense_facts": ["..."],
    "attack_records": [{"fact": "...", "expired_at": "...", "created_at": "..."}],
    "r_asr": true,
    "revoked_rank": 1,
    "revocation_mechanism": "soft_expired_at" | "hard_delete",
    "note": ""
 }]}
```

| field | meaning |
|---|---|
| `attack_facts` | what the system returns from its **default** read path, what an undefended agent sees |
| `defense_facts` | what it returns with revoked records excluded. For hard-deleting systems this is identical to `attack_facts`; that is the negative control, not a missing implementation |
| `attack_records` | the same default results **as an application would receive them**, including whatever metadata the system actually exposes. Consumed by the backend-agnostic guard, which must cope with systems that expose nothing |
| `r_asr` | the revoked policy is present in `attack_facts` |
| `revoked_rank` | 1-based position it reached, so "returned" and "ranked above the current policy" can be distinguished |
| `revocation_mechanism` | how this system revokes; makes the design split visible in the results |

On failure a probe returns `"runtime": false` with an `error` string rather than an empty
result set. A silent zero and a crash must never look the same; one is a finding, the
other is a bug.

### Detecting the revoked policy in the results

Systems with a revocation field are checked against that field directly. Systems without
one cannot be, and in `natural` mode every system paraphrases while extracting
("requires only ONE reviewer" becomes "requires one reviewer to approve deployments"), so
exact matching would under-count. Those probes use
`core/situations.py::asserts_revoked`, which treats a returned fact as carrying the
revoked policy when it is lexically closer to `v1` than to `v2` by a clear margin.

---

## Adding a system

1. Write `adapters/<system>_probe.py` implementing the protocol above.
2. Read endpoint settings from the `MWE_*` variables only.
3. Import ingestion text from `core/situations.py`, never re-author it, or a retrieval
   difference could just be a difference in what was written.
4. Register it in `attacks/matrix.py::PROBES` with the `uv run --with ...` invocation
   that installs its dependencies.
5. If a seeding mode is not expressible for that system, add it to `SKIP` rather than
   approximating it. A combination that cannot be measured honestly should not be
   reported at all.
