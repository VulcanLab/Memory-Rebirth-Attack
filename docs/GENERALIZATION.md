# Cross-system generalization

Does the flaw belong to one implementation, or to a design pattern? This document answers that per system. Numbers come from the raw matrix output (`main.py matrix`). Measurement outputs (the raw JSON and the reports built from it) are written outside this tree (see `RESULTS_DIR` / `REPORTS_DIR` in `.env.example`) and are not part of the published repository.

---

## Two distinct vulnerability mechanisms

Runtime evaluation under natural seeding (the system detects a contradiction and revokes on its own, from plain text, with no harness intervention) surfaced a second failure mode that must not be conflated with this project's central claim (Mechanism A below).

**Mechanism A: soft revoke, status-blind retrieval (this document's main subject).** The system detects the contradiction and marks the superseded record. The vulnerability is that default retrieval ignores the mark. Both stages exist; the flaw is in the second.

**Mechanism B: unreliable or absent contradiction resolution at write time.** Some systems have no temporal-status marker at all, so under the *direct* seeding arm (where the harness manually applies each system's own delete/overwrite primitive) they show no leak; there is nothing retained to resurface. But under *natural* seeding, absent that harness intervention, three of them turned out to leak anyway, for a completely different reason: the revoked and current facts were never reconciled at write time, so both survive as independent, undifferentiated records. Nothing was marked and then ignored, because nothing was marked at all.

The distinction matters because the attacker's action is identical in both cases, ordinary use that creates a contradiction in the store. An unqualified "N systems leak" count would therefore be true but misleading about *why*, and would let Mechanism B's different, upstream defect (fixed by better write-time consolidation, not a retrieval filter) be mistaken for evidence of Mechanism A.

| system | direct R-ASR | natural R-ASR | mechanism when it leaks |
|---|---|---|---|
| Graphiti | 0/81 | leaks | A, detects + marks; retrieval ignores the mark |
| Zep | n/a (no direct primitive) | leaks | A, same engine, worse: mark never exposed to callers |
| mem0 (`show_expired`) | leaks | leaks | A, soft marker; retrieval-time boolean set to expose it |
| mem0 (default) | 0/81 | leaks | B, LLM-driven consolidation exists but did not fire |
| cognee | 0/81 | leaks | B, ingestion path has no fact-level contradiction step at all |
| langmem | 0/81 | leaks partially | B, LLM-driven consolidation exists, unreliable |

*(exact rates: run `main.py matrix` and read `result_matrix.json`; this table summarises the "direct vs natural, per system" breakdown found there)*

Why the three Mechanism-B systems differ in the *why*, not just the rate:

- **cognee**'s ingestion path used here (`add()` then `cognify()`) has no fact-level contradiction step. Raw retrieval output shows both the 2024 and revised policy text present verbatim as two independent chunks, nothing was ever attempted, so nothing failed.
- **mem0** has an LLM-driven step that can add, update, or delete a memory based on similarity to what is already stored. Under natural seeding it consistently chose to add without retiring the old fact.
- **langmem**'s manager has the same kind of consolidation and is the only one of the three that sometimes succeeds, giving a partial rather than uniform natural-mode R-ASR, evidence of an unreliable mechanism rather than a structurally absent one.

---

## The hypothesis being tested

The vulnerability is predicted by a **pairing**, not by either half alone:

```
   history-preserving soft revocation          status-blind default retrieval
   (mark the old fact, keep the row)     +     (rank by similarity, no status
                                                condition in the default query)
                          ↓
              revoked knowledge is served as if current
```

Either half alone is harmless. Hard deletion leaves nothing to resurface. A store that soft-revokes but filters by default never serves the revoked row. The prediction is therefore falsifiable in both directions: systems with the pairing should exhibit it, systems without it should not, and if a hard-deleting system exhibited it anyway, the explanation would have to be something other than this design.

---

## Systems evaluated

Every system below was exercised **at runtime**, not read. Each has a retrieval probe in [`../adapters/`](../adapters/) that seeds, retrieves, and returns plain facts; all downstream measurement is shared code.

| system | update mechanism | revocation visible to the caller? | default retrieval filters it? | predicted | role in the study |
|---|---|---|---|---|---|
| **Graphiti** | soft revoke (`expired_at` / `invalid_at`) | yes, fields are returned | no | vulnerable | primary target |
| **Zep** | soft revoke (inherits the same engine) | **no, fields are never returned** | no | vulnerable, and worse | productisation test |
| **mem0** *(default)* | soft `expiration_date`; plus an LLM consolidation step that *may* add/update/delete | yes | **yes**, hidden unless asked for | safe | positive control for a safe default |
| **mem0** *(expired shown)* | same store, same data | yes | no, one boolean flipped | vulnerable | within-system A/B |
| **langmem** | hard delete / in-place overwrite | n/a, nothing retained | n/a | safe | negative control |
| **cognee** | delete-then-reingest | n/a, nothing retained | n/a | safe | negative control |

---

## Why each system is in the study

### Graphiti: the primary target

The design is explicit and deliberate: contradiction detection stamps validity metadata on the prior edge and keeps it, so history stays queryable. The default search filter is empty, the query builder emits temporal conditions only when the caller populates them, and the base retrieval query constrains partition and orders by similarity score. No boolean "active only" option exists in the filter API, the surface offers date-range matching, which a caller has to know to construct. The agent-facing tool surface inherits the same default.

The fix is expressible: pass a filter requiring the revocation field to be null. It is just not the default, and nothing in the API surface signals that it is needed.

### Zep: does the flaw survive productisation?

This is the most consequential question in the set. Zep is built on the same engine, so the retrieval behaviour carries over. What makes it *worse* rather than equivalent is the API boundary: its fact payload carries an identifier, a timestamp and the fact text. The revocation fields the store maintains internally are **never sent to the caller**.

The consequence is a strict ordering of severity:

- On Graphiti, an application that knows about this can filter, client-side if nothing else.
- On Zep, an application **cannot filter at all**, because it cannot tell which returned fact is dead. Not by default, and not with effort.

This is also why Zep is where a backend-agnostic mitigation earns its keep: the retrieval-layer fix is not expressible there by an application, but a guard that reasons over the returned set is.

To measure Zep at all, the probe reads revocation state directly from its store, purely to *label* results. That is instrumentation, not a capability Zep offers an application, and the defense arm computed from it is reported as **hypothetical**: it shows what a temporal filter would achieve if one existed.

A second observation from the Zep runs: extraction sometimes produces several edges asserting the same superseded policy and revokes only some of them. Even a hypothetical filter would therefore leak, the revocation is incomplete, not merely invisible.

### mem0: the sharpest test available

mem0 matters more than its "safe" verdict suggests, because it contains **both** mechanisms:

- it offers a soft expiry marker whose visibility is governed by one boolean that defaults to hiding expired records, and
- it has an LLM-driven consolidation step that may add, update or delete when new content resembles stored content, a decision, not a guarantee. In our natural-seeding runs that step consistently added the new policy without retiring the contradicted one, leaving both retrievable (see the two-mechanism section above).

That makes a controlled A/B possible **inside one implementation**: same store, same data, one boolean of retrieval policy apart. If flipping that default reproduces the attack, the vulnerability is a property of the retrieval policy rather than of any particular codebase, and the distance between "safe" and "vulnerable" is one configuration value.

That is a stronger and more general statement than "system X has a bug", and it is why mem0 is run in two variants rather than one.

### langmem and cognee: negative controls

Neither has any revocation marker. langmem's manager overwrites in place or deletes; cognee's documented update path is delete-then-reingest, and its data model carries no validity fields.

Including them is not redundant. They are what makes the causal claim testable: if "agent memory is vulnerable" were the right generalization, these would show it too. They also fix the meaning of the direct-seeding arm, for a system whose revocation primitive *is* deletion, the direct arm deletes, because seeding both versions side by side would model a developer who never revoked anything rather than a revocation.

---

## Reading the results

Four things to check in the generated findings report:

1. **R-ASR under `direct` splits along the predicted line.** High for the soft-revoke-plus-status-blind systems, zero for the others. This is model-independent by construction, it is a property of the store.
2. **The mem0 A/B.** Two rows, one boolean apart, on opposite sides of the split.
3. **R-ASR under `natural` does NOT split the same way**, see the two-mechanism section above before drawing any conclusion from a natural-mode number alone.
4. **The defense columns.** The store-level filter has a value only where the backend exposes revocation state. The guard column is the only defense with a value on every row.

---

## Scope

- Results describe the versions pinned in `pyproject.toml` and the stack definitions in `config/`, as of the date in the results file. These systems are actively developed; a default can change.
- "Safe" here means *not vulnerable to this attack*. It is not a general security assessment of any of these systems.
- Where a system could not be run at runtime, it is marked `source_audited` in the output and no numbers are invented for it.