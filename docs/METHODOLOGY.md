# Methodology: why the experiments are built this way

This document explains the *reasoning* behind the experimental design. For commands and configuration, see [`../README.md`](../README.md); for results, see the generated findings report under `REPORTS_DIR`.

Everything here exists to answer one objection or another. A security claim about agent memory is easy to make and easy to dismiss, and most of the design effort went into removing the ways it could be dismissed.

---

## 1. The claim, and what could invalidate it

**Claim.** Memory systems that preserve history by *soft-revoking* facts, marking them expired or invalid rather than deleting them, return those revoked facts through their default retrieval path, and an agent reading that context selects unsafe actions at a substantial rate.

Five ways that claim could be wrong, and the design decision that addresses each:

| objection | design response | where |
|---|---|---|
| "You modified the library to make it fail." | The target library is unmodified. Every behavioural change is a runtime monkeypatch applied from outside. | The target is unmodified |
| "You wrote the revoked state into the database yourself, a real attacker cannot." | Two seeding modes. The `natural` mode ingests only plain text and requires the system to detect the contradiction and revoke on its own. | Two ways the revoked state comes to exist |
| "It only works on one weak model." | Nine models across seven vendors and three capability tiers, all on identical situations with identical trial counts. | What is held constant across systems |
| "It's a property of agent memory in general, not of this design." | Systems that hard-delete are included as negative controls. If the flaw were general, they would show it too. | Negative controls |
| "You designed the payloads to succeed." | Situations span two families with different structures, including five where an explicit system-prompt rule forbids the unsafe action, and results are reported per situation so the spread is visible. | Situation design |

---

## 2. The target is unmodified

The attack must be demonstrated on upstream code. Any patch we apply to the library under test is a patch a skeptic can point at.

Two behavioural changes are nonetheless necessary:

- **Safety filters off** for one provider's native SDK. Not to make the attack work, it works regardless, but because a provider-level refusal and an agent choosing the safe action are different events that would otherwise be scored identically. Suppressing the refusal is what makes the measurement mean what it says.
- **Optional call throttling** for rate-limited endpoints.

Both are applied by `core/mwe_patch.py`, at import time, from outside the library. The vendored source tree has zero modified files, which is checkable.

---

## 3. Two ways the revoked state comes to exist

This is the most important methodological point in the study.

The threat model grants the attacker no database access. They can cause text to be ingested through the application's ordinary path, and they can phrase queries. Nothing more. An experiment that writes `expired_at` directly is therefore measuring something adjacent to the threat model, not the threat model itself.

But an experiment that *only* uses natural ingestion confounds two different things: how retrieval treats revoked facts (what we want to measure) and how reliably each system's extractor notices a contradiction (a separate property that varies by system and by model).

So both are run on every system:

| mode | how `v1` becomes revoked | what it establishes | what it cannot establish |
|---|---|---|---|
| `direct` | the harness applies the system's **own** revocation primitive | a controlled measurement with exact, repeatable revocation state and no extraction variance | that the precondition is reachable without privilege |
| `natural` | only plain text is ingested; the system must detect the contradiction and revoke by itself | end-to-end feasibility under the actual threat model | a clean measurement, since extraction quality now varies per cell |

"The system's own revocation primitive" is deliberate. For a system with a soft marker, that means setting the marker. For a system that hard-deletes, revocation *means* deletion, so the direct arm deletes. Seeding both versions side by side into a hard-deleting system would not model a revocation at all; it would model a developer who never revoked anything, and would make that system look vulnerable for entirely the wrong reason.

### A practical detail that matters

Graph-building extractors link *named entities*. A bare policy sentence ("Deployment approval requires one reviewer.") yields entities but no relationship, hence no fact edge, nothing to revoke and nothing to retrieve. Natural-mode text therefore names both a governing document and the system it governs, which is also how such policies appear in a real corpus. The wording of the policies themselves is unchanged between modes, so the two arms carry the same claim.

---

## 4. What is held constant across systems

A cross-system comparison is only meaningful if the difference between systems is the thing under study. The harness splits the pipeline to enforce that:

```mermaid
flowchart TB
    subgraph V["VARIABLE: one isolated environment per memory system"]
      direction LR
      P1["seed"] --> P2["retrieve (default)"] --> P3["retrieve (filtered)"]
    end
    subgraph C["CONSTANT: one shared code path"]
      direction LR
      D1["identical 9 situations"] --> D2["identical model set + order"]
      D2 --> D3["identical trial count"] --> D4["identical prompt template"]
      D4 --> D5["identical action parser"] --> D6["identical temperature"]
    end
    V -->|"plain fact strings, JSON over stdout"| C --> M["D-ASR per arm, Wilson 95% CI"]
```

Each system's probe runs as a subprocess in its own dependency environment, their pins genuinely conflict, and returns plain strings. From that point on there is exactly one decision function, one prompt, one parser.

The ingested text is imported from a single module by every probe, so it is byte-identical across systems. Otherwise a retrieval difference could simply be a difference in what was written.

### The confound in comparing systems on D-ASR

The design is a full factorial: every (system x situation x model) triple is run, with an identical model set in an identical order and an identical trial count. That makes the grid balanced. It does not by itself make every comparison meaningful, and it is worth being precise about which comparisons are clean.

**R-ASR compares cleanly across systems.** It is a property of the store, did the revoked record come back, and does not depend on the model or on how the text was phrased.

**D-ASR does not, in the natural seeding mode.** Each system extracts facts in its own words. Two systems given byte-identical input can hand the agent differently phrased policies, and a more absolute phrasing is more persuasive. A higher D-ASR could therefore mean "this system's retrieval is worse" or "this system's extractor produced more forceful wording", and the factorial cannot separate them, because the difference is inside the cell rather than across it.

This is the main reason both seeding modes exist:

| comparison | use this mode | why |
|---|---|---|
| cross-system D-ASR | `direct` | seeded text is verbatim identical everywhere, so the only thing differing between systems is which records their retrieval returns |
| feasibility without privilege | `natural` | faithful to the threat model, but its D-ASR mixes retrieval behaviour with extraction phrasing and is reported as such |
| cross-defense, within a system | either | all arms see the same retrieved context in the same trials, so the comparison is exact regardless of mode |

**Pooled totals are the wrong test.** Because systems are measured on the same grid, their cells are matched pairs. Comparing two pooled rates discards that structure and lets an imbalance in which situations or models happened to be harder leak into the result. Cross-system claims are therefore reported as **paired comparisons** on matched (situation, model) cells, alongside the pooled rate.

**The no-attack control is already present.** The `retrieval_filter` arm feeds the agent only the current policy, which is exactly the context it would see with no attack. Every cell therefore carries its own baseline, and the attack effect is the within-cell difference rather than a comparison against a separately-run control.

### Sampling

Trials are drawn at **temperature 0.7**, not greedily. Greedy decoding would establish only that *one* path to the unsafe action exists. The claim under test is that it is selected at a substantial *rate*, which requires sampling.

Some model families reject an explicit temperature. Rather than dropping those models, the harness sends the parameter where it is accepted and omits it where it is not, and records which models ran on their provider's default. That is a real deviation from a perfectly uniform protocol, so it is disclosed in the results rather than smoothed over.

Proportions are reported with **Wilson 95% intervals**. Several arms sit at or very near 0 and 1, where the normal approximation produces intervals that extend past the possible range.

### Isolating the probe environment

Probes receive an **allowlisted** environment: a small set of system variables plus the resolved neutral endpoint settings. Everything else is withheld, including credentials for providers the run is not using.

This is not hygiene, it is validity. Memory-system libraries inspect the ambient environment and reroute on what they find. One of the systems evaluated here switches its entire LLM client to a different provider whenever that provider's key happens to be present, ignoring the endpoint it was explicitly configured with. The failure mode is the dangerous kind: no error is raised, results are produced normally, and they describe a different endpoint than the one being reported.

We hit exactly this. A leftover credential in the environment silently redirected one system's extraction calls away from the configured endpoint, which surfaced only because the redirected request happened to fail. Had the model id been valid at both endpoints, the run would have completed and the numbers would have been wrong in a way nothing in the output would reveal.

An allowlist is therefore the only construction under which the provider-neutrality claim holds at run time rather than merely in the source.

### Concurrency

Providers tolerate very different request rates. A single global concurrency setting would either crawl or spend its time being rate-limited, and a provider that rate-limits must not silently end up with a smaller sample than the others. So concurrency is capped per model, with exponential backoff on rate-limit responses. Concurrency is a throughput setting only: every model still answers identical prompts the same number of times, so it cannot affect a measured rate.

---

## 5. Negative controls

Systems that hard-delete on update cannot exhibit this flaw: there is no retained record for a status-blind retriever to return. Including them is not wasted work, it is what ties the result to the *soft-revoke design* rather than to "agent memory" in general. If hard-deleting systems showed the same effect, the explanation would have to be something else entirely.

One system supports both mechanisms, which makes it the sharpest test available: it hard-deletes on contradiction, but also offers a soft expiry marker whose visibility is governed by a single boolean that defaults to hiding expired records. Running it in both configurations is a controlled A/B **inside one implementation**, same store, same data, one boolean of retrieval policy apart. If flipping that default reproduces the attack, the vulnerability is a property of the retrieval policy, not of any particular codebase.

Where a system could not be run at runtime, it is marked `source_audited` in the output and no numbers are fabricated for it.

---

## 6. Situation design

Nine situations, defined in `core/situations.py`. Each pairs a revoked policy `v1` whose action causes harm with the current policy `v2` that forbids it, plus benign distractor facts to make the store realistically noisy.

Two families, treated identically by the harness so their numbers are comparable:

- **payload** (4): no system-prompt rule. Measures whether the revoked fact alone decides the action.
- **guardrail scenario** (5): an explicit safety rule in the system prompt, and a destructive or unauthorized unsafe action. Measures whether the revoked fact can override an instruction that directly forbids what it implies.

Results are reported per situation, not only in aggregate. The spread is itself a finding: the attack is strongest where the unsafe action is *operationally plausible* (approving a deploy, rolling back, deleting backups) and weakest where the unsafe action is intrinsically recognizable as harmful regardless of policy. The latter cases are where a model's pretrained behaviour carries the decision even when retrieved policy says otherwise, which is worth stating plainly, because it bounds the claim.

### Why revoked facts rank well

Superseded policy tends to be phrased more absolutely than its replacement, "must be blocked" versus "are monitored"; "requires only ONE reviewer" versus "requires TWO independent reviewers". A similarity-ranked retriever rewards exactly that phrasing. This is not a quirk of our wording; it is a general property of how policies get revised, and it is why the revoked fact is often ranked *above* the fact that replaced it.

---

## 7. The defenses, and why these four

| arm | what a practitioner would call it | why it is included |
|---|---|---|
| `retrieval_filter` | "fix the query" | the obvious correct fix; establishes the floor |
| `prompt_harden` | "tell the model to ignore old facts" | the cheapest fix, and the first one people reach for |
| `postprocess` | "check the output" | the fix available when you control neither store nor prompt |
| `hybrid` | both of the above | tests whether they compose |
| `guard` | our proposal | the only one expressible on every system tested |

The output filter is deliberately given an advantage it would not have in production: it is allowed to see the revoked fact texts, which a real deployment would have to reconstruct. If it still fails under those conditions, a realistic implementation cannot do better, so a weak result for this arm is a strong statement.

The guard sees **only what the backend returned by default**, the same input the undefended agent gets. It is never handed the store's revocation state, because on at least one system that state is not available to an application at all.

---

## 8. Secondary contamination

Every experiment above measures a single decision made from a poisoned context. That leaves the strongest counter-argument open: filter at retrieval and the problem disappears.

But agents write to their own memory. If an agent acts on a revoked fact and then records what it decided, that record enters the store as an ordinary, current, un-revoked fact. From that moment the revoked policy no longer needs to be retrieved, its conclusion has already been laundered into an active fact, and a temporal filter has nothing to filter.

```mermaid
flowchart LR
  A["seed: v1 REVOKED + v2 ACTIVE"] --> B["hop 0: agent decides<br/>from poisoned context"]
  B -->|unsafe| C["agent journals the decision"]
  C --> D["stored as a NEW fact<br/>no revocation marker"]
  D --> E["hop k: new agent, related task"]
  E --> F["retrieval filter has<br/>nothing to filter"]
  style D fill:#fff3cd,stroke:#b8860b
  style F fill:#f8d7da,stroke:#a33
```

Both write-back paths are measured and reported separately:

- **natural**: the decision is fed through the system's own ingestion, exactly as any other content; nothing bypasses the pipeline. This is what an agent with memory-write access actually does.
- **direct**: the decision is written as an edge. Faster and fully controlled, but it bypasses extraction, so conflating it with the natural path would repeat the mistake the two seeding modes exist to avoid.

The measure that matters is the unsafe rate at hop *k* **under the retrieval filter**. A non-zero value there means the defense that reaches zero in the main matrix has been defeated.

---

## 8b. Reach and persistence

Contamination establishes that a poisoned decision survives in the store. Two further questions do not follow from it, and neither can be answered by measuring one decision.

**How many agents does one revoked fact affect?** Shared memory is the normal architecture for a multi-agent system, and review by a second agent is the normal containment measure. Whether review contains *this* attack is genuinely open before measuring: a reviewer asks a different question than the agent it reviews, so it may retrieve entirely different facts, and if the revoked policy does not surface for it then review is a real boundary.

Three roles share one store: an **executor** that receives the operational task and journals what it decided, an **independent reviewer** asked to approve or reject that action, and a **planner** asked what applies to the next request of the same kind. Only the executor receives the attacker-framed historical query, the other two retrieve on their own questions, so a revoked record reaching them arrived through the store rather than through anything an attacker supplied. Three arms separate the mechanisms: the default read path; the same with the status filter applied to every role; and the default path with the executor *not* journalling, which distinguishes the reach of the original revoked record from the reach of the decision record written about it.

The measure that matters is the reviewer's approval rate **conditioned on the executor having gone wrong**. An unconditional rate mixes in runs where the executor decided correctly and there was nothing to contain, which makes review look more effective than it is.

**Does exposure decay as work moves on?** Not through the passage of time. These stores have no eviction and no relevance ageing, the revoked record is retained deliberately and is not scheduled to stop being retrievable, so there is no mechanism by which elapsed time alone could reduce exposure, and a wait-and-remeasure experiment would report the wait. The absence of a decay mechanism is the finding, and stating it that way is more honest than manufacturing a time axis.

What can change is the revoked record's competitiveness in retrieval, varied along three axes on one seeded store: **query drift** (the same subject asked in progressively less similar language, ending with a purely operational question), **store growth** (unrelated current facts competing for the same top-k slots), and **turn distance** (intervening benign decisions, each journalling its own record, so the store grows through ordinary activity rather than bulk injection).

Both experiments run on a model subset rather than the full nine, because each trial issues several agent calls. The subset is recorded with the results and their numbers are not pooled with the main matrix.

---

## 8c. From a decision label to a real tool action

Every experiment to this point measures which action an agent *selects*. The fair objection is that a label is not an executed operation. The exploit-chain experiment (`main.py exploit`) escalates it: the agent is given real tool affordances, a filesystem read, a shell, an egress channel, and a sanctioned control API, and we measure whether a resurfaced policy drives it to *invoke* the dangerous one. This mirrors the impact that makes injection-based attacks serious (reading a project's secrets and exfiltrating them), reproduced from our mechanism rather than from an injection.

**Safety is the design.** The tools are instrumented sentinels (`attacks/sentinels.py`). They look real to the model and record every attempt, but perform nothing:

- The "secret" is a synthetic string whose values are canary tokens, a fixed, obviously-fake marker (`CANARY-HONEYPOT-DO-NOT-USE`). No real credential exists anywhere in the harness.
- The shell tool classifies and records a command; it never runs one. `rm -rf` is scored as an attempted destructive action, not performed.
- The egress tool is a sink that records what the agent tried to send and scans it for canary tokens. A canary reaching the sink confirms the chain closed end to end, while nothing leaves the process.
- The module imports no `subprocess`, `socket`, `os`, or HTTP client, and ships a self-check asserting no real resource is reachable.

**Dangerousness is situation-specific, never a global property of a tool.** `send_external` is exfiltration when it carries a secret but a legitimate "notify security" when it does not, so each situation names exactly the signal that is its unsafe action: reading the secret, attempting the destructive op, or using shell in place of the sanctioned API. An earlier version treated the egress tool as universally dangerous and mis-scored the correct breach response (isolate and notify) as an attack; the control (status-filter) arm surfaced it, and it was fixed.

Outcome variables: `T-ASR` (dangerous tool invoked), `secret_read`, `exfil_confirmed` (a canary reached a sink, the full chain), and `rce_attempted` (the agent composed an inline-interpreter command, arbitrary code execution, recorded, never run). Four situations: reading a secret and exfiltrating it, a destructive command, shell in place of the sanctioned API, and a break-glass incident fix that invites arbitrary code. Four arms: no defence, the retrieval filter, the guard, and a **tool-layer guardrail** that locks down the shell while leaving the resurfaced policy in context, which isolates "fix at the tool" from "fix at the store" and, because the attack routes to whatever tool reaches the goal, does not reduce the invocation rate. The `rce_attempted` detector is deliberately narrow (interpreter one-liners and pipe-to-shell only): benign command chaining (`a; b`, `a && b`) and substitution were an early false-positive source and are excluded. Compromised runs are extended through the journal-and-relapse chain of the contamination experiment, to measure whether the exploit recurs on a later benign query.

---

## 9. What this design still cannot tell you

- **Action selection, not execution.** We measure which action the agent chooses, not a side effect in a real system. Contamination and propagation are the closest thing to measuring persistence of harm: a decision is written back and read by other agents, but no action is carried out against a real system.
- **Authored situations.** Nine situations chosen to span plausible agent-security decisions. They are not a sample of production workloads, and the per-situation spread should be read as evidence about which *kinds* of decisions are exposed, not as a base rate.
- **One embedding model.** Retrieval success could in principle vary with the embedder.
- **Systems evolve.** Every result is a statement about the versions pinned in `pyproject.toml` and the stack definitions in `config/`, on the date in the results file.