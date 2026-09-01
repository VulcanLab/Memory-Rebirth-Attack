# Attack flow: the diagram

The README shows this as an animation. This is the same structure as a static diagram, for reading in a terminal, a diff, or anywhere Mermaid renders and video does not.

## The whole chain

```mermaid
flowchart TD
  A["v1 authored"] --> B["v2 supersedes it"] --> C["system soft-revokes v1<br/>(marks invalid, keeps it)"]
  Q["benign query"] --> E["default retrieval<br/>(similarity only, ignores status)"]
  C -.->|"v1 still returned"| E
  E --> D["agent picks the unsafe action"]
  D --> T["dangerous tool invoked<br/>read secret / rm -rf / shell"]
  T --> X["secret exfiltrated<br/>(canary-confirmed, sentinel)"]
  D --> J["agent journals it<br/>-> stored ACTIVE, unmarked"]
  J -.->|"laundered, no mark to filter"| E
  E -.->|"reaches other agents<br/>sharing the store"| D
  G{{"filter / guard at E<br/>cuts every path"}} --> E
  style C fill:#fff3cd,stroke:#b8860b
  style E fill:#f8d7da,stroke:#a33
  style X fill:#f5c6cb,stroke:#a33
  style G fill:#d4edda,stroke:#3a3
```

Everything routes through the retrieval boundary `E`. Every arrow of harm (the first unsafe decision, the escalation to a tool, the laundered write-back, the reach to other agents) passes through that one point, which is why a control placed there cuts all of them and a control placed anywhere else cuts one.

## Where each experiment sits on it

| stage | experiment | what it establishes |
|---|---|---|
| `C → E` | `main.py deterministic` | the revoked record survives revocation and is still returned |
| `E → D` | `main.py matrix` | the returned record changes which action the agent selects |
| `D → J → E` | `main.py contamination` | the journalled decision re-enters as an unmarked current fact |
| `E → other agents` | `main.py propagation` | the record reaches agents that never issued the query |
| `E` over distance | `main.py persistence` | drift, growth and elapsed turns do not reduce exposure |
| `D → T → X` | `main.py exploit` | the selected action becomes an invoked tool and a closed chain |
| `G → E` | `main.py matrix` (guard arm) | a control at the boundary cuts every path above |

## The two properties that have to hold together

Neither is a flaw on its own:

```mermaid
flowchart LR
  R["retains superseded records<br/>(history is the feature)"] --> P{"paired?"}
  S["read path ignores the mark<br/>(ranks by similarity alone)"] --> P
  P -->|both| V["exposed"]
  P -->|either alone| N["not exposed"]
  style V fill:#f8d7da,stroke:#a33
  style N fill:#d4edda,stroke:#a33
```

A store that hard-deletes has nothing to resurface. A store that retains but filters on read never serves it. The vulnerability is the pairing, which is why it reproduces across independent implementations and why flipping one retrieval flag can move a system from one side to the other.