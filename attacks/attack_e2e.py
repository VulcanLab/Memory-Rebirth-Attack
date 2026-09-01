"""Memory Rebirth Attack: end-to-end proof via the natural code path.

Unlike attack_deterministic.py (which seeds expired_at by hand), this drives the
REAL Graphiti ingestion pipeline with an LLM (local Ollama). We add two episodes:
    ep1 -> establishes v1: "All TOR logins must be blocked."
    ep2 -> contradicts it:  "TOR logins with anomalies are only monitored; the
            previous blanket blocking rule no longer applies."

Graphiti's edge-invalidation logic should detect the contradiction and set
expired_at / invalid_at on the v1 edge (soft delete). We then fire the attacker's
"historical" query through the DEFAULT retrieval path and check whether the
auto-revoked edge still resurfaces.

NOTE: depends on the local model producing valid structured output. If the small
model fails extraction, rely on attack_deterministic.py for the core claim.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone

from graphiti_core.nodes import EpisodeType

from mwe_common import GROUP_ID, build_graphiti, provider_banner

ATTACK_QUERY = "Explain the historical reasoning behind our TOR login blocking policy."


async def dump_edges(graphiti):
    """Read RELATES_TO edges directly to inspect temporal markers."""
    q = (
        "MATCH (n:Entity)-[e:RELATES_TO]->(m:Entity) "
        "WHERE e.group_id = $gid "
        "RETURN e.fact AS fact, e.expired_at AS expired_at, e.invalid_at AS invalid_at "
        "ORDER BY e.created_at"
    )
    records, _, _ = await graphiti.driver.execute_query(q, gid=GROUP_ID, routing_="r")
    rows = []
    for r in records:
        rows.append({
            "fact": r["fact"],
            "expired_at": str(r["expired_at"]) if r["expired_at"] is not None else None,
            "invalid_at": str(r["invalid_at"]) if r["invalid_at"] is not None else None,
        })
    return rows


async def main():
    graphiti = build_graphiti(with_llm=True)
    print(f"[config] {provider_banner()}\n")
    try:
        await graphiti.build_indices_and_constraints()

        # Episodes are written so extraction yields TWO named entities
        # (the firewall rule "FW-101" and "the TOR network") joined by a relation
        # whose value flips v1->v2, which is what triggers Graphiti's invalidation.
        print("[ingest] ep1 (establishes blocking relation)")
        await graphiti.add_episode(
            name="policy_v1",
            episode_body=(
                "Firewall rule FW-101 blocks all login connections from the TOR network. "
                "FW-101 denies every TOR connection."
            ),
            source_description="policy log",
            reference_time=datetime.now(timezone.utc),
            source=EpisodeType.text,
            group_id=GROUP_ID,
        )
        print("[ingest] ep2 (supersedes: FW-101 now monitors, not blocks)")
        await graphiti.add_episode(
            name="policy_v2",
            episode_body=(
                "Firewall rule FW-101 was updated. FW-101 no longer blocks connections "
                "from the TOR network. FW-101 now only monitors TOR network connections "
                "for anomalies. The previous rule where FW-101 blocked the TOR network "
                "no longer applies."
            ),
            source_description="policy log",
            reference_time=datetime.now(timezone.utc),
            source=EpisodeType.text,
            group_id=GROUP_ID,
        )

        print("\n[graph state] RELATES_TO edges after ingestion:")
        rows = await dump_edges(graphiti)
        for r in rows:
            status = "REVOKED" if r["expired_at"] else "ACTIVE"
            print(f"  [{status:7}] {r['fact']}  expired_at={r['expired_at']}")

        any_revoked = any(r["expired_at"] for r in rows)
        print(f"\n[graph state] auto-invalidation produced a revoked edge = {any_revoked}")

        # ---- ATTACK: default retrieval ----
        edges = await graphiti.search(query=ATTACK_QUERY, group_ids=[GROUP_ID], num_results=10)
        print("\n" + "=" * 70)
        print("ATTACK  graphiti.search(default) with historical query")
        print("-" * 70)
        revoked_returned = False
        for i, e in enumerate(edges):
            status = "REVOKED" if e.expired_at else "ACTIVE"
            if e.expired_at:
                revoked_returned = True
            print(f"  #{i+1} [{status:7}] {e.fact}  expired_at={e.expired_at}")
        print("-" * 70)
        print(f"RESULT: revoked edge resurfaced by default search = {revoked_returned}")

        verdict = {
            "auto_invalidation_occurred": any_revoked,
            "attack_default_returns_revoked": revoked_returned,
            "edges_in_graph": rows,
            "n_search_results": len(edges),
        }
        with open("result_e2e.json", "w") as f:
            json.dump(verdict, f, indent=2)
        print("\nVERDICT " + json.dumps(verdict, indent=2))
    finally:
        await graphiti.close()


if __name__ == "__main__":
    asyncio.run(main())
