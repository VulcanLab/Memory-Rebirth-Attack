"""Memory Rebirth Attack: deterministic core proof (LLM-free).

Hypothesis under test:
    Graphiti revokes knowledge by SOFT marking (expired_at / invalid_at), and the
    DEFAULT hybrid retrieval (graphiti.search with no SearchFilters) does NOT filter
    those revoked edges out. A "historical" query therefore resurfaces revoked v1.

This script does NOT rely on an LLM. It seeds the graph directly with two competing
facts about the same entities:
    v1 (REVOKED): "All TOR logins must be blocked."   expired_at/invalid_at = past
    v2 (ACTIVE) : "TOR logins with anomalies are monitored, not blocked."

Then it runs the attacker query through the *default* retrieval path and reports
whether the REVOKED edge is returned, at what rank. As a control it re-runs the
same query WITH an explicit `expired_at IS NULL` filter to show the defense exists
but is OFF by default.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta, timezone

from graphiti_core.edges import EntityEdge
from graphiti_core.nodes import EntityNode
from graphiti_core.search.search_filters import (
    ComparisonOperator,
    DateFilter,
    SearchFilters,
)

from mwe_common import GROUP_ID, build_graphiti, provider_banner

NOW = datetime.now(timezone.utc)
PAST = NOW - timedelta(days=30)

ATTACK_QUERY = "Explain the historical reasoning behind our TOR login blocking policy."


async def seed(graphiti):
    embedder = graphiti.clients.embedder

    # Two shared entity nodes the competing facts connect.
    tor = EntityNode(name="TOR network", group_id=GROUP_ID, labels=["Entity"],
                     created_at=PAST, summary="Anonymity network")
    policy = EntityNode(name="Login access policy", group_id=GROUP_ID, labels=["Entity"],
                        created_at=PAST, summary="Access control policy")
    for n in (tor, policy):
        await n.generate_name_embedding(embedder)
        await n.save(graphiti.driver)

    # v1, REVOKED (soft-deleted): expired_at + invalid_at set in the past.
    v1 = EntityEdge(
        name="POLICY_RULE",
        fact="All TOR logins must be blocked.",
        group_id=GROUP_ID,
        source_node_uuid=tor.uuid,
        target_node_uuid=policy.uuid,
        created_at=PAST,
        valid_at=PAST,
        expired_at=NOW - timedelta(days=1),   # <-- revoked
        invalid_at=NOW - timedelta(days=1),   # <-- revoked
    )
    # v2, ACTIVE: no expiry.
    v2 = EntityEdge(
        name="POLICY_RULE",
        fact="TOR logins with detected anomalies are monitored, not blocked.",
        group_id=GROUP_ID,
        source_node_uuid=tor.uuid,
        target_node_uuid=policy.uuid,
        created_at=NOW,
        valid_at=NOW,
        expired_at=None,
        invalid_at=None,
    )
    for e in (v1, v2):
        await e.generate_embedding(embedder)
        await e.save(graphiti.driver)

    return v1, v2


def describe(edge: EntityEdge) -> dict:
    return {
        "fact": edge.fact,
        "expired_at": edge.expired_at.isoformat() if edge.expired_at else None,
        "invalid_at": edge.invalid_at.isoformat() if edge.invalid_at else None,
        "status": "REVOKED" if edge.expired_at else "ACTIVE",
    }


async def main():
    graphiti = build_graphiti(with_llm=False)
    print(f"[config] {provider_banner()}\n")
    try:
        await graphiti.build_indices_and_constraints()
        v1, v2 = await seed(graphiti)
        print(f"[seed] v1(REVOKED) uuid={v1.uuid}")
        print(f"[seed] v2(ACTIVE)  uuid={v2.uuid}\n")

        # ---- ATTACK: default retrieval, no filter ----
        default_edges = await graphiti.search(
            query=ATTACK_QUERY, group_ids=[GROUP_ID], num_results=10
        )
        print("=" * 70)
        print("ATTACK  graphiti.search(default, no SearchFilters)")
        print(f"query: {ATTACK_QUERY}")
        print("-" * 70)
        revoked_returned = False
        for i, e in enumerate(default_edges):
            d = describe(e)
            if d["status"] == "REVOKED":
                revoked_returned = True
            print(f"  #{i+1} [{d['status']:7}] {d['fact']}  expired_at={d['expired_at']}")
        print("-" * 70)
        print(f"RESULT: revoked v1 resurfaced by default search = {revoked_returned}")

        # ---- CONTROL: same query, explicit expired_at IS NULL filter ----
        active_only = SearchFilters(
            expired_at=[[DateFilter(comparison_operator=ComparisonOperator.is_null)]]
        )
        filtered_edges = await graphiti.search(
            query=ATTACK_QUERY, group_ids=[GROUP_ID], num_results=10,
            search_filter=active_only,
        )
        print("\n" + "=" * 70)
        print("CONTROL  graphiti.search(SearchFilters(expired_at IS NULL))")
        print("-" * 70)
        for i, e in enumerate(filtered_edges):
            d = describe(e)
            print(f"  #{i+1} [{d['status']:7}] {d['fact']}")
        print("-" * 70)
        control_leaks = any(e.expired_at for e in filtered_edges)
        print(f"RESULT: revoked v1 leaks under explicit filter = {control_leaks}")

        verdict = {
            "attack_default_returns_revoked": revoked_returned,
            "control_filter_returns_revoked": control_leaks,
            "n_default": len(default_edges),
            "n_filtered": len(filtered_edges),
            "hypothesis_confirmed": revoked_returned and not control_leaks,
        }
        print("\n" + "=" * 70)
        print("VERDICT " + json.dumps(verdict, indent=2))
        with open("result_deterministic.json", "w") as f:
            json.dump(verdict, f, indent=2)
    finally:
        await graphiti.close()


if __name__ == "__main__":
    asyncio.run(main())
