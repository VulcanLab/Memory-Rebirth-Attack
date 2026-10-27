"""LLM-free seeder for the MCP experiment.

Writes the v1(REVOKED)/v2(ACTIVE) competing edges directly into the same
group_id + Neo4j the MCP server uses, with the SAME embedder (Ollama nomic,
768-dim) so the server's vector search matches. Lets us exercise the MCP
`search_memory_facts` tool without the LLM extraction path (e.g. when the
Gemini daily quota is exhausted).
"""

import asyncio

from attack_deterministic import seed
from mwe_common import GROUP_ID, build_graphiti, provider_banner


async def main():
    graphiti = build_graphiti(with_llm=False)
    print(f'[seed] {provider_banner()}')
    try:
        await graphiti.build_indices_and_constraints()
        v1, v2 = await seed(graphiti)
        print(f'[seed] v1(REVOKED) uuid={v1.uuid}')
        print(f'[seed] v2(ACTIVE)  uuid={v2.uuid}')
        print(f'[seed] done into group_id={GROUP_ID}')
    finally:
        await graphiti.close()


if __name__ == '__main__':
    asyncio.run(main())
