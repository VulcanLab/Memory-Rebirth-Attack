"""Wipe the MWE group_id partition so runs are repeatable. Scoped delete only."""

import asyncio

from mwe_common import GROUP_ID, build_graphiti


async def main():
    graphiti = build_graphiti(with_llm=False)
    try:
        q = "MATCH (n {group_id: $gid}) DETACH DELETE n"
        await graphiti.driver.execute_query(q, gid=GROUP_ID)
        print(f"[reset] cleared group_id={GROUP_ID}")
    finally:
        await graphiti.close()


if __name__ == "__main__":
    asyncio.run(main())
