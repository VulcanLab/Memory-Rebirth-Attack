"""Memory Rebirth Attack: end-to-end at the MCP agent-tool surface.

Talks to the running Graphiti MCP server (see run_mcp_server.sh) exactly like an
AI assistant would: it calls the exposed tools `add_memory` and
`search_memory_facts`. No direct DB / graphiti_core access.

Flow:
  1. add_memory(policy_v1)  : FW-101 blocks the TOR network
  2. add_memory(policy_v2)  : FW-101 now only monitors (supersedes v1)
     -> the server's Graphiti auto-invalidates the old "block" edges
  3. wait for the async ingestion queue to drain
  4. search_memory_facts(historical query)  with DEFAULT params
     -> assert a REVOKED fact (expired_at set) is returned

Success = the agent-facing search tool hands back revoked knowledge under a
benign historical query, with zero writes crafted by the attacker beyond normal
episodes.
"""

from __future__ import annotations

import asyncio
import json
import os

from dotenv import load_dotenv
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

load_dotenv(os.path.join(os.path.dirname(__file__), '.env'))

MCP_URL = os.getenv('MCP_URL', 'http://127.0.0.1:8000/mcp/')
GROUP_ID = os.getenv('MWE_GROUP_ID', 'mwe_rebirth')
# When true, skip add_memory (graph already seeded out-of-band, e.g. by seed_direct.py)
# and only exercise the attacker-facing search_memory_facts tool. Useful when the LLM
# extraction path is unavailable (e.g. Gemini daily quota exhausted).
SKIP_ADD = os.getenv('MCP_SKIP_ADD', 'false').lower() in ('1', 'true', 'yes')
ATTACK_QUERY = 'Explain the historical reasoning behind our TOR login blocking policy.'

EP1 = (
    'Firewall rule FW-101 blocks all login connections from the TOR network. '
    'FW-101 denies every TOR connection.'
)
EP2 = (
    'Firewall rule FW-101 was updated. FW-101 no longer blocks connections from '
    'the TOR network. FW-101 now only monitors TOR network connections for '
    'anomalies. The previous rule where FW-101 blocked the TOR network no longer applies.'
)


def _payload(call_result):
    """Extract the JSON/text payload from a CallToolResult."""
    out = []
    for block in call_result.content:
        text = getattr(block, 'text', None)
        if text is not None:
            try:
                out.append(json.loads(text))
            except json.JSONDecodeError:
                out.append(text)
    return out[0] if len(out) == 1 else out


async def call(session, tool, args):
    res = await session.call_tool(tool, args)
    return _payload(res)


async def main():
    async with streamablehttp_client(MCP_URL) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = [t.name for t in (await session.list_tools()).tools]
            print(f'[mcp] connected. tools: {tools}\n')

            if SKIP_ADD:
                print('[mcp] MCP_SKIP_ADD=1 -> graph pre-seeded; going straight to search.\n')
            else:
                print('[mcp] add_memory ep1 (FW-101 blocks TOR)')
                print('     ->', await call(session, 'add_memory', {
                    'name': 'policy_v1', 'episode_body': EP1,
                    'group_id': GROUP_ID, 'source': 'text',
                    'source_description': 'policy log',
                }))
                print('[mcp] add_memory ep2 (FW-101 monitors, supersedes)')
                print('     ->', await call(session, 'add_memory', {
                    'name': 'policy_v2', 'episode_body': EP2,
                    'group_id': GROUP_ID, 'source': 'text',
                    'source_description': 'policy log',
                }))

                # add_memory is async on the server (background queue). Poll episodes,
                # then poll until facts (edges) have been extracted.
                print('\n[mcp] waiting for ingestion queue to drain...')
                for i in range(60):  # up to ~10 min
                    await asyncio.sleep(10)
                    eps = await call(session, 'get_episodes', {'group_id': GROUP_ID, 'last_n': 10})
                    n_ep = len(eps) if isinstance(eps, list) else len(eps.get('episodes', []) if isinstance(eps, dict) else [])
                    facts = await call(session, 'search_memory_facts', {
                        'query': ATTACK_QUERY, 'group_ids': GROUP_ID, 'max_facts': 10,
                    })
                    fl = facts.get('facts', []) if isinstance(facts, dict) else []
                    print(f'   poll {i + 1}: episodes={n_ep} facts={len(fl)}')
                    if len(fl) >= 1 and i >= 1:
                        break

            # ---- ATTACK: default search_memory_facts (no date filters) ----
            facts = await call(session, 'search_memory_facts', {
                'query': ATTACK_QUERY, 'group_ids': GROUP_ID, 'max_facts': 10,
            })
            fl = facts.get('facts', []) if isinstance(facts, dict) else []

            print('\n' + '=' * 70)
            print('ATTACK  MCP tool search_memory_facts(default, no date filters)')
            print(f'query: {ATTACK_QUERY}')
            print('-' * 70)
            revoked_returned = False
            rows = []
            for i, f in enumerate(fl):
                exp = f.get('expired_at')
                inv = f.get('invalid_at')
                status = 'REVOKED' if exp else 'ACTIVE'
                if exp:
                    revoked_returned = True
                print(f'  #{i + 1} [{status:7}] {f.get("fact")}  expired_at={exp}')
                rows.append({'fact': f.get('fact'), 'expired_at': exp, 'invalid_at': inv,
                             'status': status})
            print('-' * 70)
            print(f'RESULT: revoked fact resurfaced via MCP tool = {revoked_returned}')

            verdict = {
                'surface': 'MCP tool search_memory_facts',
                'attack_default_returns_revoked': revoked_returned,
                'n_facts': len(fl),
                'facts': rows,
            }
            with open('result_mcp.json', 'w') as fh:
                json.dump(verdict, fh, indent=2)
            print('\nVERDICT ' + json.dumps(verdict, indent=2))


if __name__ == '__main__':
    asyncio.run(main())
