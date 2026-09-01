#!/usr/bin/env bash
# Start the Graphiti MCP server for the Memory Rebirth Attack e2e.
# LLM=Gemini (safety off), EMBED=Ollama nomic (768), DB=Neo4j :7688, HTTP :8000.
# Uses our editable/patched graphiti_core. Config: mcp_server/.env + config/config.yaml.
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"      # tools/
MWE="$(cd "$HERE/.." && pwd)"              # project root (mwe/)
SRV="$MWE/../graphiti-main/graphiti-main/mcp_server"

cd "$SRV"
echo "### uv sync (mcp_server, no dev; google-genai comes via graphiti-core extra)"
uv sync --no-dev 2>&1 | tail -3

# Inject the non-invasive MWE patches (Gemini safety-off + call throttle) into the
# server process via sitecustomize on PYTHONPATH. Graphiti source stays pristine.
# PYTHONPATH needs the project root (finds sitecustomize.py) + core/ (finds mwe_patch).
export PYTHONPATH="$MWE:$MWE/core${PYTHONPATH:+:$PYTHONPATH}"

echo "### starting MCP server on http://127.0.0.1:8000/mcp/"
exec uv run --no-dev python src/graphiti_mcp_server.py \
  --config config/config.yaml \
  --transport http --host 127.0.0.1 --port 8000 \
  --llm-provider gemini --embedder-provider openai --database-provider neo4j \
  --model gemini-flash-latest --embedder-model nomic-embed-text \
  --group-id mwe_rebirth
