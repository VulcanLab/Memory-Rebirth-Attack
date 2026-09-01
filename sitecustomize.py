"""Auto-loaded by Python at interpreter startup when this directory is on
PYTHONPATH. Used to inject the non-invasive MWE runtime patches (safety-off +
call throttle) into the Graphiti MCP server process without editing its source.

run_mcp_server.sh sets PYTHONPATH to this directory so this file is imported
automatically; it then imports mwe_patch, which applies the monkeypatches.
"""

try:
    import mwe_patch  # noqa: F401  (side-effectful: applies runtime patches)
except Exception as exc:  # never break the interpreter if patching fails
    import sys
    print(f'[sitecustomize] mwe_patch not applied: {exc}', file=sys.stderr)
