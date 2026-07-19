"""
sentinel-harness · MCP Server
==============================
Exposes all 20 sentinel-harness tools as a standards-compliant MCP (Model Context
Protocol) server over **stdio**. Any MCP-compatible AI agent (Claude Code, Cursor,
Windsurf, custom agents) can connect and invoke the full detection-engineering
suite, security enrichment, and SecOps automation tools — zero integration code.

Usage
-----
::

    # Start the MCP server (stdio mode)
    sentinel mcp serve

    # Or directly:
    uv run python -m sentinel_harness.mcp_server

    # In Claude Code settings.json:
    {
      "mcpServers": {
        "sentinel": {
          "command": "sentinel",
          "args": ["mcp", "serve"]
        }
      }
    }

Architecture
------------
Each tool's ``handler(event, context) -> dict`` is wrapped as an MCP tool with:
- Tool name derived from the directory name (``sigma_yara_lint``, ``detection_audit``, etc.)
- Description from the module docstring's first line
- Input schema: a single JSON object parameter (``event``) — the same shape the
  handler already expects
- The ``context`` argument receives a minimal stub (tools are pure/deterministic)

The server imports tools lazily at startup from ``tools/*/handler.py`` using the
same registry discovery as ``sentinel_harness/cli.py``.

Dependencies
------------
Requires ``mcp`` (the reference Python SDK). Added as an optional extra:
``pip install sentinel-harness[mcp]``.
"""
from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

# Discover the tools directory relative to this file or the repo root.
_THIS_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _THIS_DIR.parent
_TOOLS_DIR = _REPO_ROOT / "tools"

# Minimal context stub — tools are pure/deterministic, they don't use context.
_STUB_CONTEXT: Any = None


def _discover_tools() -> Dict[str, Dict[str, Any]]:
    """Walk tools/ and import each handler module. Returns {name: {module, description}}."""
    tools: Dict[str, Dict[str, Any]] = {}
    if not _TOOLS_DIR.is_dir():
        return tools

    for entry in sorted(_TOOLS_DIR.iterdir()):
        handler_path = entry / "handler.py"
        if not handler_path.is_file():
            continue

        tool_name = entry.name
        try:
            spec = importlib.util.spec_from_file_location(
                f"tools.{tool_name}.handler", str(handler_path)
            )
            if spec is None or spec.loader is None:
                continue
            mod = importlib.util.module_from_spec(spec)
            sys.modules[f"tools.{tool_name}.handler"] = mod
            spec.loader.exec_module(mod)

            if not hasattr(mod, "handler"):
                continue

            doc = (mod.__doc__ or "").strip().split("\n")[0]
            tools[tool_name] = {"module": mod, "description": doc}
        except Exception as exc:
            tools[tool_name] = {"module": None, "description": f"[LOAD ERROR: {exc}]"}

    return tools


def _tool_input_schema(tool_name: str) -> Dict[str, Any]:
    """Generate a permissive JSON Schema for the tool's event parameter."""
    return {
        "type": "object",
        "properties": {
            "event": {
                "type": "object",
                "description": f"Input event for the {tool_name} tool. Pass the tool-specific parameters as keys.",
            }
        },
        "required": ["event"],
    }


def _invoke_tool(tool_name: str, mod: Any, event: Dict[str, Any]) -> str:
    """Call the handler and return JSON-serialized result."""
    try:
        result = mod.handler(event, _STUB_CONTEXT)
        return json.dumps(result, indent=2, default=str)
    except Exception as exc:
        return json.dumps({"error": type(exc).__name__, "message": str(exc)})


def create_server():
    """Create and configure the MCP server with all sentinel tools registered."""
    try:
        from mcp.server import Server
        from mcp.server.stdio import stdio_server
        from mcp.types import Tool, TextContent
    except ImportError:
        print(
            "ERROR: The 'mcp' package is required for MCP server mode.\n"
            "Install it with: pip install sentinel-harness[mcp]\n"
            "Or: pip install mcp",
            file=sys.stderr,
        )
        sys.exit(1)

    server = Server("sentinel-harness")
    tools_registry = _discover_tools()

    @server.list_tools()
    async def list_tools() -> List[Tool]:
        """Return all available sentinel tools as MCP tool definitions."""
        result = []
        for name, info in tools_registry.items():
            if info["module"] is None:
                continue
            result.append(
                Tool(
                    name=name,
                    description=info["description"],
                    inputSchema=_tool_input_schema(name),
                )
            )
        return result

    @server.call_tool()
    async def call_tool(name: str, arguments: Dict[str, Any]) -> List[TextContent]:
        """Dispatch an MCP tool call to the matching sentinel handler."""
        if name not in tools_registry:
            return [TextContent(
                type="text",
                text=json.dumps({"error": "unknown_tool", "message": f"Tool {name!r} not found. Available: {sorted(tools_registry)}"}),
            )]

        info = tools_registry[name]
        if info["module"] is None:
            return [TextContent(
                type="text",
                text=json.dumps({"error": "load_error", "message": info["description"]}),
            )]

        event = arguments.get("event", arguments)
        output = _invoke_tool(name, info["module"], event)
        return [TextContent(type="text", text=output)]

    return server, stdio_server


async def main():
    """Run the MCP server over stdio."""
    server, run_stdio = create_server()
    async with run_stdio(server.create_initialization_options()) as streams:
        await server.run(
            streams[0],
            streams[1],
            server.create_initialization_options(),
        )


def run():
    """Synchronous entry point for the CLI."""
    import asyncio
    asyncio.run(main())


if __name__ == "__main__":
    run()
