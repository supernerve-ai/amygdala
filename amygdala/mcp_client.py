"""Splunk MCP connection client."""

import os
import logging

import httpx

logger = logging.getLogger(__name__)


class MCPClient:
    """Client for connecting to Splunk via MCP server."""

    def __init__(self):
        self.server_url = os.getenv("MCP_SERVER_URL", "http://localhost:8080")
        self.timeout = int(os.getenv("MCP_TIMEOUT", "30"))
        self._client = httpx.AsyncClient(timeout=self.timeout)

    async def call_tool(self, tool_name: str, arguments: dict) -> dict:
        """Call an MCP tool on the server."""
        payload = {
            "tool": tool_name,
            "arguments": arguments,
        }
        response = await self._client.post(
            f"{self.server_url}/tools/call",
            json=payload,
        )
        response.raise_for_status()
        return response.json()

    async def close(self):
        """Close the HTTP client."""
        await self._client.aclose()
