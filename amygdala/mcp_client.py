"""Splunk MCP connection client with retry logic and error handling."""

import os
import logging
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

# Default retry configuration
MAX_RETRIES = 3
RETRY_BACKOFF = [1, 3, 5]  # seconds between retries


class MCPConnectionError(Exception):
    """Raised when MCP server is unreachable after retries."""
    pass


class MCPToolError(Exception):
    """Raised when an MCP tool call returns an error."""
    pass


class MCPClient:
    """Client for connecting to Splunk via MCP server.

    Handles retries, timeouts, and structured error reporting.
    """

    def __init__(self):
        self.server_url = os.getenv("MCP_SERVER_URL", "http://localhost:8080")
        self.timeout = int(os.getenv("MCP_TIMEOUT", "30"))
        self.max_retries = int(os.getenv("MCP_MAX_RETRIES", str(MAX_RETRIES)))
        self._client: Optional[httpx.AsyncClient] = None

    def _get_client(self) -> httpx.AsyncClient:
        """Get or create the async HTTP client."""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(self.timeout, connect=10),
                headers={"Content-Type": "application/json"},
            )
        return self._client

    async def call_tool(self, tool_name: str, arguments: dict) -> dict:
        """Call an MCP tool on the server with retry logic.

        Args:
            tool_name: Name of the MCP tool to invoke (e.g., 'splunk_search')
            arguments: Tool-specific arguments dict

        Returns:
            Parsed JSON response from the MCP server

        Raises:
            MCPConnectionError: If server is unreachable after all retries
            MCPToolError: If the tool returns an error response
        """
        import asyncio

        payload = {
            "tool": tool_name,
            "arguments": arguments,
        }

        last_error = None
        client = self._get_client()

        for attempt in range(self.max_retries):
            try:
                logger.debug(f"MCP call attempt {attempt + 1}/{self.max_retries}: {tool_name}")
                response = await client.post(
                    f"{self.server_url}/tools/call",
                    json=payload,
                )

                if response.status_code == 200:
                    result = response.json()
                    # Check for tool-level errors in response
                    if "error" in result:
                        raise MCPToolError(
                            f"MCP tool '{tool_name}' returned error: {result['error']}"
                        )
                    logger.debug(f"MCP call succeeded: {tool_name}")
                    return result

                elif response.status_code >= 500:
                    # Server error — retry
                    last_error = f"Server error {response.status_code}: {response.text[:200]}"
                    logger.warning(f"MCP server error (attempt {attempt + 1}): {last_error}")

                elif response.status_code == 429:
                    # Rate limited — retry with longer backoff
                    last_error = "Rate limited by MCP server"
                    logger.warning(f"MCP rate limited (attempt {attempt + 1})")

                else:
                    # Client error — don't retry
                    raise MCPToolError(
                        f"MCP tool call failed with status {response.status_code}: "
                        f"{response.text[:200]}"
                    )

            except httpx.ConnectError as e:
                last_error = f"Connection failed: {e}"
                logger.warning(f"MCP connection error (attempt {attempt + 1}): {e}")

            except httpx.TimeoutException as e:
                last_error = f"Request timed out: {e}"
                logger.warning(f"MCP timeout (attempt {attempt + 1}): {e}")

            except (MCPToolError, MCPConnectionError):
                raise

            except Exception as e:
                last_error = f"Unexpected error: {e}"
                logger.error(f"MCP unexpected error (attempt {attempt + 1}): {e}")

            # Wait before retry (skip wait on last attempt)
            if attempt < self.max_retries - 1:
                backoff = RETRY_BACKOFF[min(attempt, len(RETRY_BACKOFF) - 1)]
                logger.debug(f"Retrying in {backoff}s...")
                await asyncio.sleep(backoff)

        raise MCPConnectionError(
            f"Failed to reach MCP server after {self.max_retries} attempts. "
            f"Last error: {last_error}"
        )

    async def health_check(self) -> bool:
        """Check if the MCP server is reachable.

        Returns:
            True if server responds, False otherwise.
        """
        try:
            client = self._get_client()
            response = await client.get(f"{self.server_url}/health")
            return response.status_code == 200
        except Exception:
            return False

    async def close(self):
        """Close the HTTP client and release resources."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None
