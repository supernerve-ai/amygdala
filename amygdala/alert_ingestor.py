"""SPL query and alert ingestion from Splunk via MCP."""

import os
import logging
from typing import List

from .mcp_client import MCPClient

logger = logging.getLogger(__name__)

DEFAULT_SPL_QUERY = 'index=main sourcetype=alert | head 100'


class AlertIngestor:
    """Ingests security alerts from Splunk using SPL queries."""

    def __init__(self):
        self.mcp = MCPClient()
        self.index = os.getenv("SPLUNK_INDEX", "main")

    async def fetch_alerts(self, spl_query: str = None) -> List[dict]:
        """Fetch alerts from Splunk via MCP tool call."""
        query = spl_query or DEFAULT_SPL_QUERY
        logger.info(f"Running SPL query: {query}")

        result = await self.mcp.call_tool(
            tool_name="splunk_search",
            arguments={
                "query": query,
                "earliest_time": "-15m",
                "latest_time": "now",
            },
        )

        alerts = result.get("results", [])
        logger.info(f"Ingested {len(alerts)} alerts from Splunk")
        return alerts
