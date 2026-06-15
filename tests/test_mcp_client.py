"""Tests for the MCP client."""

import pytest

from amygdala.mcp_client import MCPClient


class TestMCPClient:
    """Tests for MCPClient initialization and configuration."""

    def test_default_initialization(self):
        client = MCPClient()
        assert client.server_url == "http://localhost:8080"
        assert client.timeout == 30

    def test_custom_server_url(self, monkeypatch):
        monkeypatch.setenv("MCP_SERVER_URL", "http://custom-mcp:9090")
        client = MCPClient()
        assert client.server_url == "http://custom-mcp:9090"

    def test_custom_timeout(self, monkeypatch):
        monkeypatch.setenv("MCP_TIMEOUT", "60")
        client = MCPClient()
        assert client.timeout == 60
