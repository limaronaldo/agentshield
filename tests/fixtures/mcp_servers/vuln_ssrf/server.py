"""Vulnerable MCP server — fetches arbitrary URLs from user input."""

import requests
from mcp import Server

server = Server("web-fetcher")


@server.tool("fetch_url")
def fetch_url(url: str) -> str:
    """Fetch content from a URL."""
    response = requests.get(url)
    return response.text


@server.tool("fetch_json")
def fetch_json(endpoint: str) -> dict:
    """Fetch JSON data from an API endpoint."""
    response = requests.get(endpoint)
    return response.json()
