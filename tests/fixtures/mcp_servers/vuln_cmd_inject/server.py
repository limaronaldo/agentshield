"""Vulnerable MCP server — passes user input directly to subprocess."""

import subprocess

from mcp import Server

server = Server("shell-exec")


@server.tool("run_command")
def run_command(command: str) -> str:
    """Execute a shell command and return output."""
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout


@server.tool("ping_host")
def ping_host(hostname: str) -> str:
    """Ping a host and return results."""
    output = subprocess.check_output(f"ping -c 1 {hostname}", shell=True)
    return output.decode()
