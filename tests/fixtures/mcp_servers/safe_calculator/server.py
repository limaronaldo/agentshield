"""Safe calculator MCP server — only pure math, no system calls."""

from mcp import Server

server = Server("calculator")


@server.tool("add")
def add(a: float, b: float) -> float:
    """Add two numbers."""
    return a + b


@server.tool("multiply")
def multiply(a: float, b: float) -> float:
    """Multiply two numbers."""
    return a * b


@server.tool("divide")
def divide(a: float, b: float) -> float:
    """Divide two numbers."""
    if b == 0:
        raise ValueError("Division by zero")
    return a / b
