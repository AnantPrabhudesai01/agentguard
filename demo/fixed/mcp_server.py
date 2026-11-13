"""Demo support agent - remediated twin of ../vulnerable/mcp_server.py.

Every sink now has an explicit control: allowlist, parameterized query,
argument list, environment-backed secret, or bounded path.
"""

import ast
import os
import sqlite3
import subprocess
from pathlib import Path
from urllib.parse import urlparse

import requests
from mcp.server.fastmcp import FastMCP

DB_PATH = "tickets.db"
ATTACHMENTS = Path(os.environ.get("ATTACHMENT_DIR", "./attachments")).resolve()
ALLOWED_STATUS_HOSTS = {"status.example.com"}
ALLOWED_DIAGNOSTIC_HOSTS = {"127.0.0.1", "localhost"}
SUPPORT_API_KEY = os.environ.get("SUPPORT_API_KEY", "")

mcp = FastMCP("demo-support")


def _eval_node(node: ast.AST) -> float:
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return float(node.value)
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
        value = _eval_node(node.operand)
        return value if isinstance(node.op, ast.UAdd) else -value
    if isinstance(node, ast.BinOp) and isinstance(
        node.op, (ast.Add, ast.Sub, ast.Mult, ast.Div, ast.Mod, ast.Pow)
    ):
        left = _eval_node(node.left)
        right = _eval_node(node.right)
        if isinstance(node.op, ast.Add):
            return left + right
        if isinstance(node.op, ast.Sub):
            return left - right
        if isinstance(node.op, ast.Mult):
            return left * right
        if isinstance(node.op, ast.Div):
            return left / right
        if isinstance(node.op, ast.Mod):
            return left % right
        return left**right
    raise ValueError("unsupported expression")


@mcp.tool()
def calculate(expression: str) -> str:
    """Evaluate arithmetic using a small AST allowlist."""
    tree = ast.parse(expression, mode="eval")
    return str(_eval_node(tree.body))


@mcp.tool()
def run_diagnostic(host: str) -> str:
    """Ping an allowlisted host for the customer."""
    if host not in ALLOWED_DIAGNOSTIC_HOSTS:
        raise ValueError("host not allowed")
    result = subprocess.run(
        ["ping", "-n", "1", host],
        shell=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    return result.stdout


@mcp.tool()
def lookup_ticket(ticket_id: str) -> str:
    """Look up a support ticket with a parameterized query."""
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute(
        "SELECT id, subject FROM tickets WHERE id = ?", (ticket_id,)
    ).fetchall()
    conn.close()
    return str(rows)


@mcp.tool()
def read_attachment(filename: str) -> str:
    """Read an attachment inside the configured attachment directory."""
    target = (ATTACHMENTS / filename).resolve()
    if not target.is_relative_to(ATTACHMENTS):
        raise ValueError("path outside attachment directory")
    return target.read_text(encoding="utf-8")


@mcp.tool()
def fetch_url(url: str) -> str:
    """Fetch an allowlisted HTTPS status page."""
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_STATUS_HOSTS:
        raise ValueError("url not allowed")
    return requests.get(url, timeout=15).text


if __name__ == "__main__":
    mcp.run()
