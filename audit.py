#!/usr/bin/env python3
"""AgentGuard - static security audit for AI agent and MCP codebases.

Zero third-party dependencies. Python 3.10+.

Usage:
    python audit.py scan <path> --format md --output report.md
    python audit.py scan <path> --format json
    python audit.py scan <path> --fail-on high

This is a static analysis tool, not a penetration test. It finds patterns
that commonly become real vulnerabilities in agent/MCP deployments.
"""

from __future__ import annotations

import argparse
import ast
import html
import json
import os
import re
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path

SEVERITY_WEIGHT = {"critical": 40, "high": 20, "medium": 8, "low": 2, "info": 0}
SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

SKIP_DIRS = {
    ".git", "node_modules", ".venv", "venv", "env", "__pycache__",
    "dist", "build", ".next", "target", "vendor", ".idea", ".vscode",
    ".mypy_cache", ".pytest_cache", "site-packages",
}

# Test fixtures are full of fake secrets, localhost URLs, and deliberate
# shell calls. They are skipped by default; use --include-tests to scan them.
TEST_DIRS = {"test", "tests", "__tests__", "testdata", "fixtures", "e2e", "cypress", "spec", "specs"}
TEST_FILE_RE = re.compile(r"(?i)(^test_.*\.py$|.*_test\.py$|^conftest\.py$|.*\.(test|spec)\.[a-z0-9]+$)")

TEXT_EXTS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".json", ".yaml", ".yml",
    ".toml", ".md", ".txt", ".env", ".sh", ".ps1", ".dockerfile",
}

CONFIG_NAMES = {
    "mcp.json", "mcp_config.json", "claude_desktop_config.json",
    ".mcp.json", "opencode.json", "docker-compose.yml",
    "docker-compose.yaml", "compose.yml", "compose.yaml",
    "requirements.txt", "package.json", "Dockerfile",
}

MCP_NAMES = {
    "mcp.json", "mcp_config.json", "claude_desktop_config.json",
    ".mcp.json", "opencode.json",
}

# --- secret patterns -------------------------------------------------------

SECRET_PATTERNS = [
    ("SECRET-001", "critical", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}"), "OpenAI-style API key"),
    ("SECRET-002", "critical", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}"), "GitHub token"),
    ("SECRET-003", "critical", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}"), "GitHub fine-grained token"),
    ("SECRET-004", "critical", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS access key"),
    ("SECRET-005", "critical", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}"), "Slack token"),
    ("SECRET-006", "critical", re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----"), "Private key"),
    ("SECRET-007", "high", re.compile(r"(?i)\b(?:api[_-]?key|secret|token|password|passwd|pwd)\s*[:=]\s*[\"']([^\"']{8,})[\"']"), "Hardcoded credential"),
    ("SECRET-008", "high", re.compile(r"(?im)^\s*[A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD)\s*=\s*([^\s#]{8,})\s*$"), "Credential in .env-style file"),
]

PLACEHOLDER_MARKERS = (
    "your", "example", "changeme", "change-me", "placeholder", "xxx",
    "redacted", "dummy", "fake", "test-key", "${", "{{", "<", ">",
    "os.environ", "process.env", "env.", "env(", "getenv",
)

# --- prompt injection patterns --------------------------------------------

PROMPT_PATTERNS = [
    ("PROMPT-001", "high", re.compile(r"(?i)ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions"), "Instruction-override phrase"),
    ("PROMPT-002", "high", re.compile(r"(?i)disregard\s+(?:all\s+)?(?:previous|prior|above)"), "Instruction-override phrase"),
    ("PROMPT-003", "high", re.compile(r"(?i)do\s+not\s+(?:tell|inform|alert|notify)\s+(?:the\s+)?user"), "Hidden-action phrase"),
    ("PROMPT-004", "high", re.compile(r"(?i)send\s+(?:all\s+)?(?:data|memories|secrets|credentials|keys)\s+to"), "Exfiltration phrase"),
    ("PROMPT-005", "medium", re.compile(r"(?i)reveal\s+(?:the\s+)?(?:system|hidden)\s+prompt"), "Prompt-extraction phrase"),
    ("PROMPT-006", "medium", re.compile(r"(?i)you\s+are\s+now\s+(?:a|an|the)\s+"), "Role-override phrase"),
]

HIDDEN_CHARS = {
    "\u200b", "\u200c", "\u200d", "\u2060", "\ufeff",
    "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",
}

AUTH_MARKERS = ("auth", "token", "api_key", "apikey", "check_auth", "verify", "current_user", "depends")
RATE_MARKERS = ("rate_limit", "ratelimit", "limiter", "slowapi", "throttle")


@dataclass
class Finding:
    rule_id: str
    severity: str
    category: str
    title: str
    file: str
    line: int
    evidence: str
    remediation: str

    def to_dict(self) -> dict:
        return asdict(self)


class Scanner:
    def __init__(self, root: str | Path, excludes: list[str] | None = None,
                 include_tests: bool = False):
        self.root = Path(root).resolve()
        self.excludes = [e.lower().replace("\\", "/") for e in (excludes or [])]
        self.include_tests = include_tests
        self.findings: list[Finding] = []
        self.files_scanned = 0
        self.errors: list[str] = []
        self._seen: set[tuple] = set()
        self.tool_params: set[str] = set()

    # --- helpers -----------------------------------------------------------
    def rel(self, path: Path) -> str:
        try:
            return str(path.resolve().relative_to(self.root)).replace("\\", "/")
        except ValueError:
            return str(path)

    def excluded(self, path: Path) -> bool:
        text = str(path).lower().replace("\\", "/")
        return any(e in text for e in self.excludes)

    def add(self, rule_id: str, severity: str, category: str, title: str,
            path: Path, line: int, evidence: str, remediation: str,
            line_text: str = "") -> None:
        if "agentguard:ignore" in line_text.lower():
            return
        key = (rule_id, self.rel(path), line)
        if key in self._seen:
            return
        self._seen.add(key)
        self.findings.append(Finding(
            rule_id=rule_id,
            severity=severity,
            category=category,
            title=title,
            file=self.rel(path),
            line=line,
            evidence=evidence.strip()[:240],
            remediation=remediation,
        ))

    def walk(self):
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = [
                d for d in dirnames
                if d not in SKIP_DIRS
                and (self.include_tests or d.lower() not in TEST_DIRS)
                and not self.excluded(Path(dirpath) / d)
            ]
            for name in filenames:
                path = Path(dirpath) / name
                if self.excluded(path):
                    continue
                if not self.include_tests and TEST_FILE_RE.match(name):
                    continue
                try:
                    if path.stat().st_size > 1_000_000:
                        continue
                except OSError:
                    continue
                if name in CONFIG_NAMES or path.suffix.lower() in TEXT_EXTS:
                    yield path

    def scan(self) -> list[Finding]:
        if not self.root.exists():
            raise SystemExit(f"Path not found: {self.root}")
        for path in self.walk():
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError as exc:
                self.errors.append(f"{path}: {exc}")
                continue
            self.files_scanned += 1
            self.scan_text(path, text)
        self.findings.sort(key=lambda f: (-SEVERITY_RANK[f.severity], f.file, f.line))
        return self.findings

    # --- generic text rules -------------------------------------------------
    def scan_text(self, path: Path, text: str) -> None:
        lines = text.splitlines()
        for i, line in enumerate(lines, 1):
            self.scan_secrets(path, i, line)
            self.scan_prompt(path, i, line)
            if line.count("\u200b") or any(ch in line for ch in HIDDEN_CHARS):
                self.add("PROMPT-007", "medium", "Prompt injection",
                         "Hidden Unicode character in text",
                         path, i, self.redact(line),
                         "Remove zero-width/bidi characters; they can hide instructions from humans.",
                         line)
        suffix = path.suffix.lower()
        if suffix == ".py":
            self.scan_python(path, text)
        elif suffix in {".js", ".jsx", ".ts", ".tsx"}:
            self.scan_js(path, text)
        if path.name in MCP_NAMES or (suffix == ".json" and '"mcpservers"' in text.lower()):
            self.scan_mcp_config(path, text)
        if path.name == "requirements.txt":
            self.scan_requirements(path, text)
        if path.name == "package.json":
            self.scan_package_json(path, text)
        if path.name in {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}:
            self.scan_compose(path, text)

    def scan_secrets(self, path: Path, line_no: int, line: str) -> None:
        found_specific = False
        for rule_id, severity, pattern, title in SECRET_PATTERNS:
            for match in pattern.finditer(line):
                value = match.group(1) if match.lastindex else match.group(0)
                if self.is_placeholder(value):
                    continue
                if rule_id == "SECRET-008" and found_specific:
                    continue
                if rule_id == "SECRET-007":
                    found_specific = True
                self.add(rule_id, severity, "Secrets", title,
                         path, line_no, self.redact(line),
                         "Remove the secret from source, rotate it, and load it from a secret manager or environment variable.",
                         line)

    def scan_prompt(self, path: Path, line_no: int, line: str) -> None:
        for rule_id, severity, pattern, title in PROMPT_PATTERNS:
            if pattern.search(line):
                self.add(rule_id, severity, "Prompt injection", title,
                         path, line_no, self.redact(line),
                         "Treat tool descriptions and retrieved text as untrusted. Strip instruction-like content and keep it outside the system prompt.",
                         line)
        if "<!--" in line and re.search(r"(?i)description[\"']?\s*[:=]|tool[_-]?description", line):
            self.add("PROMPT-008", "medium", "Prompt injection",
                     "HTML comment inside a tool description",
                     path, line_no, self.redact(line),
                     "Strip HTML comments from tool metadata; hidden text can carry instructions.",
                     line)
        if re.search(r"(?i)description[\"']?\s*[:=]\s*[\"'][^\"']*https?://", line):
            self.add("PROMPT-009", "low", "Prompt injection",
                     "URL inside a tool description",
                     path, line_no, self.redact(line),
                     "Review outbound URLs in tool metadata. An agent may fetch or trust them.",
                     line)

    def is_placeholder(self, value: str) -> bool:
        low = value.lower()
        return any(marker in low for marker in PLACEHOLDER_MARKERS)

    def redact(self, text: str) -> str:
        text = re.sub(r"\s+", " ", text.strip())
        # Redact quoted values on credential-like keys first, then unquoted.
        text = re.sub(
            r"(?i)((?:api[_-]?key|secret|token|password|passwd|pwd)\s*[:=]\s*[\"'])([^\"']+)([\"'])",
            r"\1***\3",
            text,
        )
        text = re.sub(
            r"(?i)((?:api[_-]?key|secret|token|password|passwd|pwd)\s*[:=]\s*)([^\s#]+)",
            r"\1***",
            text,
        )
        for pattern in (r"sk-(?:proj-)?[A-Za-z0-9_-]{20,}",
                        r"gh[pousr]_[A-Za-z0-9]{20,}",
                        r"github_pat_[A-Za-z0-9_]{20,}",
                        r"AKIA[0-9A-Z]{16}",
                        r"xox[baprs]-[A-Za-z0-9-]{10,}"):
            text = re.sub(pattern, lambda m: m.group(0)[:4] + "..." + m.group(0)[-4:], text)
        return text[:240]

    # --- Python AST rules ---------------------------------------------------
    def scan_python(self, path: Path, text: str) -> None:
        try:
            tree = ast.parse(text)
        except SyntaxError as exc:
            self.errors.append(f"{self.rel(path)}:{exc.lineno}: {exc.msg}")
            return
        lines = text.splitlines()
        self.tool_params = self.collect_tool_params(tree)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                self.check_call(path, text, lines, node)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.check_function_auth(path, lines, node)

    def collect_tool_params(self, tree: ast.AST) -> set[str]:
        """Parameters of @tool/@mcp-decorated functions are untrusted input.

        Internal helper parameters are not, which avoids flagging every
        function that happens to take a variable called ``path``.
        """
        params: set[str] = set()
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            is_tool = False
            for dec in node.decorator_list:
                target = dec.func if isinstance(dec, ast.Call) else dec
                name = self.call_name(target).lower()
                if "tool" in name or "mcp" in name:
                    is_tool = True
                    break
            if is_tool:
                params.update(a.arg for a in node.args.args)
                params.update(a.arg for a in node.args.kwonlyargs)
        return params

    def call_name(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            parent = self.call_name(node.value)
            return f"{parent}.{node.attr}" if parent else node.attr
        if isinstance(node, ast.Call):
            return self.call_name(node.func)
        if isinstance(node, ast.Subscript):
            return self.call_name(node.value)
        return ""

    def is_tainted(self, node: ast.AST) -> bool:
        strong = ("input", "request", "req.", "params", "query", "body",
                  "payload", "upload", "attachment", "filename", "user", "tool")
        if isinstance(node, ast.Name):
            if node.id in self.tool_params:
                return True
            name = node.id.lower()
        elif isinstance(node, ast.Attribute):
            name = self.call_name(node).lower()
        elif isinstance(node, ast.Subscript):
            name = self.call_name(node.value).lower()
        elif isinstance(node, (ast.JoinedStr, ast.BinOp)):
            return True
        elif isinstance(node, ast.Call):
            name = self.call_name(node.func).lower()
            return any(t in name for t in ("input", "args", "json", "form", "query", "params"))
        else:
            return False
        return any(t in name for t in strong)

    def line_text(self, lines: list[str], node: ast.AST) -> str:
        try:
            return lines[node.lineno - 1]
        except (IndexError, AttributeError):
            return ""

    def check_call(self, path: Path, text: str, lines: list[str], node: ast.Call) -> None:
        name = self.call_name(node.func)
        short = name.split(".")[-1]
        source = ast.get_source_segment(text, node) or name
        line = getattr(node, "lineno", 1)
        lt = self.line_text(lines, node)
        tainted = any(self.is_tainted(a) for a in node.args)
        kwargs = {kw.arg: kw.value for kw in node.keywords if kw.arg}
        # Validation is often done a few lines before the sink; use a small
        # backward window so remediated code does not get flagged forever.
        context = "\n".join(lines[max(0, line - 25):line])

        if name in {"eval", "exec", "compile"} or short in {"eval", "exec"}:
            self.add("EXEC-001", "critical" if tainted else "high", "Execution",
                     f"Dynamic code execution via {name or short}()",
                     path, line, self.redact(source),
                     "Never pass model output, tool arguments, or user input to eval/exec. Use a parser or an allowlist.",
                     lt)
        elif name in {"os.system", "os.popen"} or short in {"system", "popen"} and name.startswith("os."):
            self.add("EXEC-002", "high", "Execution",
                     f"Shell execution via {name}()",
                     path, line, self.redact(source),
                     "Use subprocess with a list of arguments and shell=False; allowlist commands.",
                     lt)
        elif name.startswith("subprocess.") and self.is_true(kwargs.get("shell")):
            self.add("EXEC-003", "high", "Execution",
                     "subprocess call with shell=True",
                     path, line, self.redact(source),
                     "Set shell=False and pass an argument list. Never interpolate tool input into a shell command.",
                     lt)
        elif name in {"pickle.loads", "yaml.load"} or short in {"loads", "load"} and name.startswith("yaml."):
            if name.startswith("yaml.") and self.is_safe_loader(kwargs.get("Loader")):
                return
            self.add("DESER-001", "high", "Deserialization",
                     f"Unsafe deserialization via {name}()",
                     path, line, self.redact(source),
                     "Use json or yaml.safe_load. Never unpickle data from an untrusted source.",
                     lt)
        elif short in {"open", "read_text", "read_bytes", "read"} and tainted:
            if not self.has_path_validation(context):
                self.add("PATH-001", "high", "Filesystem",
                         "File path built from tool/user input",
                         path, line, self.redact(source),
                         "Resolve the path and verify it stays inside an allowlisted base directory (is_relative_to).",
                         lt)
        elif short in {"urlopen", "get", "post", "request"} and tainted and (
            name.startswith(("requests.", "httpx.", "urllib.")) or short == "urlopen"
        ):
            if not self.has_url_validation(context):
                self.add("SSRF-001", "high", "Network",
                         "Outbound URL built from tool/user input",
                         path, line, self.redact(source),
                         "Parse the URL, require https, and allowlist hosts before making the request.",
                         lt)
        elif short in {"execute", "executemany"}:
            first = node.args[0] if node.args else None
            if isinstance(first, (ast.JoinedStr, ast.BinOp)):
                self.add("SQLI-001", "critical", "Injection",
                         "SQL query built with string formatting",
                         path, line, self.redact(source),
                         "Use parameterized queries (?, %s) and pass values separately.",
                         lt)
        elif short in {"print", "info", "debug", "warning", "error", "log"}:
            if re.search(r"(?i)(token|secret|password|api[_-]?key)", source):
                self.add("LOG-001", "medium", "Logging",
                         "Possible secret written to logs",
                         path, line, self.redact(source),
                         "Never log credentials or raw tokens; redact before logging.",
                         lt)

    def is_true(self, node: ast.AST | None) -> bool:
        return isinstance(node, ast.Constant) and node.value is True

    def is_safe_loader(self, node: ast.AST | None) -> bool:
        return isinstance(node, ast.Attribute) and node.attr == "SafeLoader"

    def has_path_validation(self, text: str) -> bool:
        return any(w in text for w in ("is_relative_to", "safe_join", "resolve()", "basename"))

    def has_url_validation(self, text: str) -> bool:
        return any(w in text for w in ("urlparse", "ALLOWED_HOSTS", "allowlist", "allowed_hosts"))

    def check_function_auth(self, path: Path, lines: list[str], node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        name = node.name
        is_handler = name in {"do_GET", "do_POST", "do_PUT", "do_DELETE", "do_PATCH"}
        is_route = False
        for dec in node.decorator_list:
            dname = self.call_name(dec.func) if isinstance(dec, ast.Call) else self.call_name(dec)
            if dname.split(".")[-1] in {"get", "post", "put", "delete", "patch", "route"}:
                if dname.split(".")[0] in {"app", "router", "api"}:
                    is_route = True
        if not (is_handler or is_route):
            return
        try:
            body = ast.get_source_segment("\n".join(lines), node) or ""
        except Exception:
            body = ""
        if not any(marker in body.lower() for marker in AUTH_MARKERS):
            self.add("AUTH-001", "medium", "Authorization",
                     f"HTTP handler {name}() may lack authentication",
                     path, node.lineno, name,
                     "Require and verify a token/session before executing tools or returning data.",
                     lines[node.lineno - 1] if node.lineno <= len(lines) else "")
        file_text = "\n".join(lines).lower()
        if not any(marker in file_text for marker in RATE_MARKERS):
            self.add("RATE-001", "low", "Availability",
                     "No rate limiting detected in an HTTP handler",
                     path, node.lineno, name,
                     "Add per-token rate limits and request size limits.",
                     lines[node.lineno - 1] if node.lineno <= len(lines) else "")

    # --- JS/TS rules --------------------------------------------------------
    def scan_js(self, path: Path, text: str) -> None:
        for i, line in enumerate(text.splitlines(), 1):
            if re.search(r"\beval\s*\(", line) or re.search(r"\bnew\s+Function\s*\(", line):
                self.add("EXEC-001", "high", "Execution", "Dynamic code execution in JavaScript",
                         path, i, self.redact(line),
                         "Avoid eval/new Function. Parse data and use an allowlist.", line)
            if re.search(r"child_process\.(exec|execSync)\s*\(", line):
                self.add("EXEC-002", "high", "Execution", "Shell execution in JavaScript",
                         path, i, self.redact(line),
                         "Use execFile/spawn with an argument list and shell disabled.", line)
            if re.search(r"shell\s*:\s*true", line):
                self.add("EXEC-003", "high", "Execution", "spawn/exec with shell enabled",
                         path, i, self.redact(line),
                         "Pass an argument list and leave shell disabled.", line)
            if re.search(r"(fetch|axios\.(get|post))\s*\(\s*`[^`]*`", line):
                template = re.search(r"`([^`]*)`", line)
                inner = template.group(1) if template else ""
                variables = re.findall(r"\$\{([^}]+)\}", inner)
                taint = re.compile(
                    r"(?i)(input|request|req\.|params|query|body|args|user|tool|content|message|host|target|dest)"
                )
                if any(taint.search(v) for v in variables):
                    self.add("SSRF-001", "high", "Network", "Outbound URL built from request/tool input",
                             path, i, self.redact(line),
                             "Allowlist hosts and validate the URL before fetching.", line)
            if re.search(r"(db|client|conn)\.query\s*\(\s*`[^`]*\$\{", line):
                self.add("SQLI-001", "critical", "Injection", "SQL query built with a template literal",
                         path, i, self.redact(line),
                         "Use parameterized queries.", line)
            if re.search(r"console\.log\s*\([^)]*(token|secret|password|apiKey)", line, re.I):
                self.add("LOG-001", "medium", "Logging", "Possible secret written to console",
                         path, i, self.redact(line),
                         "Redact secrets before logging.", line)

    # --- MCP config rules ---------------------------------------------------
    def scan_mcp_config(self, path: Path, text: str) -> None:
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return
        if not isinstance(data, dict):
            return
        servers = data.get("mcpServers") or data.get("servers") or {}
        if not isinstance(servers, dict):
            return
        for server_name, server in servers.items():
            if not isinstance(server, dict):
                continue
            command = str(server.get("command", ""))
            args = server.get("args", [])
            if not isinstance(args, list):
                args = [str(args)]
            env = server.get("env", {})
            if not isinstance(env, dict):
                env = {}
            joined = " ".join([command] + [str(a) for a in args])
            line_no = self.find_line(text, str(server_name))
            lt = text.splitlines()[line_no - 1] if line_no <= len(text.splitlines()) else ""

            if re.search(r"(?i)\b(npx\s+-y|npx\s+--yes|uvx|pipx\s+run|curl|wget|bash\s+-c|sh\s+-c|powershell\s+-c)\b", joined):
                self.add("MCP-001", "medium", "MCP configuration",
                         f"MCP server '{server_name}' runs a remote/unpinned command",
                         path, line_no, self.redact(joined),
                         "Pin the package version and review the package before granting it tool access.",
                         lt)
            if re.search(r"(?i)(--allow-all|--dangerously|--no-sandbox|--privileged|--read-only=false)", joined):
                self.add("MCP-002", "high", "MCP configuration",
                         f"MCP server '{server_name}' uses a dangerous flag",
                         path, line_no, self.redact(joined),
                         "Remove the flag and grant the minimum filesystem/network permissions needed.",
                         lt)
            for key, value in env.items():
                if re.search(r"(?i)(key|token|secret|password)", str(key)) and not self.is_placeholder(str(value)):
                    self.add("MCP-003", "high", "MCP configuration",
                             f"Secret in MCP env for '{server_name}'",
                             path, line_no, self.redact(f"{key}=..."),
                             "Use the OS keychain or a secret manager; do not store credentials in the MCP config.",
                             lt)
            for arg in args:
                if str(arg) in {"/", "C:\\", "~", "$HOME", "${HOME}"}:
                    self.add("MCP-004", "medium", "MCP configuration",
                             f"MCP server '{server_name}' gets broad filesystem access",
                             path, line_no, self.redact(joined),
                             "Mount a dedicated data directory, not the whole filesystem.",
                             lt)
                    break
            for arg in args:
                s = str(arg)
                if s.startswith("-") or s.startswith((".", "/", "~")) or "\\" in s or ":" in s:
                    continue
                if re.match(r"^(@[^/]+/)?[^@]+$", s):
                    self.add("MCP-005", "low", "MCP configuration",
                             f"MCP package '{s}' is not version-pinned",
                             path, line_no, self.redact(joined),
                             "Pin an exact version or commit so a compromised release cannot auto-run.",
                             lt)
                    break

    def find_line(self, text: str, needle: str) -> int:
        for i, line in enumerate(text.splitlines(), 1):
            if needle in line:
                return i
        return 1

    # --- dependency and compose rules --------------------------------------
    def scan_requirements(self, path: Path, text: str) -> None:
        for i, raw in enumerate(text.splitlines(), 1):
            line = raw.split("#", 1)[0].strip()
            if not line or line.startswith(("-r", "-e", "--")):
                continue
            if not re.search(r"(===|==|~=|>=|<=|!=| @ )", line):
                self.add("DEP-001", "low", "Dependencies",
                         f"Unpinned dependency: {line}",
                         path, i, self.redact(line),
                         "Pin exact versions and use a lockfile for reproducible builds.",
                         raw)

    def scan_package_json(self, path: Path, text: str) -> None:
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return
        for section in ("dependencies", "devDependencies"):
            deps = data.get(section, {})
            if not isinstance(deps, dict):
                continue
            for name, version in deps.items():
                v = str(version)
                if v in {"*", "latest"} or v.startswith(("^", "~")):
                    line_no = self.find_line(text, f'"{name}"')
                    self.add("DEP-001", "low", "Dependencies",
                             f"Floating dependency: {name}@{v}",
                             path, line_no, f"{name}: {v}",
                             "Pin exact versions and commit a lockfile.",
                             "")

    def scan_compose(self, path: Path, text: str) -> None:
        for i, line in enumerate(text.splitlines(), 1):
            if re.search(r"privileged\s*:\s*true", line, re.I):
                self.add("DOCKER-001", "high", "Containers", "Privileged container",
                         path, i, self.redact(line),
                         "Remove privileged mode; add only the specific capabilities needed.", line)
            if re.search(r"network_mode\s*:\s*[\"']?host", line, re.I):
                self.add("DOCKER-002", "high", "Containers", "Host network mode",
                         path, i, self.redact(line),
                         "Use a dedicated bridge network and expose only required ports.", line)
            if "/var/run/docker.sock" in line:
                self.add("DOCKER-003", "high", "Containers", "Docker socket mounted into a container",
                         path, i, self.redact(line),
                         "Use a read-only socket proxy or avoid mounting the Docker socket.", line)
            m = re.search(r"image\s*:\s*[\"']?([^\"'\s#]+)", line, re.I)
            if m:
                image = m.group(1)
                if ":" not in image or image.endswith(":latest"):
                    self.add("DOCKER-004", "low", "Containers", "Unpinned container image",
                             path, i, self.redact(line),
                             "Pin a specific image digest or version.", line)


# --- reporting --------------------------------------------------------------

def risk_score(findings: list[Finding]) -> int:
    """Diminishing-returns score so low-severity noise cannot fake a crisis.

    Each severity has a per-finding weight and a cap. Criticals dominate,
    but a hundred unpinned dev dependencies should read as "low", not 100.
    """
    counts = {s: 0 for s in SEVERITY_WEIGHT}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    caps = {
        "critical": (25, 50),
        "high": (10, 30),
        "medium": (3, 15),
        "low": (1, 5),
        "info": (0, 0),
    }
    score = 0
    for severity, (weight, cap) in caps.items():
        score += min(counts.get(severity, 0) * weight, cap)
    return min(100, score)


def render_html(root: Path, findings: list[Finding], files: int, errors: list[str]) -> str:
    counts = {s: 0 for s in ("critical", "high", "medium", "low", "info")}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    score = risk_score(findings)
    if score >= 70:
        band = "Critical"
    elif score >= 45:
        band = "High"
    elif score >= 20:
        band = "Moderate"
    elif score:
        band = "Low"
    else:
        band = "Clean"
    esc = html.escape
    cards = []
    for i, f in enumerate(findings, 1):
        cards.append(
            f'<article class="finding {esc(f.severity)}">'
            f'<div class="finding-head"><span class="sev {esc(f.severity)}">{esc(f.severity.upper())}</span>'
            f'<h3>{i}. {esc(f.title)}</h3></div>'
            f'<div class="meta"><span class="rule">{esc(f.rule_id)}</span>'
            f'<span>{esc(f.category)}</span><span class="loc">{esc(f.file)}:{f.line}</span></div>'
            f'<pre><code>{esc(f.evidence)}</code></pre>'
            f'<p class="fix"><strong>Fix:</strong> {esc(f.remediation)}</p></article>'
        )
    if not cards:
        cards.append('<p class="empty">No findings in the static ruleset. This is not proof of security; a manual review is still required.</p>')
    notes = ""
    if errors:
        notes = '<h2>Scan notes</h2><ul>' + "".join(f"<li>{esc(e)}</li>" for e in errors[:20]) + "</ul>"
    summary = (
        f"Found <strong>{len(findings)} findings</strong>: {counts['critical']} critical, "
        f"{counts['high']} high, {counts['medium']} medium, {counts['low']} low."
        if findings else
        "No findings in the static ruleset. This is not proof of security; a manual review is still required."
    )
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AgentGuard Security Audit — {esc(str(root))}</title>
<style>
  :root {{ --ink:#16202f; --muted:#5c6b82; --line:#dfe5ee; --bg:#f6f8fc; --panel:#ffffff; --accent:#3f5bd9; --critical:#d92d4b; --high:#d97706; --medium:#b58900; --low:#4b6cb7; }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; background:var(--bg); color:var(--ink); font-family:ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif; line-height:1.6; }}
  .wrap {{ max-width:980px; margin:0 auto; padding:0 24px 60px; }}
  header {{ background:linear-gradient(135deg,#111a2e,#26365f); color:#fff; padding:34px 0 30px; margin-bottom:28px; }}
  header .wrap {{ padding-bottom:0; }}
  .brand {{ font-weight:800; letter-spacing:-0.02em; font-size:15px; color:#aebcff; text-transform:uppercase; }}
  h1 {{ font-size:30px; letter-spacing:-0.03em; margin:6px 0 4px; }}
  .target {{ font-family:ui-monospace,Consolas,monospace; font-size:12.5px; color:#c3cce7; word-break:break-all; }}
  .score-row {{ display:flex; gap:22px; align-items:center; margin-top:18px; flex-wrap:wrap; }}
  .score {{ width:92px; height:92px; border-radius:50%; display:grid; place-items:center; background:conic-gradient(#ff6b81 {score}%, #2c3d68 0); }}
  .score-inner {{ width:72px; height:72px; border-radius:50%; background:#111a2e; display:grid; place-items:center; text-align:center; }}
  .score-inner b {{ font-size:22px; display:block; line-height:1; }}
  .score-inner span {{ font-size:9px; text-transform:uppercase; letter-spacing:.08em; color:#aebcff; }}
  .score-copy b {{ display:block; font-size:18px; }}
  .score-copy span {{ color:#c3cce7; font-size:13px; }}
  .panel {{ background:var(--panel); border:1px solid var(--line); border-radius:14px; padding:22px 24px; margin:16px 0; }}
  h2 {{ font-size:20px; letter-spacing:-0.02em; margin:0 0 12px; }}
  .summary p {{ margin:0; color:var(--muted); }}
  table {{ width:100%; border-collapse:collapse; font-size:14px; }}
  th,td {{ text-align:left; padding:9px 10px; border-bottom:1px solid var(--line); }}
  th {{ color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.06em; }}
  td:last-child, th:last-child {{ text-align:right; }}
  .sev {{ display:inline-block; font-size:10.5px; font-weight:800; letter-spacing:.08em; padding:3px 8px; border-radius:6px; margin-right:10px; vertical-align:2px; }}
  .sev.critical {{ background:#fdeaee; color:var(--critical); }}
  .sev.high {{ background:#fff2df; color:var(--high); }}
  .sev.medium {{ background:#fff8d9; color:#8a6d00; }}
  .sev.low {{ background:#eaf0ff; color:var(--low); }}
  .finding {{ border:1px solid var(--line); border-left:4px solid var(--line); border-radius:10px; padding:16px 18px; margin:12px 0; background:#fff; page-break-inside:avoid; }}
  .finding.critical {{ border-left-color:var(--critical); }}
  .finding.high {{ border-left-color:var(--high); }}
  .finding.medium {{ border-left-color:var(--medium); }}
  .finding.low {{ border-left-color:var(--low); }}
  .finding-head {{ display:flex; align-items:flex-start; }}
  .finding h3 {{ font-size:15.5px; margin:0; letter-spacing:-0.01em; }}
  .meta {{ display:flex; gap:14px; flex-wrap:wrap; color:var(--muted); font-size:12px; margin:8px 0 10px; }}
  .meta .rule {{ font-family:ui-monospace,Consolas,monospace; color:var(--accent); font-weight:600; }}
  .meta .loc {{ font-family:ui-monospace,Consolas,monospace; }}
  pre {{ background:#0f1726; color:#d7e2ff; border-radius:8px; padding:12px 14px; overflow-x:auto; font-size:12px; margin:0 0 10px; }}
  code {{ font-family:ui-monospace,Consolas,monospace; }}
  .fix {{ margin:0; font-size:13.5px; color:var(--muted); }}
  .fix strong {{ color:var(--ink); }}
  .scope {{ color:var(--muted); font-size:13px; }}
  footer {{ color:var(--muted); font-size:12px; text-align:center; padding-top:22px; }}
  .empty {{ color:var(--muted); }}
  @media print {{ body {{ background:#fff; }} header {{ background:#111a2e !important; -webkit-print-color-adjust:exact; print-color-adjust:exact; }} .panel,.finding {{ break-inside:avoid; }} }}
</style>
</head>
<body>
<header><div class="wrap">
  <div class="brand">AgentGuard · Security Audit</div>
  <h1>Static security report</h1>
  <div class="target">{esc(str(root))}</div>
  <div class="score-row">
    <div class="score"><div class="score-inner"><b>{score}</b><span>/ 100</span></div></div>
    <div class="score-copy"><b>{band} risk</b><span>{files} files scanned · {time.strftime('%Y-%m-%d %H:%M')}</span></div>
  </div>
</div></header>
<div class="wrap">
  <div class="panel summary"><h2>Executive summary</h2><p>{summary}</p></div>
  <div class="panel"><h2>Findings by severity</h2>
    <table><thead><tr><th>Severity</th><th>Count</th></tr></thead><tbody>
      <tr><td>Critical</td><td>{counts['critical']}</td></tr>
      <tr><td>High</td><td>{counts['high']}</td></tr>
      <tr><td>Medium</td><td>{counts['medium']}</td></tr>
      <tr><td>Low</td><td>{counts['low']}</td></tr>
    </tbody></table>
  </div>
  <div class="panel"><h2>Findings</h2>{''.join(cards)}</div>
  <div class="panel scope"><h2>Scope and limitations</h2>
    <p>This is a static analysis pass over source and configuration files. It does not execute the agent, test live APIs, or prove exploitability. A manual review and dynamic testing are required for a complete audit.</p>
  </div>
  {notes}
  <footer>Generated by AgentGuard · static analysis, not a penetration test · confidential to the client</footer>
</div>
</body>
</html>"""


def render_markdown(root: Path, findings: list[Finding], files: int, errors: list[str]) -> str:
    counts = {s: 0 for s in ("critical", "high", "medium", "low", "info")}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    score = risk_score(findings)
    if score >= 70:
        band = "Critical"
    elif score >= 45:
        band = "High"
    elif score >= 20:
        band = "Moderate"
    elif score:
        band = "Low"
    else:
        band = "Clean"

    out = []
    out.append("# AgentGuard Security Audit\n\n")
    out.append(f"**Target:** `{root}`  \n")
    out.append(f"**Date:** {time.strftime('%Y-%m-%d %H:%M')}  \n")
    out.append(f"**Files scanned:** {files}  \n")
    out.append(f"**Risk score:** {score}/100 ({band})\n\n")
    out.append("## Executive Summary\n\n")
    if findings:
        out.append(f"Found **{len(findings)} findings**: "
                   f"{counts['critical']} critical, {counts['high']} high, "
                   f"{counts['medium']} medium, {counts['low']} low.\n\n")
        out.append("Fix critical and high findings before exposing this agent to untrusted input or the public internet.\n\n")
    else:
        out.append("No findings in the static ruleset. This is not proof of security; a manual review is still required.\n\n")
    out.append("## Findings by Severity\n\n")
    out.append("| Severity | Count |\n|---|---:|\n")
    for severity in ("critical", "high", "medium", "low"):
        out.append(f"| {severity.capitalize()} | {counts[severity]} |\n")
    out.append("\n## Findings\n\n")
    if not findings:
        out.append("_No findings._\n")
    for i, f in enumerate(findings, 1):
        out.append(f"### {i}. [{f.severity.upper()}] {f.title}\n\n")
        out.append(f"- **Rule:** `{f.rule_id}`\n")
        out.append(f"- **Category:** {f.category}\n")
        out.append(f"- **Location:** `{f.file}:{f.line}`\n")
        out.append(f"- **Evidence:** `{f.evidence}`\n\n")
        out.append(f"**Fix:** {f.remediation}\n\n")
    out.append("## Scope and Limitations\n\n")
    out.append("This is a static analysis pass over source and configuration files. "
               "It does not execute the agent, test live APIs, or prove exploitability. "
               "A manual review and dynamic testing are required for a complete audit.\n\n")
    if errors:
        out.append("### Scan notes\n\n")
        for e in errors[:20]:
            out.append(f"- {e}\n")
    return "".join(out)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="AgentGuard static security audit")
    parser.add_argument("path", nargs="?", default=".", help="directory or file to scan")
    parser.add_argument("--format", choices=["md", "json", "html"], default="md")
    parser.add_argument("--output", "-o", help="write report to file")
    parser.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "none"], default="none")
    parser.add_argument("--exclude", action="append", default=[], help="substring to exclude")
    parser.add_argument("--include-tests", action="store_true",
                        help="also scan test directories and *.test.* / *.spec.* files")
    args = parser.parse_args(argv)

    scanner = Scanner(args.path, args.exclude, include_tests=args.include_tests)
    findings = scanner.scan()
    if args.format == "json":
        payload = {
            "target": str(scanner.root),
            "files_scanned": scanner.files_scanned,
            "include_tests": scanner.include_tests,
            "risk_score": risk_score(findings),
            "findings": [f.to_dict() for f in findings],
            "errors": scanner.errors,
        }
        report = json.dumps(payload, indent=2)
    elif args.format == "html":
        report = render_html(scanner.root, findings, scanner.files_scanned, scanner.errors)
    else:
        report = render_markdown(scanner.root, findings, scanner.files_scanned, scanner.errors)

    if args.output:
        Path(args.output).write_text(report, encoding="utf-8")
        print(f"Wrote {args.output} ({len(findings)} findings, {scanner.files_scanned} files)")
    else:
        print(report)

    if args.fail_on != "none":
        threshold = SEVERITY_RANK[args.fail_on]
        if any(SEVERITY_RANK[f.severity] >= threshold for f in findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
