# AgentGuard

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/AnantPrabhudesai01/agentguard)](https://github.com/AnantPrabhudesai01/agentguard/releases)
[![Sponsor](https://img.shields.io/badge/Sponsor-%E2%99%A5-ff69b4.svg)](https://github.com/sponsors/AnantPrabhudesai01)

Static security audit for AI agents and MCP servers. Zero dependencies, runs offline, Python 3.10+.

Agents are no longer chatbots. They read files, run shell commands, query databases, call internal APIs, and load third-party MCP servers. Every tool argument is an input path into your infrastructure. AgentGuard checks the places where those paths become vulnerabilities.

```bash
python audit.py .
python audit.py path/to/agent --format md --output report.md
python audit.py path/to/agent --format html --output report.html
python audit.py path/to/agent --format json --fail-on high
```

## Proof, not promises

The repo ships with a deliberately vulnerable demo agent and its remediated twin:

| Target | Findings | Risk score |
|---|---:|---:|
| `demo/vulnerable` | 23 (2 critical, 12 high) | 97/100 |
| `demo/fixed` | 0 | 0/100 |

```bash
python audit.py demo/vulnerable --format md --output reports/demo-vulnerable.md
python audit.py demo/fixed --format md --output reports/demo-fixed.md
```

Full reports: [`reports/demo-vulnerable.md`](reports/demo-vulnerable.md) and [`reports/demo-fixed.md`](reports/demo-fixed.md). Every finding cites a file, line, evidence, and a concrete fix.

Calibration on public code: scans of `modelcontextprotocol/servers`, `microsoft/playwright-mcp`, and `supabase-community/supabase-mcp` covered 306 source files and produced **0 critical/high** findings, only low dependency-pinning notes. Test fixtures are skipped by default to keep the signal clean.

## What it checks

| Area | Examples |
|---|---|
| Code execution | `eval`/`exec`, `os.system`, `subprocess(shell=True)`, JS `eval`/`child_process.exec` |
| Injection | SQL built with f-strings/templates, unsafe deserialization |
| Filesystem | File paths built from tool input without containment |
| Network | SSRF via user-controlled URLs, missing host allowlists |
| Secrets | API keys, tokens, private keys, credentials in MCP env and compose files |
| Prompt injection | Instruction-override phrases, hidden Unicode, HTML comments in tool metadata |
| MCP configuration | `npx -y`, unpinned packages, dangerous flags, broad filesystem mounts |
| Containers | Privileged mode, host networking, Docker socket mounts, `:latest` images |
| Dependencies | Unpinned Python and npm dependencies |
| Web surface | Route handlers without visible auth or rate limiting |
| Logging | Tokens or credentials written to logs |

Run `python audit.py --help` for options. Test directories and `*.test.*`/`*.spec.*` files are skipped by default to avoid fixture noise; add `--include-tests` to scan them. Suppress a reviewed line with `# agentguard:ignore`.

## CI

```yaml
- name: AgentGuard
  uses: your-org/agentguard@v0.1.0
  with:
    path: .
    fail-on: high
```

Or call the script directly:

```yaml
- run: python audit.py . --format md --output agentguard-report.md --fail-on high
```

A ready-to-copy workflow is in [`examples/github-workflow.yml`](examples/github-workflow.yml).

## Tests

```bash
python -m unittest discover -s tests -v
```

27 tests cover the rule set, taint precision, remediation paths, redaction, suppression, report formats, and CI exit codes.

## Scope and honesty

AgentGuard is **static analysis**, not a penetration test. It does not execute your agent, call live APIs, or prove exploitability. It finds patterns that commonly become real vulnerabilities, then a human reviews the architecture, permissions, and business logic. The report says this explicitly.

## Paid audit

The scanner is the free proof. The paid engagement adds manual review, severity triage against your actual deployment, a walkthrough call, and a re-scan after fixes. See [`OFFER.md`](OFFER.md) and [`CHECKLIST.md`](CHECKLIST.md).

## Layout

```
agentguard/
  audit.py                  scanner and report generator
  demo/vulnerable/          intentionally insecure sample agent
  demo/fixed/               remediated sample agent
  reports/                  generated proof reports (Markdown + HTML)
  tests/                    unit tests
  CHECKLIST.md              manual audit checklist
  OFFER.md                  service scope and pricing
  LAUNCH.md                 publishing and distribution plan
  examples/                 CI workflow
  action.yml                composite GitHub Action
```

License is intentionally unset until the owner chooses one before publishing.
