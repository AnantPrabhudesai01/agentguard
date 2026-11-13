# AgentGuard Security Audit — offer

**Find the agent vulnerability before an attacker does.**

AI agents now hold credentials, read private files, run commands, and call internal APIs. A single unvalidated tool argument can become remote code execution, SSRF into your cloud metadata service, or a cross-tenant data leak. Generic SAST tools miss the agent layer. AgentGuard reviews both the code and the agent-specific attack surface.

## What you get

1. **Static scan** of your agent, MCP servers, configs, and container setup using the open-source AgentGuard engine.
2. **Manual review** of the highest-risk paths: tool boundaries, auth/tenant isolation, secret handling, filesystem and network reach, and prompt/context handling.
3. **Prioritized report** — critical/high/medium/low, each with file, line, evidence, impact, and a concrete fix. Delivered as a shareable HTML report plus Markdown and JSON.
4. **30-minute walkthrough** call (recorded if you want).
5. **One re-scan** after fixes, with a before/after risk score.

Turnaround: **2 business days** from receipt of code and scope confirmation.

## Scope

- Python, JavaScript, and TypeScript agents and MCP servers.
- MCP client/server configuration (`mcp.json`, Claude Desktop, OpenCode, VS Code).
- Docker and compose files, dependency manifests, CI workflow files.
- Up to **50,000 lines** of first-party code. Larger repos quoted separately.
- One codebase and one environment per engagement.

Out of scope: live penetration testing, exploit development, production traffic testing, cloud account review, and compliance certification. Those can be quoted separately.

## Pricing (launch)

| Tier | Price | Includes |
|---|---:|---|
| **Launch audit** (first 5 clients) | **$99** | Everything above, one codebase up to 50k LOC |
| Standard audit | $249 | Everything above, one re-scan, 45-minute call |
| Monthly retainer | $499/mo | Monthly scan + 2 hours of review, priority turnaround |

INR billing at the day's rate (≈ ₹9,320 for the $99 launch tier at $1 = ₹94.14). Payment by Stripe invoice, PayPal, or UPI. The human operator handles invoicing; no crypto wallet or seed phrase is ever required.

## Guarantee

If the audit produces no actionable findings, you pay nothing. If we miss a critical issue that a reasonable manual review of the agreed scope should have caught, the next audit is free.

## Rules of engagement

- Written authorization before any work starts.
- Static review only; we do not attack live systems.
- No client code is retained after 30 days, and it is never used to train models.
- Findings are confidential to the client. We do not publish them or name the client without written permission.
- We do not help with spam, fraud, unauthorized access, or evasion.
- NDA available on request.

## Process

1. You send the repo (or a zip) and confirm the scope in writing.
2. We confirm the quote and payment terms.
3. Scan + manual review.
4. You receive the report and a walkthrough slot.
5. Fix, then we re-scan and issue the after-report.

## Contact & Booking

To request a security audit:
- Open an issue at the AgentGuard repository: [github.com/AnantPrabhudesai01/agentguard](https://github.com/AnantPrabhudesai01/agentguard)
- Or reach out via GitHub discussions / direct inquiry.
- Invoices are delivered upon scope confirmation. Payments accepted via UPI, Stripe, and PayPal.

---

*AgentGuard is static analysis plus human review. It is not a guarantee that the system is free of vulnerabilities. The report states its own limitations.*
