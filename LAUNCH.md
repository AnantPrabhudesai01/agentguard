# Launch plan

Everything here is free. The only cost is the human's attention and consent. Do not publish under someone's identity without their explicit approval.

## Phase 0 — pre-flight (10 minutes)

- [ ] Read `OFFER.md` and approve the pricing and guarantee.
- [ ] Replace every `[contact]` / "replace this line" placeholder with a real contact path.
- [ ] Run the scanner on the package itself and confirm no secrets:
      `python audit.py . --exclude demo/vulnerable --exclude tests --exclude reports --exclude audit.py --fail-on high`
- [ ] Confirm the demo fake credentials are obviously fake (`NOT_A_REAL_*`).
- [ ] Pick a license (MIT is the usual choice for a lead-gen scanner).
- [ ] Decide the public repo name: `agentguard`.

## Phase 1 — publish the proof

Run from `revenue/agentguard`, never from `D:\`.

```powershell
cd D:\Anant\AiHuman\revenue\agentguard
.\publish.ps1            # dry run: tests, self-scan, preview
.\publish.ps1 -Execute   # create the public repo and push
```

Or do it manually:

```powershell
cd D:\Anant\AiHuman\revenue\agentguard
git init
git add .
git commit -m "AgentGuard v0.1.0: static security audit for AI agents"
gh repo create agentguard --public --source=. --remote=origin --push
gh repo edit --add-topic mcp,security,ai-agents,static-analysis,appsec
gh release create v0.1.0 --title "v0.1.0" --notes "First public release. 23 findings on the vulnerable demo, 0 after remediation. 27 tests."
```

Then, in the GitHub UI:
- [ ] Enable Issues (contact path) and Discussions (Q&A).
- [ ] Enable Pages from `main` / `/site` if you want the landing page.
- [ ] Add the repo link to the GitHub profile README.

## Phase 2 — launch posts (value first, no hype)

Post **once** per community, follow each community's self-promotion rules. Do not cross-post the same text everywhere; adapt it.

### Show HN

> **Show HN: AgentGuard – static security audit for AI agents and MCP servers**
>
> Agents now hold filesystem, shell, database, and network access. I built a zero-dependency scanner that checks the agent-specific surface: tool metadata, MCP configs, prompt-injection phrases, hidden Unicode, dangerous container flags, unvalidated tool arguments, and secret handling.
>
> It ships with a deliberately vulnerable demo agent and a remediated twin: 23 findings / 97 risk score vs 0. Every finding has file, line, evidence, and a fix. 27 tests.
>
> It's static analysis, not a pentest, and the README says so. The paid audit exists because the scanner can't judge architecture or business logic.
>
> Repo: [link] — feedback on missed rules is welcome.

### r/mcp

> I scanned a typical MCP setup and found 23 issues. Here's the checklist I used.
>
> The highest-impact ones were a filesystem server mounted at `/`, `npx -y` with an unpinned package, a GitHub token in `mcp.json`, and tool descriptions that carried instruction-like text. None of these are exotic; they are the default copy-paste setup.
>
> I turned the checks into a free scanner plus a manual checklist. Repo: [link]. If you maintain an MCP server, run `python audit.py .` and tell me what it misses.

### X / LinkedIn

> Your agent has shell access, a filesystem, and your API keys.
>
> Generic SAST doesn't check the agent layer. I built AgentGuard: 20+ rules for tool boundaries, MCP configs, prompt injection, secrets, SSRF, and container escape paths.
>
> Vulnerable demo: 23 findings. Fixed demo: 0. Free and offline.
>
> [link]

## Phase 3 — direct outreach (10 per week, personalized)

Rules:
- One message per project, one follow-up after 7 days, then stop.
- Only contact maintainers who publish a security contact or ask for audits.
- Never send a mass email or scrape addresses.
- Lead with a specific, non-scary observation, not a sales pitch.
- Do not disclose a vulnerability publicly before the maintainer has had time to fix it.

Template:

> Subject: One question about [project]'s MCP tool boundary
>
> Hi [name] — I maintain AgentGuard, a free static scanner for agent/MCP codebases. I ran it against [project] and saw [specific pattern, no exploit details]. It may be intentional, so I wanted to ask rather than assume.
>
> If it's useful, the scan is here: [report]. No pitch; I'm trying to make the rules less noisy. If you want the full manual review, I offer a $99 launch audit, but the scanner and checklist are free either way.
>
> — [name]

## Phase 4 — convert

- [ ] Track every lead in `sales/pipeline.md`.
- [ ] Send the offer only after the person replies.
- [ ] Invoice through the human operator's Stripe/PayPal/UPI; never ask for crypto keys.
- [ ] Deliver within 2 business days.
- [ ] Ask for a testimonial after the re-scan, with permission to quote.
- [ ] Record revenue in `money/ledger.json` only when the money has actually arrived.

## What not to do

- No mass DMs, no bought email lists, no comment spam on issues.
- No publishing exploitable details about a real project without coordination.
- No claiming "0-day" or "guaranteed secure".
- No fake testimonials, fake client logos, or fake earnings.
- No pushing from `D:\` or committing `.env`, tokens, or client code.
