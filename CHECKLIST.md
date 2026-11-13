# AgentGuard manual audit checklist

Use this alongside `audit.py`. The scanner finds patterns; this checklist finds design mistakes. Score each item Pass / Fail / N/A and attach evidence.

## 1. Tool surface

- [ ] Every tool has a one-sentence description that states what it does and what it does not do.
- [ ] Tool descriptions contain no instructions to the model beyond the task (no "always", "ignore", "do not tell").
- [ ] Tools are read-only by default; write/execute tools are separate and explicitly named.
- [ ] Destructive tools require a human confirmation step.
- [ ] Tool arguments are validated against a schema with types, lengths, and enums.
- [ ] Unknown arguments are rejected, not ignored.
- [ ] Tool output is treated as untrusted text and never concatenated into a system prompt.
- [ ] There is a maximum output size and a truncation rule.

## 2. Identity and authorization

- [ ] Every request is tied to an authenticated user or service identity.
- [ ] Authorization is checked per resource, not just per endpoint.
- [ ] Tenant ID comes from the session, never from a tool argument.
- [ ] Cross-tenant reads are tested with two real accounts.
- [ ] Admin tools are behind a separate role check.
- [ ] Tokens are short-lived and audience-scoped.
- [ ] There is no shared service account with broad access.
- [ ] Failed authorization returns a generic error, not resource existence.

## 3. Prompt and context handling

- [ ] System prompt and tool metadata are separated from user/retrieved content.
- [ ] Retrieved documents are wrapped in explicit delimiters and labeled untrusted.
- [ ] Instruction-like text in retrieved content is stripped or escaped.
- [ ] Hidden Unicode and bidi characters are removed from inbound text.
- [ ] HTML comments and metadata are stripped from tool descriptions.
- [ ] Tool output cannot change the agent's goals or permissions.
- [ ] The agent cannot read its own system prompt or secrets through a tool.
- [ ] Memory writes are validated; malicious memories cannot persist.

## 4. Secrets

- [ ] No secrets in source, MCP config, compose files, or logs.
- [ ] Secrets come from a manager or OS keychain, not `.env` committed to git.
- [ ] `.gitignore` covers `.env`, keys, and local config.
- [ ] Every exposed secret has been rotated, not just deleted.
- [ ] Secrets are scoped to the minimum API surface.
- [ ] Logs redact tokens, headers, and connection strings.
- [ ] Error messages do not echo credentials.
- [ ] Backups and CI artifacts do not contain secrets.

## 5. Filesystem

- [ ] All file paths are resolved and checked against an allowlisted base directory.
- [ ] Symlinks cannot escape the base directory.
- [ ] Filenames cannot contain traversal, null bytes, or absolute paths.
- [ ] Uploads are stored outside the web root with generated names.
- [ ] File type is validated by content, not only extension.
- [ ] Read size and count are bounded.
- [ ] Temporary files are cleaned up.
- [ ] The agent cannot read its own config or credentials directory.

## 6. Execution

- [ ] No `eval`, `exec`, or dynamic import on model/tool input.
- [ ] No shell invocation with interpolated input.
- [ ] Subprocesses use an argument list, `shell=False`, a timeout, and a minimal environment.
- [ ] Commands are allowlisted by executable and argument shape.
- [ ] Working directory is fixed and writable paths are isolated.
- [ ] Resource limits (CPU, memory, time, output) are enforced.
- [ ] Generated code runs in a sandbox with no network and no host mounts.
- [ ] Execution results cannot be used to escalate to another tool.

## 7. Network and SSRF

- [ ] Outbound URLs are parsed and restricted to `https`.
- [ ] Hostnames are allowlisted after DNS resolution, not before.
- [ ] Private IP ranges, link-local, and cloud metadata addresses are blocked.
- [ ] Redirects are disabled or re-validated at each hop.
- [ ] DNS rebinding is considered for high-risk paths.
- [ ] Request timeouts and response size limits are set.
- [ ] Webhooks validate signatures and replay windows.
- [ ] The agent cannot reach the control plane or internal admin APIs.

## 8. Data and storage

- [ ] All SQL uses parameterized queries.
- [ ] ORM raw-query escape hatches are reviewed.
- [ ] Database users have least privilege.
- [ ] Vector-store filters enforce tenant scope server-side.
- [ ] Memory writes have provenance and an expiry policy.
- [ ] Deletes are authorized and auditable.
- [ ] Backups are encrypted and access-controlled.
- [ ] PII is minimized, labeled, and retention-bounded.

## 9. MCP runtime

- [ ] Every MCP server is pinned to an exact version or commit.
- [ ] Servers are installed from a trusted registry and reviewed before first run.
- [ ] No `npx -y`, `uvx`, `curl | bash`, or `--dangerously-*` flags in production.
- [ ] Each server gets only the directories and env vars it needs.
- [ ] The filesystem server is not mounted at `/` or `C:\`.
- [ ] MCP server processes run as a low-privilege user.
- [ ] Server stdout/stderr cannot leak secrets into logs.
- [ ] Unused servers and tools are disabled.

## 10. Containers and deployment

- [ ] No privileged containers.
- [ ] No Docker socket mounts.
- [ ] No host networking unless justified and documented.
- [ ] Images are pinned by digest or exact version, not `:latest`.
- [ ] Containers run read-only with a non-root user.
- [ ] Capabilities are dropped and seccomp/AppArmor profiles are applied.
- [ ] Network policies restrict egress.
- [ ] Resource limits and health checks are set.

## 11. Logging and monitoring

- [ ] Tool calls are logged with actor, tool, arguments hash, and result status.
- [ ] Logs do not contain secrets or full sensitive payloads.
- [ ] Anomalies (rate spikes, new destinations, repeated failures) alert a human.
- [ ] There is an audit trail for permission and config changes.
- [ ] Log retention and access are defined.
- [ ] Incident response has an owner and a contact path.

## 12. Supply chain

- [ ] Dependencies are pinned and a lockfile is committed.
- [ ] CI uses least-privilege tokens and pinned actions by SHA.
- [ ] Third-party actions and MCP servers are reviewed before use.
- [ ] Build artifacts are signed or verified.
- [ ] Dependabot or equivalent is enabled.
- [ ] A compromised dependency has a rollback plan.

## 13. Abuse and cost

- [ ] Per-user and per-token rate limits exist.
- [ ] Expensive tools have quotas and budgets.
- [ ] Recursive agent loops have a step and spend cap.
- [ ] User input cannot select an unbounded model or tool.
- [ ] Abuse alerts route to a human.
- [ ] There is a kill switch.

---

**Scoring:** any Fail in sections 2, 4, 5, 6, or 7 is a release blocker. Everything else is prioritized by exploitability and blast radius. Record evidence for every Pass; "looks fine" is not evidence.
