# JO AI Monitor

A Dockerized, read-only evidence explorer for Anthropic's Claude Compliance API. It gives security, legal, and compliance teams a searchable view of Claude.ai chats, Claude Code/Cowork sessions, and activity records, with a verbatim JSON evidence export.

See [ROADMAP.md](ROADMAP.md) for delivered capabilities, planned milestones, and the Security and Compliance approval gates required before production use.

## Run the demo

```bash
cp .env.example .env
docker compose up --build
```

Open `http://localhost:8080`. The example credentials are `admin` / `change-me-now`; change them in `.env` before any shared deployment.

## Update an existing deployment

A GitHub push does not automatically rebuild an existing Docker container. From the deployment checkout, run:

```bash
git pull origin main
docker compose up -d --build --force-recreate
```

Then open `/health` and confirm the reported `version` is `0.6.1`. The same version appears persistently in the fixed lower-left sidebar. Frontend assets are served with no-cache headers so a normal reload receives the matching interface; if a reverse proxy or CDN adds its own cache, purge it once after deployment.

## Connect Anthropic

1. Have a Claude Enterprise primary/organization owner enable the Compliance API.
2. Create a Compliance Access Key with `read:compliance_activities`, `read:compliance_user_data`, and optionally `read:compliance_org_data`. Do **not** grant delete scope to this application.
3. Set `ANTHROPIC_COMPLIANCE_ACCESS_KEY` in `.env`, set `DEMO_MODE=false`, use a strong `SESSION_SECRET`, and restart.

An Admin API key can only read the Activity Feed. Full chat, file, project, directory, and transcript access requires a Compliance Access Key.

## Current capabilities

- Standard username/password login with signed, HTTP-only sessions
- Server-side Anthropic credential handling (never exposed to the browser)
- Unified evidence index for chats, local Claude Code/Cowork sessions, and remote Cowork sessions
- Search and filtering, transcript drill-down, Activity Feed and organizations backend endpoints
- Downloadable JSON evidence envelope with source, exporter, and timestamp
- Responsive UI, health check, Docker Compose, persistent volume
- Safe demo mode with 100 realistic, threshold-qualified leadership-demo findings when no Anthropic key is present
- Microsoft 365 Copilot Chat and Copilot-in-Office prompt/response ingestion through Microsoft Graph
- Leadership-ready Usage & Spend dashboard for adoption, licensing, budgets, products, applications, models, and anonymized utilization

## Usage and spend governance

The **Usage & spend** navigation item keeps adoption and economics separate from security findings. Demo mode includes an anonymized July 2026 leadership dataset with Copilot interactions, Claude API requests and token spend, seat assignment, budget utilization, estimated monthly run rate, application/product mix, model economics, agent-assisted usage, and a role-restricted-style user sample.

Copilot interactions and Claude requests are intentionally displayed as different units. They are not added together or treated as measures of employee productivity. Opening the dashboard writes a `usage_analytics_viewed` event to the access-audit chain.

Live deployments currently show the module as unconfigured until a monthly analytics ingestion connector is supplied. No real identities from the source workbook are embedded in the application.

## Production notes

- Terminate TLS at a trusted reverse proxy and set `COOKIE_SECURE=true`.
- Put the Compliance Access Key in your orchestrator's secret store, not `.env` or an image.
- This MVP intentionally exposes no Compliance API delete operations.
- The Compliance API is retrospective. For real-time prompt blocking, use Anthropic Inference Hooks; for live telemetry, consider OpenTelemetry.
- The current live list is a direct API view. Production evidence retention, case annotations, legal hold, append-only audit logs, and cryptographic export manifests should use a durable database/object store.

## Microsoft Entra ID / SSO

JO AI Monitor supports native OpenID Connect using Entra's authorization-code flow with PKCE. Register a **Web** application in Entra and add the exact redirect URI used by the app, for example `https://ai-monitor.example.com/api/auth/entra/callback`.

1. Create an Entra app registration restricted to your organizational directory.
2. Add the Web redirect URI above. Do not enable the implicit grant.
3. Create a client secret for initial deployment; prefer a certificate or workload identity in a later hardening phase.
4. Define app roles such as `Compliance.Reviewer` and `Compliance.Admin`, then assign users or groups to the enterprise application.
5. Set `ENTRA_TENANT_ID`, `ENTRA_CLIENT_ID`, `ENTRA_CLIENT_SECRET`, `ENTRA_REDIRECT_URI`, and `ENTRA_ALLOWED_ROLES` in the secret environment.
6. Start with `LOCAL_AUTH_ENABLED=true`. After validating Entra access and recovery procedures, set it to `false`.

If either `ENTRA_ALLOWED_ROLES` or `ENTRA_ALLOWED_GROUPS` is configured, the app rejects authenticated users who do not match at least one allowlisted value. App roles are recommended because they make the intended authorization boundary explicit and avoid oversized group claims.

## Microsoft 365 Copilot evidence

Use a separate Entra app registration for application-only Microsoft Graph access. Grant and administratively consent to:

- `AiEnterpriseInteraction.Read.All` — reads enterprise Copilot prompts and responses.
- `User.ReadBasic.All` — enumerates the users whose interaction histories will be queried. This is unnecessary when `M365_COPILOT_USER_IDS` explicitly lists every monitored user.

Configure `M365_COPILOT_TENANT_ID`, `M365_COPILOT_CLIENT_ID`, and `M365_COPILOT_CLIENT_SECRET`. JO AI Monitor obtains an app-only Graph token, queries each user's `interactionHistory/getAllEnterpriseInteractions` endpoint, pairs prompts and responses by request ID, and includes accessed resources in the evidence record.

For a limited pilot, set `M365_COPILOT_USER_IDS` to comma-separated Entra object IDs or UPNs. For tenant-wide discovery, leave it empty and set `M365_COPILOT_MAX_USERS` to the desired safety cap. Only Microsoft 365 experiences that write to the interaction history service are returned; consumer accounts and Copilot Studio agent interactions are outside this API's coverage.

## Risk thresholding

Every record is evaluated by an explainable 0–100 rules engine before it enters the findings queue. The response includes `risk_score`, `risk_factors`, and `risk_rule_version`; the interface displays the score beside its severity.

- 80–100: critical
- 60–79: high
- 40–59: medium
- 20–39: low
- 0–19: informational

Set `RISK_FINDING_THRESHOLD` to the minimum score that should become a full finding (default `40`). Below-threshold content is not retained by JO AI Monitor. Only minimal suppression metadata is stored: source evidence ID, provider, user ID, surface, score, rule version, observation time, and suppression reason. The upstream provider remains the system of record.

The initial rules detect unauthorized access, evasion, credential exposure, production targeting, data exfiltration, regulated/personal data, confidential information, malware/exploit requests, and destructive actions. Treat the supplied weights as a transparent starting policy requiring organizational review before production.

## Access audit

JO AI Monitor writes an append-only audit event for local and Entra sign-ins, failed sign-ins, sign-outs, searches and filters, evidence views, exports, provider views, directory/activity access, and audit-log access. Each event includes actor, timestamp, source IP, user agent, action, object, and structured context.

Audit entries form a SHA-256 hash chain: every record includes the prior record's hash, and `/api/audit` verifies the chain before returning results. The **Access audit** navigation item displays the ledger and its current integrity status. Persist `DATABASE_PATH` on durable storage; Docker Compose maps it to `/data/jo-ai-monitor.db`.
