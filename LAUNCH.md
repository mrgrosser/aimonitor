# 0.9.7 deployment notes

This release was reviewed for a combined Claude and Microsoft 365 Copilot deployment. Local automated checks do not verify your organization's credentials, Entra assignments, reverse proxy, or production backup.

## Before starting the work deployment

- Set `DEMO_MODE=false` and `COOKIE_SECURE=true`. Use the HTTPS deployment URL, a unique `SESSION_SECRET` of at least 32 characters, and a non-default local password if local login is enabled. Startup now rejects insecure/incomplete live configuration instead of silently loading demo data.
- Configure `ANTHROPIC_COMPLIANCE_ACCESS_KEY` and all three `M365_COPILOT_*` tenant/client/secret settings. Give the Graph app the permissions described in README and validate admin consent. Choose an explicit pilot user list or review the discovery cap.
- Set `FINDINGS_SYNC_MAX_ITEMS=0` for complete pagination. An old value of 2000 now fails visibly if exceeded; it no longer silently accepts the oldest part of the history.
- Register the exact HTTPS Entra callback URL. Validate an administrator and a restricted reviewer account before disabling local authentication. UsageReader cannot import or replace periods; use `USAGE_IMPORT_ROLES` plus Usage page access for approved importers.
- Back up the existing persistent database and attachments before rebuilding. Prefer a separate production volume if the current volume contains demo cases; toggling demo mode does not remove existing synthetic investigations or alerts.

## Rebuild and verify

After the release is committed and pushed, from the deployment checkout:

```sh
git pull origin main
docker compose up -d --build --force-recreate
docker compose logs --tail=100 claude-monitor
```

Confirm `/health` reports version `0.9.7` and mode `live`. Health is HTTP liveness only. Sign in, refresh Evidence, and wait for **Last sync succeeded**. **Sync failed**, **Sync incomplete**, or **Sync pending** does not establish provider coverage; inspect Access audit and the service logs. The status appears after refreshing; it is not a push notification.

Use known, authorized sample activity from both providers to verify transcript text, timestamps, attribution, and finding detection. Verify a restricted account cannot access Settings, Access audit, or imports unless explicitly assigned. Verify reports and exports using representative records. System appearance should follow the workstation's theme, and explicit Light/Dark should survive reloads.

## Policy limitation to resolve for your pilot

The current live normalizers supply user ID and email, not organizational group membership, department, or approval workflow IDs. IT-group exemptions and group/department-scoped policy controls therefore cannot distinguish your IT staff yet. Review those controls with the policy owner; use approved, time-bound user exceptions where appropriate or defer those specific controls until identity/workflow enrichment is implemented. Do not interpret those default app-generation flags as verified unauthorized activity.

## Checks included with this release

- Backend regression suite, including live startup, permissions, provider pagination, transcript normalization, retention boundaries, and report privacy/escaping.
- Headless Edge checks for System / Light / Dark on sign-in and sidebar, operating-system theme changes, reload persistence, invalid preferences, and blocked browser storage (`uv run --with playwright python tools/check_theme.py`).
- Dependency audit with `pip-audit -r requirements.txt`; vulnerable web/auth/upload pins updated. A clean dependency audit is not a penetration test or a validation of tenant configuration.

Provider contracts checked against the [Claude chat messages API](https://platform.claude.com/docs/en/api/http/compliance/apps/chats/messages/list), [Claude remote session messages API](https://platform.claude.com/docs/en/api/http/compliance/apps/sessions/remote/messages/list), and [Microsoft Copilot interaction export API](https://learn.microsoft.com/en-us/microsoft-365/copilot/extensibility/api/ai-services/interaction-export/aiinteractionhistory-getallenterpriseinteractions).

### Claude throttling

Claude requests share a per-process gate with at least 250 ms between attempts. HTTP 429 responses apply a shared cooldown using `Retry-After` (seconds or HTTP date), with exponential fallback and up to five retries of the same request. Exhausted requests remain incomplete and are retried by a later sync. Access audit exposes the status and diagnostic details. Other deployments sharing the organization quota can still cause throttling; this gate is not distributed across replicas.

### Scoring correction (0.9.8)

Risk indicators use user-authored text only. Assistant output, tool blocks, generated titles, summaries, and resource labels do not contribute to the user score. Missing department/groups or workflow approval are unknown, not violations; explicit `approved_workflow=false` represents an unapproved workflow. This remains keyword screening for analyst review, not a determination of intent or a confirmed incident. Unknown roles and non-text attachments are not scored.

At the next sync, retained evidence with an older scoring pipeline is rescored before provider requests. Below-threshold records leave the queue but retain their transcript and original retention clock. Existing investigation snapshots and historical alerts remain historical records. Suppressed metadata from older pipelines is reevaluated when provider content is fetched successfully.

### Copilot discovery

Leave `M365_COPILOT_USER_IDS` empty to discover users. `M365_COPILOT_MAX_USERS=0` follows all directory pages without a user cap (default remains 100). Per-user history failures are audited as `copilot_user_sync_failed` and reported as partial sync coverage while successful users continue. Discovery/token failures still fail the sync. HTML bodies are converted to plain text for display and scoring; the original body is retained in evidence JSON.

### Executive monthly reports

Reports opens automatic monthly analytics with Excel, PDF, and print downloads. Detailed sections have pagination; compliance reports remain available through a separate button.

For CEO access, create/assign the `Compliance.ReportsOnly` Entra application role and include it in `ENTRA_ALLOWED_ROLES` if sign-in is restricted by that setting. This role opens Reports and pseudonymizes email identities throughout previews and exports. It does not allow evidence browsing or imports. To authorize named usage reporting explicitly, add that role to `USAGE_USER_DETAIL_ROLES`; do not grant administrator access simply to enable report downloads. Existing compliance-report authorization remains separate.

SQLite remains in use. Monthly report snapshots are read-heavy and suitable for one app process with the existing persistent volume and backups. Reassess PostgreSQL for multiple replicas or sustained concurrent writers. No database migration is included.

### Automatic Claude analytics (0.10.1)
Live Usage & spend and Reports now collect directly from Claude Enterprise Analytics; no workbook import is required or offered. Live import endpoints are disabled. The collector uses ANTHROPIC_COMPLIANCE_ACCESS_KEY by default, with read:analytics required; an optional ANTHROPIC_ANALYTICS_API_KEY overrides it for a separate analytics key. Keep DEMO_MODE=false and the persistent /data volume.

Startup collects the current month first and backfills up to 12 calendar months (within the provider retention window, starting January 2026). Current and previous months refresh hourly; older cached months refresh daily. Requests share the existing paced HTTP gate and Retry-After backoff. Completed monthly snapshots persist in SQLite; a failed collection leaves the prior snapshot intact. Refresh view reads the cache and does not start another provider request. Analytics status and collection time appear in the report, separately from evidence sync.

Reports include Claude requests, tokens, active users, daily requests, product/model usage and actual USD spend. Copilot usage and seat costs are explicitly unavailable: the Copilot evidence connector is not a complete usage source. Grouped API breakdowns have the provider's top-100-per-day cap; headline totals use ungrouped calls. Historical imported workbooks remain stored but are not used by the live views.

### Automatic Copilot adoption (0.10.2)
Add Microsoft Graph APPLICATION permission `Reports.Read.All` to the existing JO AI Monitor Entra app and grant tenant admin consent. The existing M365_COPILOT_TENANT_ID, M365_COPILOT_CLIENT_ID, and M365_COPILOT_CLIENT_SECRET are reused; no additional credentials or user list is needed. This permission is separate from AiEnterpriseInteraction.Read.All used for evidence.

The Graph v1.0 Copilot UserCountSummary and UserCountTrend reports collect automatically at startup and every six hours. Select Copilot - last 7/30/90/180 days under Usage & spend or Reports. Microsoft supplies rolling adoption windows rather than calendar-month prompt counts; these reports therefore remain separate from Claude monthly reports. Each report shows Microsoft's refresh date. Active users across apps overlap and cannot be added. Costs, prompt counts, and a complete Purview inventory of unlicensed chat activity are not supplied by this source. Failed refreshes preserve the prior snapshot and display the provider error. Existing evidence sync is independent.

Reference: https://learn.microsoft.com/en-us/microsoft-365/copilot/extensibility/api/admin-settings/reports/copilotreportroot-getmicrosoft365copilotusercountsummary

Usage & spend now shows the current UTC calendar month and a separate group of latest Copilot rolling windows. Reports lists only completed months; rolling-window totals are never labeled as historical monthly totals. Copilot usage failures now include Microsoft error text and request ID in the page status and Access audit (`copilot_usage_failed`).
