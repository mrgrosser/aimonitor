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
