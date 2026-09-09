# Workbook reporting coverage

Reference: AI_Usage_Copilot_and_Claude_August2026.xlsx, 11 sheets. The reference was inspected read-only. No named source records or workbook copy were added to the repository.

## Automatic sources

- Claude Enterprise Analytics: monthly organization totals plus paginated user/product/model usage and cost. Requires the existing `read:analytics` scope. Requests come from usage rows; cost rows are joined separately. Amount and list amount use the existing cents-to-USD normalization. User totals cover seat-attributed traffic; organization totals can also include API-key/automation traffic.
- Microsoft Graph adoption: rolling licensed-user reports, including inactive entries. Requires existing `Reports.Read.All`. These are distinct from audit interaction counts and may have concealed identities.
- Microsoft Purview: optional Graph audit queries filtered to `CopilotInteraction`, with query IDs persisted across polls/restarts. Requires application `AuditLogsQuery.Read.All` and admin consent. Set `M365_PURVIEW_ANALYTICS_ENABLED=true`. `M365_PURVIEW_MONTHS=3` requests current and two previous calendar months by default. No tenant query was made during implementation.
- Entra directory: optional dated snapshots of enabled users, department, UPN and mail. Requires application `User.Read.All` and admin consent. Set `USAGE_DIRECTORY_ENABLED=true`. This uses Entra data, which may differ from an on-premises AD export. Snapshots cannot prove historical headcount before collection began.

## Sheet coverage

| Workbook sheet | Implemented reporting path | Source limits |
|---|---|---|
| AI Usage Summary | Provider summaries, active users, separate request/interaction counts, spend, app/product mix | Provider reports keep populations and periods separate. Claude's workbook-specific agent-assisted definition is not inferred from request volume. |
| Department Summary | Dated directory headcount, mapped/unmapped users, adoption, provider volume and spend | Directory connector required. Ratios use the labeled snapshot; no denominator for unmatched accounts. |
| Copilot User by App | Full user/app interaction matrix, apps used, active days, agent interactions | Requires Purview. Includes unlicensed activity returned by that source. |
| Claude User by Product | Full user/product request matrix, products and models used, exact user spend | Requires successful detailed Analytics API collection. |
| Copilot App Totals | Interactions, distinct users, average per user, share, original app-host grouping | Uses deduplicated audit records, not rolling Graph adoption totals. |
| Copilot Agents | Agent interactions, distinct users, primary host | Supports TargetAgentName, AgentName and Copilot Studio AppIdentity fallback when supplied. Live raw-field variants still need tenant verification. |
| Copilot Daily Trend | UTC calendar-day interactions and distinct users, including zero days in a completed query interval | Provider ingestion and retention affect availability. |
| Claude Product & Model | Requests, spend and shares by product/model | Shares are explicitly of returned groups; organization headline totals remain ungrouped. |
| Copilot Detail | User, UTC time, grouped/raw app, observed license type, agent, resource count | No prompts, responses, resource names or URLs stored. Missing fields remain unknown. |
| Claude Detail | User, product, model, requests, prompt/completion tokens, net/list spend | Prompt tokens include cache read/creation. No fabricated daily breakdown from the workbook. |
| Notes & Caveats | Provider provenance, dates, coverage and missing-data explanations | Reference-specific historical claims are not copied into new periods. |

A separate dated **Copilot licensed users** section accompanies Purview monthly reports when the existing Graph roster is available. Inactive license-report entries remain visible there. This is report membership, not a real-time licensing inventory.

## Interface and exports

Current-month Usage and completed-month Reports use the new sections. Search and pagination apply to every section. Excel, CSV, JSON and print/HTML include the full detailed sections. PDF remains a summary report with its existing top-user selection, not an exhaustive interaction transcript. Named-user access is applied before generating new sections and exports; restricted identities use aliases.

## Reference reconciliation

The existing workbook importer accepts all 11 sheets. Recomputing Copilot summaries, users, apps, agents and daily counts from its normalized interaction detail matches the workbook when using its actual date coverage.

Two discrepancies should not be reproduced as calendar-month facts:

- The detail and daily trend include 17 September 1 records. There are 8,839 records strictly within August, versus the workbook's 8,856 across its full source coverage. Live monthly queries use an exclusive next-month boundary.
- The directory notes describe 194 enabled accounts, but Department Summary totals 191. The original AD snapshot is needed to explain that difference.

Agent-table footer lines were previously interpreted as agents by the importer; parsing now stops at the total-agent-assisted footer.

## Deployment validation still required

Enable the new optional sources only after permissions are granted, rebuild/restart, and check source collection status. Confirm at least one real Purview record's license/agent fields, compare exact UTC intervals against Purview, and verify Claude net/list amount normalization against the provider portal. Validate Entra department/headcount coverage against the desired directory population. Empty completed queries cannot prove that all expected event types were returned by the tenant. Previous successful reports survive collection failures.

Run `python tools/check_workbook_coverage.py <reference.xlsx>` for read-only reference reconciliation. Unit tests use synthetic records only.

Sources: [Claude per-user cost](https://platform.claude.com/docs/en/api/http/admin/analytics/cost/list_by_user), [Purview audit query API](https://learn.microsoft.com/en-us/graph/api/security-auditcoreroot-post-auditlogqueries?view=graph-rest-1.0), [Copilot event schema](https://learn.microsoft.com/en-us/office/office-365-management-api/copilot-schema), [Graph users](https://learn.microsoft.com/en-us/graph/api/user-list?view=graph-rest-1.0).


## Tenant export validation — September 9, 2026

The supplied audit CSV parsed all 1,531 records, covering September 2–8 UTC and 63 distinct users. Observed event license types: Starter 688, Premium 418, Unknown 425. These are event attributes, not a current license inventory. User identities and raw audit content were not copied into the repository. This validates CSV field compatibility; the deployed Graph query still requires an end-to-end collection check.

After deploying this patch through the existing GitHub → Gitea → Komodo build workflow, set the following in the application's deployment environment and rebuild/restart:

```dotenv
M365_PURVIEW_ANALYTICS_ENABLED=true
M365_PURVIEW_MONTHS=1
```

Use the existing Microsoft application credentials, with application `AuditLogsQuery.Read.All` granted admin consent. Keep the existing licensed-user collector enabled. The additional audit collector supplies observed interactions across returned users. Check Usage/Reports collection status for a completed Copilot monthly report; queries are asynchronous. Compare a matching UTC interval with the audit export. Increase months only after the first successful collection. Directory enrichment is optional and separately requires `User.Read.All`.


## 0.10.13 summary exports and departments

PDF and Print report now contain provider-specific metrics, charts, department summary when available, product/application summaries, and at most ten users per provider. Individual interaction records and full user lists remain in Download Excel, CSV/JSON, and on-screen sections; they are excluded from summary printouts.

To enable department summaries, grant Microsoft Graph application `User.Read.All` with admin consent and set `USAGE_DIRECTORY_ENABLED=true` in the deployed environment, then restart. The existing Microsoft credentials are reused. Enabled Entra accounts are matched to Claude and Copilot usage by email or userPrincipalName. The report labels the directory observation date; applying today's directory to an older month does not establish historical department membership. Unmatched users remain unmapped.
