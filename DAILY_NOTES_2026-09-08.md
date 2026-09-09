# Daily Notes — September 8, 2026

## JO AI Monitor

Worked through the initial live rollout of JO AI Monitor, connecting Claude and Microsoft 365 Copilot evidence and usage reporting, resolving production integration issues, and preparing for a broader pilot.

## Application and deployment

- Reviewed and hardened the application ahead of live use.
- Added System appearance mode alongside Light and Dark.
- Added the blue JO favicon.
- Committed and pushed iterative releases to GitHub for transfer to the internal Gitea repository and deployment through Komodo.
- Worked through the GitHub download → Gitea workflow, branch selection, stale source downloads, and version/cache verification.
- Continued using SQLite; PostgreSQL remains a future scaling and production-hardening consideration rather than an immediate small-pilot prerequisite.

## Claude evidence collection

- Configured the Claude Compliance key and enabled live mode.
- Confirmed live evidence ingestion and diagnosed incomplete synchronization.
- Addressed HTTP 429 rate limiting with shared request pacing, Retry-After cooldowns, and retry/backoff behavior.
- Corrected conflated risk scoring: user-authored content contributes to screening; assistant output, generated titles, summaries, and resource labels do not.
- Clarified that below-threshold conversations can be collected without appearing in the findings queue.
- Kept scoring framed as keyword screening requiring analyst review, not proof of an incident.

## Microsoft 365 Copilot evidence

- Configured Entra application permissions and admin consent for interaction collection and user discovery.
- Enabled collection beyond an explicitly configured single user.
- Diagnosed per-user HTTP 403 failures during broad directory discovery and reviewed licensed-user targeting.
- Fixed HTML markup/entity display in Copilot evidence.
- Fixed long evidence identifiers stretching the table across the screen.
- Replaced generic Human labels with the actual user in verbatim evidence.

## Reporting and analytics

- Built monthly reports using the supplied Copilot/Claude Excel workbook as the reference.
- Added Excel, PDF, and print outputs, report sections, and pagination.
- Added charts and restrained visual styling.
- Removed audience-specific Leadership branding.
- Separated current-month Usage & spend from completed-month Reports.
- Implemented automatic Claude analytics collection; live reporting no longer requires workbook imports.
- Implemented Microsoft Graph Copilot adoption collection using Reports.Read.All.
- Corrected Claude spend normalization from fractional cents to USD, including legacy cached values.
- Kept seat fees separate from reported usage spend.
- Resolved Microsoft's CSV-only response, HTTP 302 preauthenticated report downloads, and reportsncu.office.com host validation.
- Kept bearer credentials out of redirected report downloads.
- Improved provider error diagnostics in the UI, audit records, and Docker logs.
- Confirmed successful collection for both providers.

## Report presentation

- Gave Claude and Copilot explicit provider headings.
- Applied warm orange styling to Claude and teal to Copilot.
- Added readable reporting-month and product labels.
- Added reporting dates, retrieval times, and estimated next refresh.
- Collapsed explanatory notes and removed redundant aggregate identity notices.
- Removed duplicate Copilot overview content when opening its detail report.
- Extended provider colors to charts and exports.

## Historical Copilot reporting

- Added historical daily Copilot activity alongside Claude monthly reports.
- Backfilled available months from existing cached rolling reports.
- Added retained snapshots so rolling-window refreshes do not erase collected history.
- Labeled day coverage and partial months explicitly.
- Kept monthly unique users unavailable where only daily aggregates exist; daily user counts cannot be summed into a distinct monthly count.

## Latest pushed release

- **v0.10.11 — dc5dc56**, pushed to GitHub main.
- Includes historical Copilot reporting and snapshot retention.
- Previous polish release: **v0.10.10 — 1a13cf5**.

## Stabilization work completed locally — not yet pushed

- Replaced historical Unavailable cards with average and peak daily active users.
- Average includes reported zero-activity days and excludes missing dates; coverage is shown.
- Retained daily enabled-user counts when supplied and included dated values in report tables.
- Updated historical PDF and print summaries to match the new metrics.
- Added checks for Excel metric parity, PDF generation, monthly UI cards, and partial-month calculations.
- Added a read-only SQLite restore verification tool for integrity, foreign-key checks, and table counts.
- Added a GitHub test workflow; it does not deploy or publish images.
- Corrected outdated scoring documentation and updated roadmap/launch notes.
- Created ROLLOUT_CHECKLIST.md with owners and procedures for reconciliation, access testing, recovery, release controls, scoring review, retention, and approval status.
- **Validation: all 126 unit tests and report browser checks passed.** These are local checks, not production acceptance evidence.

## Remaining before broader access

- Reconcile one complete month against actual Claude and Microsoft source reports.
- Test deployed Reports-only, reviewer, and administrator accounts, including direct API and export access.
- Restore a real backup into an isolated environment and verify reports, cases, attachments, and audit integrity.
- Integrate controlled image builds, deployment checks, and rollback into Gitea/Komodo.
- Evaluate scoring against representative flagged and unflagged conversations.
- Agree analytics snapshot retention and stale-collection alerting requirements.
- Record the authorized audience, operational owners, and Security/Compliance approval status.

## Important reporting distinctions

- Claude requests, Copilot interactions, and Copilot active users are different units.
- Copilot rolling unique-user totals are not calendar-month unique-user totals.
- Historical daily activity cannot reconstruct monthly distinct users without an appropriate source.
- A healthy application endpoint does not establish that every collector is current.
- Persistent storage does not replace a tested backup and restore procedure.
