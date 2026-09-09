# Wider rollout validation

Status: local checks do not establish deployment approval. Record dates, deployed commit, tester, and outcomes below before widening access.

## 1. Report reconciliation — service owner and report reviewer

Use August 2026 in both provider portals and this application. Record the provider reporting window and refresh date. Compare Claude ungrouped USD usage spend, requests, and active users. Seat fees are excluded. Compare Copilot daily active counts for the same dates, including zeros. Average daily active users = sum of available daily counts / number of available dates; peak = maximum daily count. Neither is monthly unique users. Confirm coverage, and compare the application's screen, Excel and PDF tables. Keep evidence of discrepancies and their resolution outside the source repository. Do not compare a rolling 30-day unique count to a calendar-month average.

Outcome: pending real source reconciliation.

## 2. Access — Entra administrator and service owner

Assign a dedicated Reports-only test account, a reviewer, and an administrator separately. In fresh browser sessions verify the Reports-only account can preview and export reports but cannot open evidence, audit, settings, or case mutation APIs directly. Verify exports omit restricted identities. Test the reviewer cannot activate policies or perform administrator operations. Remove an assignment, sign out and back in, and confirm access is denied. Record HTTP status and role without copying cookies or tokens. Use synthetic records for mutation checks.

Outcome: pending deployed account tests.

## 3. Recovery — infrastructure owner

Schedule a short maintenance window. Stop the application before making a consistent backup of the entire persistent data volume (database, SQLite sidecars if present, and attachments), preserving permissions. Store configuration and secret recovery material separately with restricted access. Record the deployed image/commit and a file checksum inventory. Restart the service.

Restore a copy into an isolated instance with separate volumes and external delivery/collectors disabled. Never restore over the live volume for a rehearsal. Verify SQLite integrity, report periods, representative cases/attachments, and audit-chain verification. Record elapsed restore time and recovery point. Keep the original backup untouched. Confirm the isolation configuration before starting the restored container.

Outcome: pending backup and restore rehearsal.

## 4. Release — infrastructure and service owner

Build one immutable image per commit. Run unit and browser checks before promoting it. Record the image digest and application version in the deployment record. Rehearse rollback to the previous image against a backup copy of the data; do not assume future schema migrations are backward compatible. Keep GitHub-to-Gitea source synchronization explicit until a reviewed CI pipeline replaces it.

Outcome: pending infrastructure pipeline integration.

## 5. Scoring, collection health and retention — service owner and reviewers

Review a representative sample of flagged and unflagged evidence, recording rule version and false positives/negatives. Treat scores as screening indicators. Agree on how long analytics snapshots should be retained before implementing deletion. No new snapshot deletion is enabled by this release. Check collector success and freshness independently of /health, which only indicates application availability. Define the acceptable stale interval and notification destination before enabling operational notifications.

Outcome: pending reviewer sample, retention decision and monitoring integration.

## 6. Approval record — service owner

Update SECURITY_REVIEW.md and ROADMAP.md after recording the authorized audience, responsible owners, and completed checks. Existing approval status is not changed by this checklist.

## Local tooling

After restoring into isolation, run `python tools/verify_sqlite_restore.py PATH_TO_RESTORED_DATABASE`. It opens the file read-only, reports integrity and foreign-key checks, and prints table counts without row contents. Compare counts to your backup baseline. This does not verify attachments, audit hashes, application authorization, or backup freshness; complete those rehearsal checks separately.

The GitHub Release checks workflow runs unit tests and the report browser smoke test on Windows. It does not deploy or publish images. Configure the corresponding Gitea check and immutable-image promotion in your infrastructure before treating this as a deployment gate.
