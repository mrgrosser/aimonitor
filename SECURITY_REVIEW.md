# JO AI Monitor Security Review Handoff

This checklist prepares version 0.9.5 for review by Security, Compliance, Privacy, and Infrastructure. It does not represent production approval.

## Review scope

- Entra sign-in, application roles, group allowlists, page/API authorization, and emergency local access.
- Claude Compliance and Microsoft Graph permissions and secret handling.
- Named-user reporting, prompt evidence, attachments, audit data, exports, and retention.
- Policy lifecycle, separation of duties, scoped thresholds, exceptions, and the IT-only approved application-generation control.
- Pangolin TLS termination, cookie security, network exposure, backups, restoration, and incident response.

## Required evidence before production approval

- Architecture and data-flow diagram with trust boundaries.
- Entra assignments and negative authorization test results.
- Provider permission and admin-consent inventory.
- Data classification, privacy impact assessment, retention schedule, and deletion/legal-hold test.
- Threat model, dependency/container scans, penetration-test results, and remediation record.
- Backup restoration, rollback, audit-chain verification, and export-verification results.
- Named owners for the service, policies, investigations, privacy, support, and emergency access.

## Pilot safeguards

- Keep local access only while a monitored emergency-access procedure exists; disable it after Entra recovery is validated.
- Set `COOKIE_SECURE=true`, use a strong session secret, and keep secrets outside the image and repository.
- Limit Graph user discovery with an explicit pilot list or reviewed safety cap.
- Treat prompts, responses, named usage, attachments, and audit identities as sensitive monitoring data.
- Require human review before disciplinary, access-control, or other adverse action.
- Keep Rapid7 forwarding disabled until its audit-only field allowlist and destination are approved; validate the payload preview and test event before enabling it.

## v1.0 exit criteria

The application remains pilot software until every roadmap approval gate is recorded, authorization and restore tests pass, operational ownership is assigned, and Security and Compliance provide written production approval.
