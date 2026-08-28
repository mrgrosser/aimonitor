# JO AI Monitor Roadmap

JO AI Monitor is evolving from an AI compliance evidence explorer into a provider-neutral AI governance platform covering security, investigations, auditability, adoption, cost, licensing, and executive reporting.

> **Approval status:** JO AI Monitor has not yet received formal Security or Compliance approval. Current releases should be treated as evaluation and pilot software. Features involving named-user monitoring, prompt content, retention, alerting, or automated enforcement must pass the approval gates below before production use.

## Product principles

- Preserve evidence fidelity and provenance.
- Keep security findings separate from adoption and productivity analytics.
- Never treat usage volume as employee performance.
- Collect and retain the minimum data required for the approved purpose.
- Make risk scoring, suppression, access, exports, and administrative changes explainable and auditable.
- Default leadership reporting to aggregate or anonymized data.
- Use read-only provider permissions unless a separately approved control requires write access.
- Support multiple AI providers through a normalized evidence and usage model.

## Delivered: v0.1–v0.8

- Docker and Docker Compose deployment, including Komodo/Gitea-compatible local image builds.
- Standard authentication with signed HTTP-only sessions.
- Microsoft Entra ID OIDC/SSO with role and group allowlisting.
- Anthropic Claude Compliance API evidence collection.
- Microsoft 365 Copilot prompt, response, and accessed-resource collection through Microsoft Graph.
- Searchable evidence queue with provider, surface, identity, time, and transcript context.
- Fixed slide-over evidence drawer and viewport-pinned navigation.
- Explainable 0–100 risk scoring with configurable finding threshold.
- Minimal metadata recording for below-threshold evidence.
- JSON evidence export.
- Append-only, SHA-256 hash-chained access audit.
- Auditing of authentication, searches, views, exports, directory access, provider access, and usage analytics access.
- Leadership demo mode with 100 realistic, threshold-qualified findings.
- Usage & Spend dashboard covering adoption, applications, products, models, licensing, budgets, and anonymized utilization.
- Visible runtime version and cache prevention for deployment verification.

## v0.7: Reports and analytics ingestion — delivered

**Goal:** Make JO AI Monitor useful for recurring leadership, Security, Legal, Finance, and Compliance reviews.

### Delivered in v0.7.0

- Executive PDF, CSV, JSON, and printable HTML reports.
- Reporting-period selector and historical period archive.
- XLSX and normalized CSV import with preview and validation.
- Source fingerprint, duplicate protection, replacement confirmation, and reconciliation warnings.
- Stable anonymization of imported user identities.
- Audit events for report generation, import preview, and confirmed import.

### Delivered in v0.7.2

- Compliance finding reports with severity, category, disposition, evidence identifiers, rule versions, and provenance.
- Custom date, severity, and provider-surface filters.
- Month-over-month adoption, spend, risk, and finding trends.
- Persistent daily, weekly, and monthly report schedules with optional SMTP delivery and audited outcomes.
- Connector-status reporting for live Compliance, Microsoft Graph, imported analytics, and SMTP capabilities.
- Role-aware named-user reporting, hidden by default and approval-gated through Entra application roles.

### Acceptance criteria

- Imported totals reconcile to source totals before publication.
- Reports show period, generation time, actor, source, filters, and version.
- Copilot interactions and Claude API requests remain separate units.
- Named-user sections require an approved role and are omitted by default.
- Re-running an identical import does not duplicate the reporting period.

## v0.8: Investigation and case management — delivered

**Goal:** Turn detected findings into a complete analyst review workflow.

### Delivered in v0.8.0

- Durable cases with priority, assignment, due dates, descriptions, and tags.
- New, Investigating, Confirmed, Benign, Accepted Risk, and Closed states.
- Required disposition reasons for benign, accepted-risk, and closed outcomes.
- Analyst notes with a complete actor-and-timestamp case timeline.
- Stable evidence snapshots linked independently of upstream provider changes.
- Related-finding suggestions using identity, indicator, provider surface, and risk context.
- Case-level PDF and JSON evidence packages separating evidence from analyst commentary.
- Audited case creation, search, views, updates, notes, links, and exports.
- Full-page analyst queue and case-detail interface, including seeded demo investigations.

### Delivered in v0.8.1

- Threaded comments and type/size-restricted, SHA-256-hashed file attachments.
- Custom categories and escalation states for watch, management, incident response, and legal review.
- Reason-required bulk assignment, tagging, status, priority, and escalation changes plus bulk ZIP export.
- Configurable time-window controls for related-finding correlation.
- Administrator-controlled legal holds with reasons and audited release.
- Saved personal/shared reviewer queues with persisted filters.
- Entra role enforcement separating case readers, investigators, and legal-hold administrators.

### Delivered in v0.8.2

- Server-enforced page authorization with configurable Entra application-role mappings.
- Reports-only and usage-reader experiences with unauthorized navigation removed.
- Role-restricted named-user adoption detail showing Claude products and Copilot applications in use.
- Persistent light and dark appearance modes.

### Delivered in v0.8.3

- Expandable user-adoption rows with product/application usage, share, spend, and calculation basis.
- Exact Copilot interaction attribution by host app and clearly labeled included-license economics.
- Claude per-product user spend allocation labeled as estimated where the provider source lacks a cross-tab.
- Explicit accessible appearance switch replacing the text-only theme control.

### v0.7 completion audit

The v0.7 acceptance criteria were regression-tested during v0.8.1. Usage imports retain duplicate protection and reconciliation warnings; reports retain actor, generation time, source, filters, and version metadata; Copilot interactions and Claude requests remain separate units; named-user reports remain role-restricted and excluded by default; and identical imports do not duplicate reporting periods.

### Acceptance criteria

- Every case mutation records actor, time, old value, new value, and reason.
- Evidence and analyst commentary are distinguishable in exports.
- Legal-hold records cannot be deleted through ordinary retention workflows.
- Users can access only cases permitted by their assigned role and scope.

## v0.9: Policy, detection, and alerting

**Goal:** Make detection policy configurable and connect JO AI Monitor to operational security workflows.

### Planned capabilities

- Administrative editor for rules, weights, severities, and thresholds.
- Versioned policy packs with draft, review, approval, activation, and rollback.
- Per-provider, surface, business-unit, and category thresholds.
- Documented allowlists, approved workflows, and time-bounded exceptions.
- Repeat-event and behavioral-risk correlation.
- Cost, budget, model, and unused-license alerts.
- Email and Microsoft Teams notifications.
- Generic outbound webhooks with signing and retry handling.
- SIEM export using normalized JSON and common event fields.
- OpenTelemetry logs, traces, and metrics.
- Alert acknowledgement, suppression, ownership, and escalation.
- Optional real-time intervention only where provider support and formal approval permit it.

### Acceptance criteria

- Policy changes are reviewed and audited before activation.
- Every finding identifies the exact policy version and contributing factors.
- Notifications contain minimal necessary data and link back to authorized views.
- Failed deliveries retry safely without creating duplicate incidents.

## v1.0: Production hardening

**Goal:** Meet the technical and governance requirements for an approved production deployment.

### Identity and authorization

- Entra application roles for Viewer, Reviewer, Investigator, Auditor, Report Reader, and Administrator.
- Route-level and object-level authorization enforcement.
- Separation of duties for policy approval, investigation, audit, and administration.
- Emergency local-access procedure with monitoring and expiration.
- Workload identity or certificates in place of long-lived client secrets where supported.

### Data and reliability

- Postgres support and controlled schema migrations.
- Durable object storage for evidence and generated reports.
- Configurable retention, deletion, preservation, and legal-hold policies.
- Cryptographically signed export manifests.
- Background synchronization, pagination, checkpoints, replay safety, and idempotency.
- Provider rate-limit handling, retry policies, and dead-letter processing.
- Backup, restoration, disaster recovery, and integrity-verification procedures.

### Engineering and operations

- Automated unit, integration, browser, migration, and authorization tests.
- Dependency, container, secret, and source-code security scanning.
- Gitea/Komodo CI/CD pipeline with immutable versioned images.
- Software bill of materials and release provenance.
- Structured logging, health checks, metrics, dashboards, and operational alerts.
- Upgrade, rollback, incident-response, and support documentation.
- Performance testing using production-representative volumes.

## Post-1.0 expansion

- GitHub Copilot telemetry and governance where supported.
- Copilot Studio and enterprise agent activity where supported.
- Additional approved enterprise AI providers.
- Provider-neutral evidence, identity, usage, cost, and policy schemas.
- Cross-provider identity and campaign correlation.
- Executive governance scorecards and organizational benchmarks.
- API for approved downstream reporting, SIEM, GRC, and case-management systems.

## Security and Compliance approval gates

The following gates apply before production use. A capability may be built and demonstrated before its gate is approved, but it must remain disabled or restricted in production until approval is recorded.

### Gate 1: Purpose and policy

- Approved business purpose and documented prohibited uses.
- Confirmation that monitoring is not used as employee productivity scoring.
- Acceptable-use, notification, consent, and labor-relations review where applicable.
- Defined owners for Security, Compliance, Legal, Privacy, HR, and the service.

### Gate 2: Data governance

- Data classification and privacy impact assessment.
- Approved fields, providers, identities, prompts, responses, and accessed-resource metadata.
- Retention, deletion, legal hold, residency, and cross-border requirements.
- Rules for named-user reporting, redaction, anonymization, and aggregate thresholds.

### Gate 3: Security architecture

- Threat model and architecture review.
- Provider permission and Entra consent review.
- Secrets management, encryption, TLS, network exposure, and workload identity review.
- RBAC, separation of duties, audit access, and emergency-access approval.
- Vulnerability testing and remediation requirements.

### Gate 4: Detection and response

- Approved risk taxonomy, weights, thresholds, exceptions, and review cadence.
- False-positive and false-negative evaluation.
- Defined investigation, escalation, notification, and incident-response procedures.
- Human review required before adverse or enforcement action.

### Gate 5: Production readiness

- Backup and restoration test.
- Retention and deletion test.
- Authorization and tenant-isolation test.
- Audit integrity and export-verification test.
- Monitoring, support, rollback, and incident-response runbooks.
- Written Security and Compliance production approval.

## Prioritization

1. Reports and monthly analytics ingestion.
2. Case management and durable evidence retention.
3. Formal RBAC and Security/Compliance approval controls.
4. Policy administration, notifications, and SIEM integration.
5. Production reliability and automated delivery pipeline.
6. Additional providers and advanced cross-provider correlation.

## Roadmap status definitions

- **Delivered:** implemented and available in the current release.
- **Planned:** accepted direction, not yet implemented.
- **Approval-gated:** may be implemented for evaluation but cannot be enabled in production without the applicable approval.
- **Exploratory:** dependent on provider APIs, licensing, organizational policy, or technical validation.

This roadmap is directional and should be reviewed after each milestone, provider API change, risk assessment, and Security or Compliance decision.
