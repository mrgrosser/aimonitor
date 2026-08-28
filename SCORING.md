# JO AI Monitor Risk Scoring

JO AI Monitor currently uses a deterministic, explainable rules engine. Demo mode supplies synthetic evidence, but the score itself is not hardcoded: prompts, responses, summaries, and accessed-resource context are evaluated at request time. Live Claude and Microsoft 365 Copilot evidence follows the same scoring path.

## Current scoring process

1. Combine the evidence title, summary, prompt/response messages, and accessed-resource names/types into an evaluation string.
2. Evaluate the string against each versioned policy rule.
3. Add the weight of every matched rule once.
4. Cap the result at 100.
5. Assign severity from the resulting score.
6. Promote the record only when it meets `RISK_FINDING_THRESHOLD`.

The seeded baseline policy version is `rules-2026.08.2`. From v0.9.0 onward, the active version is stored in the persistent database and can be managed by a Compliance Administrator through the versioned policy workflow in Settings.

| Factor | Points | Representative indicators |
|---|---:|---|
| Unauthorized access | 45 | hack, bypass, root access, privilege escalation |
| Evasion | 20 | evade detection, hide activity, avoid administrator notice |
| Credential exposure | 25 | passwords, API keys, access tokens, private keys, cloud credentials |
| Production target | 15 | production, live server, customer environment |
| Data exfiltration | 25 | steal, exfiltrate, bundle credentials, send data outside |
| Regulated or personal data | 20 | SSN, credit card, patient records, PHI, PII |
| Confidential information | 40 | confidential, proprietary, trade secrets, customer records, source code |
| Malware or exploit | 30 | malware, ransomware, reverse shell, exploit code, payload |
| Destructive action | 25 | wipe, delete all, drop database, disable logging |

### Severity bands

| Score | Severity |
|---:|---|
| 80–100 | Critical |
| 60–79 | High |
| 40–59 | Medium |
| 20–39 | Low |
| 0–19 | Informational |

The seeded finding threshold is 40. An approved policy version can change it without rebuilding the application. Below-threshold content is not retained by JO AI Monitor; only minimal suppression metadata is recorded.

## Worked example

Prompt: `How do I hack root access on the production Linux server without the admin noticing?`

| Match | Points |
|---|---:|
| Unauthorized access (`hack`, `root access`) | 45 |
| Evasion (`without the admin noticing`) | 20 |
| Production target (`production`) | 15 |
| **Total** | **80 — Critical** |

The evidence record includes `risk_score`, `risk_factors`, and `risk_rule_version`, allowing an investigator to reproduce why it received that severity.

## Why not use an AI-only score

Sending every prompt to a model and accepting one number would introduce material governance problems:

- Scores may vary between runs or model versions.
- A numeric answer may not provide policy-level evidence.
- Prompt content can attempt to manipulate the classifier.
- It adds cost, latency, availability dependencies, and another sensitive-data transfer.
- A classifier may silently miss organization-specific policy requirements.
- An AI score alone is difficult to defend in an investigation or audit.

## Recommended hybrid architecture

An approved model classifier can improve semantic coverage, but it should be an advisory layer around the deterministic policy engine.

1. **Deterministic baseline:** Apply approved rules and record each matched factor.
2. **Semantic classifier:** Ask an approved, pinned model for structured category probabilities, a recommended score, confidence, and short rationale—not an unstructured verdict.
3. **Context enrichment:** Apply policy-controlled modifiers for production targets, sensitive data, privileged identity, repeat behavior, approved exceptions, and accessed resources.
4. **Policy aggregation:** Use a versioned formula. A model may elevate a rule score but should not silently reduce a deterministic critical match.
5. **Human review:** Require an investigator before adverse, disciplinary, access-control, or incident-declaration decisions.

A conservative starting formula is:

```text
semantic_component = round(model_score * model_confidence)
final_score = min(100, max(rule_score, semantic_component) + approved_context_modifiers)
```

If the model is unavailable, malformed, or below its confidence requirement, the deterministic score remains authoritative.

## Classifier safety requirements

- Treat monitored content as untrusted data, never as classifier instructions.
- Use a strict JSON schema and reject unexpected fields.
- Pin and record the provider, model, prompt-template version, and policy version.
- Disable tools, browsing, memory, and external actions for classification.
- Keep content within approved tenant, region, retention, and contractual boundaries.
- Store category factors and confidence; do not retain hidden reasoning.
- Evaluate false positives and false negatives against a human-labeled test set.
- Monitor score drift before and after any model or prompt change.
- Provide a deterministic fallback and a kill switch.

## Approval required before semantic scoring

Security, Compliance, Privacy, and Legal should approve the model/provider, data flow, retention, classifier categories, confidence threshold, aggregation formula, human-review workflow, and evaluation results before semantic scoring is enabled in production.
