---
name: email-dns-health
description: "Audit and validate email DNS records (SPF, DKIM, DMARC, BIMI, MTA-STS, MX) for any domain. Detect email providers, count SPF DNS lookups, grade overall health A-F, and provide fix guidance. Use when the user says 'check email DNS', 'audit SPF/DKIM/DMARC', 'email deliverability check', 'detect email provider', 'fix email DNS', 'setup email records', or 'email health score'."
---

# Email DNS Health

## Language

**Match user's language**: Respond in the same language the user uses.

## Overview

A zero-dependency email DNS health checker that uses `dig` and `jq` to audit SPF, DKIM, DMARC, BIMI, MTA-STS, and MX records. It detects email providers, counts SPF DNS lookups against the 10-lookup limit, grades overall email health A-F, and provides actionable fix guidance.

## Commands

| Command | Usage | Description |
|---------|-------|-------------|
| `audit` | `audit <domain>` | Full email DNS health check with grade |
| `check-spf` | `check-spf <domain>` | SPF validation with DNS lookup counting |
| `check-dkim` | `check-dkim <domain> [selector]` | DKIM key validation (auto-detects selectors) |
| `check-dmarc` | `check-dmarc <domain>` | DMARC policy validation |
| `detect-provider` | `detect-provider <domain>` | Detect email provider from MX/SPF |
| `setup-guide` | `setup-guide <provider>` | DNS setup guide for a provider |
| `fix` | `fix <domain>` | Interactive fix workflow (Cloudflare API) |

## Workflow

Progress:
- [ ] Step 1: Run preflight check
- [ ] Step 2: Determine command from user request
- [ ] Step 3: Execute command via helper script
- [ ] Step 4: Present results with actionable guidance
- [ ] Step 5: Offer follow-up actions

### Step 1: Preflight

Run the helper script to check environment readiness:

```bash
bash {SKILL_DIR}/scripts/email-dns-health.sh preflight
```

Output is JSON. If `ready` is `true`, proceed. If `false`, follow the `hint` field.

| Check | Fix |
|-------|-----|
| `dig` not found | `brew install bind` (macOS) or `apt install dnsutils` (Linux) |
| `jq` not found | `brew install jq` (macOS) or `apt install jq` (Linux) |

### Step 2: Determine Command

Map the user's request to a command:

| User intent | Command |
|-------------|---------|
| "Check my domain's email setup" / "audit email DNS" | `audit` |
| "Check SPF" / "how many DNS lookups" | `check-spf` |
| "Check DKIM" / "verify DKIM key" | `check-dkim` |
| "Check DMARC" / "DMARC policy" | `check-dmarc` |
| "What email provider" / "detect provider" | `detect-provider` |
| "How to set up email for [provider]" | `setup-guide` |
| "Fix email DNS" / "update records" | `fix` |

### Step 3: Execute Command

Run the appropriate command:

```bash
bash {SKILL_DIR}/scripts/email-dns-health.sh <command> <args...>
```

All commands output JSON to stdout. Parse the JSON response.

### Step 4: Present Results

Format the JSON output into a human-readable report:

**For `audit`**: Present each record type (SPF, DKIM, DMARC, BIMI, MTA-STS, MX) with status indicators, the overall grade, and specific recommendations.

**For `check-spf`**: Show the SPF record, DNS lookup count (with breakdown), and warnings if approaching the 10-lookup limit.

**For `check-dkim`**: Show key details (algorithm, key length, flags) and security assessment.

**For `check-dmarc`**: Show the DMARC policy, reporting addresses, and deployment stage assessment.

**For `detect-provider`**: Show detected provider(s) with confidence level.

**For `setup-guide`**: Read `{SKILL_DIR}/references/provider-configs.md` and present the step-by-step guide for the requested provider.

**For `fix`**: This is an interactive workflow. Read the audit results, identify issues, and guide the user through fixes. If the user has a Cloudflare API token (in `$CLOUDFLARE_API_TOKEN` or `~/.claude/email-dns-health/.env`), offer to apply DNS changes automatically via the Cloudflare API. Otherwise, provide the exact DNS records to add/modify manually.

### Step 5: Follow-up

After presenting results, offer relevant next steps:
- If issues found: suggest `fix` command
- If SPF lookups high: suggest provider-specific optimizations (read `references/best-practices.md`)
- If no DMARC: suggest progressive deployment plan
- If DMARC at `none`: suggest advancing to `quarantine`
- If non-sending domain detected: suggest null record setup

## Degradation

| Dependency | Required | Behavior when unavailable |
|------------|----------|--------------------------|
| `dig` | Yes | Cannot run any checks - halt and guide installation |
| `jq` | Yes | Cannot parse results - halt and guide installation |
| `CLOUDFLARE_API_TOKEN` | No | `fix` command falls back to manual guidance mode |

## Completion Report

After `audit` or `fix` commands, present:

```
[Email DNS Health] Audit Complete

Domain: <domain>
Grade: <A-F>

Records:
  SPF:    <status> (<lookup_count>/10 lookups)
  DKIM:   <status> (<key_length>-bit <algorithm>)
  DMARC:  <status> (policy: <policy>)
  BIMI:   <status>
  MTA-STS: <status>
  MX:     <status> (provider: <provider>)

Issues: <count>
Recommendations:
  1. <recommendation>
  2. <recommendation>
```

## Troubleshooting

| Symptom | Resolution |
|---------|------------|
| `dig` returns SERVFAIL | DNS server issue; try `dig @8.8.8.8 <domain> TXT` |
| DKIM selector not found | Try common selectors: `default`, `google`, `selector1`, `k1`, `mx` |
| SPF lookup count exceeds 10 | Use CNAME-based providers (SendGrid, SES) to reduce lookups; read `references/best-practices.md` |
| Cloudflare API 403 | Token needs `Zone:DNS:Edit` permission; regenerate at dash.cloudflare.com |

## References

For detailed provider DNS configurations, read `{SKILL_DIR}/references/provider-configs.md`.
For SPF/DKIM/DMARC best practices, read `{SKILL_DIR}/references/best-practices.md`.
For common issues and troubleshooting, read `{SKILL_DIR}/references/troubleshooting.md`.
