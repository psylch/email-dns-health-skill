# Email DNS Health

[中文文档](README.zh.md)

A zero-dependency email DNS health checker skill for AI coding agents. Audits SPF, DKIM, DMARC, BIMI, MTA-STS, and MX records using only `dig` and `jq`. Detects email providers, counts SPF DNS lookups against the 10-lookup limit, grades overall email health A-F, and provides actionable fix guidance.

## Installation

### Via skills.sh (recommended)

```bash
npx skills add psylch/email-dns-health-skill -g -y
```

### Manual Install

```bash
git clone https://github.com/psylch/email-dns-health-skill.git ~/.claude/skills/email-dns-health
```

Restart your agent after installation.

## Prerequisites

- Any AI coding agent that supports [skills.sh](https://skills.sh/) (Claude Code, Cursor, Windsurf, etc.)
- `dig` (DNS lookup utility)
- `jq` (JSON processor)

## Usage

The skill activates automatically when you mention email DNS topics. Example prompts:

- "Check email DNS for example.com"
- "Audit SPF/DKIM/DMARC for my domain"
- "How many SPF DNS lookups does example.com use?"
- "What email provider is example.com using?"
- "Help me set up email DNS for Google Workspace"
- "Fix my domain's email deliverability"

### Commands

| Command | Description |
|---------|-------------|
| `audit <domain>` | Full email DNS health check with A-F grade |
| `check-spf <domain>` | SPF validation with DNS lookup counting |
| `check-dkim <domain> [selector]` | DKIM key validation (auto-detects selectors) |
| `check-dmarc <domain>` | DMARC policy validation |
| `detect-provider <domain>` | Detect email provider from MX/SPF |
| `setup-guide <provider>` | DNS setup guide for a provider |
| `fix <domain>` | Interactive fix workflow (supports Cloudflare API) |

### Sample Output

```
[Email DNS Health] Audit Complete

Domain: example.com
Grade: A
Score: 100/120 (core 100/100 + bonus 0/20)

Core (determines deliverability):
  SPF:     ✓ valid (7/10 lookups)              30/30
  DKIM:    ✓ valid (2048-bit RSA)              30/30
  DMARC:   ✓ strong (policy: reject)           40/40

Bonus (nice-to-have):
  BIMI:    ✗ missing                            0/10
  MTA-STS: ✗ missing                            0/10

MX: ✓ valid (provider: Google Workspace)

Issues: 0
```

## License

MIT
