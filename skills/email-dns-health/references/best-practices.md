# Email DNS Best Practices

## SPF (Sender Policy Framework)

### Core Rules
- **10 DNS lookup limit** is hard-enforced. Exceeding it causes a `permerror` and SPF fails for all emails.
- Use `include:` — avoid `a` and `mx` mechanisms as they waste lookups and are fragile.
- End with `-all` (hard fail) when DMARC is at `reject`. Use `~all` (softfail) during initial rollout.
- Never use `+all` — it allows any server to send as your domain.
- Remove deprecated `ptr` mechanism (RFC 7208).

### Optimization Strategies
- **CNAME-based providers** (SendGrid, SES Easy DKIM, Resend) use 0 SPF lookups. Prefer these for transactional email.
- **Subdomain segmentation**: Use `marketing.<domain>` for bulk mail, `notifications.<domain>` for transactional. Each subdomain gets its own 10-lookup budget.
- **SPF flattening** (tools like `dmarcian` or `autospf`): Converts `include:` to IP ranges. Reduces lookups but requires maintenance as provider IPs change. Use with caution.
- Track lookup costs per provider (see `provider-configs.md` for the cost table).

### Multi-Provider Example
```
v=spf1 include:_spf.google.com include:spf.protection.outlook.com include:spf.infomaniak.ch -all
```
This uses ~7 lookups. Adding SendGrid or SES via CNAME keeps it under 10.

---

## DKIM (DomainKeys Identified Mail)

### Key Management
- **2048-bit RSA minimum**. 1024-bit is crackable with sufficient resources.
- **Rotate keys every 6-12 months**. Use meaningful selector names with dates (e.g., `google-20250101`).
- **Dual signing** (Ed25519 + RSA): Ed25519 is faster and shorter but not universally supported. RSA is the fallback. Where supported, use both.
- **Never reuse selectors** after rotation — old keys remain in DNS caches.

### Selector Naming
- Use descriptive names: `google-20250101`, `sendgrid-s1`, `infomaniak-20250919`
- Avoid generic names like `default` or `key1` — they make troubleshooting harder
- Include dates for rotation tracking

### Common Issues
- DKIM key too long for a single TXT record: Split into multiple strings within one TXT record. Most providers handle this automatically.
- Cloudflare proxying: DKIM TXT records must be DNS-only (gray cloud) — never proxy `_domainkey` records.

---

## DMARC (Domain-based Message Authentication, Reporting, and Conformance)

### Progressive Deployment
1. **Start with monitoring**: `v=DMARC1; p=none; rua=mailto:dmarc@<domain>`
2. **Analyze reports** for 2-4 weeks. Identify legitimate senders failing alignment.
3. **Quarantine with gradual rollout**: `v=DMARC1; p=quarantine; pct=25; rua=...`
4. **Increase pct** to 50, 75, then 100 as compliance improves.
5. **Move to reject** when compliance is >98%: `v=DMARC1; p=reject; rua=...`

### Key Parameters
| Parameter | Values | Notes |
|-----------|--------|-------|
| `p` | none/quarantine/reject | Policy for organizational domain |
| `sp` | none/quarantine/reject | Subdomain policy (defaults to `p` if absent) |
| `pct` | 0-100 | Percentage of messages to apply policy to |
| `rua` | mailto:... | Aggregate report destination |
| `ruf` | mailto:... | Forensic report destination (many providers ignore) |
| `adkim` | r/s | DKIM alignment: relaxed (default) or strict |
| `aspf` | r/s | SPF alignment: relaxed (default) or strict |

### Report Monitoring
- **Free DMARC monitoring**: Cloudflare DMARC Management, Postmark DMARC Digests
- **Advanced**: dmarcian, Valimail, EasyDMARC
- Review reports weekly during rollout, monthly once at reject

---

## BIMI (Brand Indicators for Message Identification)

### Prerequisites
- DMARC at `quarantine` or `reject` (with pct=100)
- SPF and DKIM both passing
- An SVG-P/S formatted logo (SVG Tiny Portable/Secure)
- A VMC (Verified Mark Certificate) for Gmail and Apple Mail display

### Record Format
```
default._bimi.<domain> TXT "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem"
```

### VMC Certificates
- Issued by: DigiCert, Entrust
- Requires a registered trademark
- Cost: ~$1,000-1,500/year
- Without VMC: some providers (Yahoo) show the logo; Gmail and Apple do not

---

## MTA-STS (Mail Transfer Agent Strict Transport Security)

### Purpose
Forces receiving mail servers to use TLS. Prevents downgrade attacks.

### Setup
1. Add DNS record: `_mta-sts.<domain> TXT "v=STSv1; id=<unique-id>"`
2. Host policy file at: `https://mta-sts.<domain>/.well-known/mta-sts.txt`
3. Policy content:
   ```
   version: STSv1
   mode: enforce
   mx: mail.example.com
   max_age: 604800
   ```

### Modes
- `testing`: Reports failures but delivers anyway
- `enforce`: Rejects on TLS failure

---

## Cloudflare-Specific Considerations

### Proxying Rules
- **MX records**: Must be DNS-only (gray cloud). Proxied MX breaks email delivery.
- **Mail subdomains** (mail.domain.com, smtp.domain.com): DNS-only.
- **DKIM _domainkey records**: DNS-only (TXT records can't be proxied anyway).
- **SPF TXT records**: DNS-only (TXT records can't be proxied).
- **BIMI/MTA-STS**: DNS-only for TXT records.
- **mta-sts subdomain**: Can be proxied if hosting the policy file via Cloudflare Pages/Workers.

### Avoid `a` Mechanism in SPF with Cloudflare
When Cloudflare proxies `A` records, the `a` SPF mechanism resolves to Cloudflare's proxy IPs, not your mail server. This causes SPF failures. Always use `include:` or `ip4:`/`ip6:` instead.

### Email Routing
Cloudflare Email Routing adds its own records. When using it, ensure:
- MX records point to Cloudflare's email routing servers
- SPF includes Cloudflare's SPF record
- DKIM is configured per the forwarding destination

---

## 2025 Enforcement Updates

### Gmail Requirements (for bulk senders: >5000 msgs/day)
- SPF or DKIM authentication required
- DMARC record required (any policy, even `none`)
- One-click unsubscribe header
- Spam complaint rate < 0.3%
- Valid forward and reverse DNS (PTR records)

### Yahoo/Microsoft Requirements
- Similar to Gmail: SPF + DKIM + DMARC required
- Microsoft rolling out enforcement through 2025

### Action Items
1. Ensure SPF + DKIM + DMARC are all configured
2. Monitor spam complaint rates
3. Add `List-Unsubscribe-Post: List-Unsubscribe=One-Click` header
4. Check PTR records for sending IPs

---

## Non-Sending Domain Checklist

Every domain you own — even those that never send email — should have:

```
<domain>         TXT   "v=spf1 -all"
*._domainkey.<domain> TXT   "v=DKIM1; p="
_dmarc.<domain>  TXT   "v=DMARC1; p=reject; rua=mailto:dmarc@<primary-domain>"
<domain>         MX    0 .
```

This prevents attackers from spoofing email as your unused domains.
