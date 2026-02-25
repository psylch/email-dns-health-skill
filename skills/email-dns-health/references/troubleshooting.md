# Email DNS Troubleshooting Guide

## SPF Issues

### SPF exceeds 10 DNS lookup limit
**Symptoms**: Email fails SPF checks despite having a valid SPF record. `permerror` in DMARC reports.

**Diagnosis**: Run `email-dns-health.sh check-spf <domain>` and check `lookup_count`.

**Solutions** (in order of preference):
1. **Switch to CNAME-based providers**: SendGrid, Amazon SES Easy DKIM, and Resend use CNAME delegation that costs 0 SPF lookups.
2. **Subdomain segmentation**: Move marketing email to `marketing.<domain>`, transactional to `notify.<domain>`. Each subdomain gets its own 10-lookup budget.
3. **Remove unused includes**: Audit your SPF record. Remove `include:` entries for services you no longer use.
4. **SPF flattening**: Use tools like `dmarcian` to convert `include:` to IP ranges. Requires ongoing maintenance.

### SPF softfail (~all) vs hardfail (-all)
**When to use `~all`**: During initial DMARC deployment (policy=none). Gives you time to identify all legitimate senders.

**When to use `-all`**: After DMARC is at `quarantine` or `reject` with >98% compliance. This signals strong confidence in your SPF record.

### "Too many DNS lookups" but count seems low
**Cause**: Each `include:` triggers recursive lookups. `include:_spf.google.com` alone costs ~4 lookups because Google's SPF record includes other records.

**Fix**: Use `check-spf` with the lookup breakdown to see per-include costs.

---

## DKIM Issues

### DKIM selector not found
**Causes**:
1. Wrong selector name — check your email provider's documentation
2. DKIM not enabled — configure in your email provider's admin panel
3. DNS propagation delay — wait 15-60 minutes after adding the record

**Diagnosis**:
```bash
# Try common selectors
dig +short TXT google._domainkey.<domain>
dig +short TXT selector1._domainkey.<domain>
dig +short TXT default._domainkey.<domain>
dig +short TXT k1._domainkey.<domain>
```

**To find the actual selector**: Send a test email and inspect the `DKIM-Signature` header. The `s=` field is the selector.

### DKIM key too short (1024-bit or less)
**Risk**: 1024-bit RSA keys can be factored with sufficient computing resources. 512-bit keys are trivially breakable.

**Fix**: Generate a new 2048-bit key in your email provider's admin panel. Update the DNS record and retire the old selector.

### DKIM signature fails validation
**Common causes**:
1. **Email content modified in transit**: Mailing lists, forwarding services, or security gateways may modify the message body or headers, breaking the DKIM signature.
2. **DNS record mismatch**: The public key in DNS doesn't match the private key used for signing.
3. **Selector rotation incomplete**: Old selector removed from DNS before all cached emails expired.
4. **Record too long**: Some DNS providers silently truncate TXT records. Verify the full record is published.

---

## DMARC Issues

### No DMARC reports arriving
**Causes**:
1. `rua` address not receiving — check the mailbox exists and accepts messages
2. **External domain verification missing**: If `rua` points to a different domain than the one in the DMARC record, the receiving domain must publish:
   ```
   <reporting-domain>._report._dmarc.<target-domain> TXT "v=DMARC1"
   ```
3. Low email volume — reports are typically sent daily
4. Report processing delay — allow 48-72 hours after initial setup

### DMARC alignment failures
**SPF alignment fails**: The `envelope-from` domain doesn't match the `From` header domain. This happens when a service sends on your behalf using their own envelope sender.

**Fix**: Configure the service to use your domain as the MAIL FROM (e.g., Amazon SES custom MAIL FROM domain).

**DKIM alignment fails**: The `d=` in the DKIM signature doesn't match the `From` header domain.

**Fix**: Ensure your email provider signs with your domain (not theirs) in the `d=` field.

### Moving from p=none to p=quarantine
**Checklist**:
1. Review DMARC aggregate reports for at least 2 weeks
2. Confirm >98% of legitimate emails pass both SPF and DKIM
3. Identify and fix any failing legitimate senders
4. Start with `pct=25` to only quarantine 25% of failing emails
5. Monitor for increased bounce rates or user complaints
6. Gradually increase `pct` to 100
7. Then move to `p=reject`

---

## MX Record Issues

### Email not being delivered
**Common causes**:
1. **Cloudflare proxying**: MX target hostname is orange-clouded (proxied). Must be gray cloud (DNS-only).
2. **Missing MX records**: Domain has no MX records. Some senders fall back to A record, but many don't.
3. **Priority misconfigured**: Lower number = higher priority. Ensure primary server has the lowest number.

### Cloudflare Email Routing conflicts
**Symptom**: After enabling Cloudflare Email Routing, original MX records are replaced.

**Fix**: Cloudflare Email Routing replaces your MX records with its own. If you want to use a different email provider, disable Email Routing first, then add your provider's MX records.

---

## DNS Propagation

### Records not visible after update
- **TTL**: Check the TTL of the old record. DNS resolvers cache for this duration.
- **Typical propagation**: 5 minutes to 48 hours depending on TTL and resolver
- **Verify with specific resolver**: `dig @8.8.8.8 TXT <domain>` (Google DNS) or `dig @1.1.1.1 TXT <domain>` (Cloudflare DNS)
- **Cloudflare**: Changes are typically visible within 5 minutes globally

### Conflicting records
- Only one SPF record is allowed per domain. Multiple SPF records cause `permerror`.
- Multiple DKIM records are fine (different selectors).
- Only one DMARC record per domain.
- Check for duplicate or conflicting records: `dig +short TXT <domain>` — if you see two lines starting with `v=spf1`, you have duplicate SPF records.

---

## Cloudflare API Issues

### 403 Forbidden
- Token needs `Zone:DNS:Edit` permission
- Token must have access to the specific zone
- Regenerate at: Cloudflare Dashboard > My Profile > API Tokens

### Zone ID not found
- Find zone ID: Cloudflare Dashboard > Domain > Overview (right sidebar)
- Or via API: `curl -H "Authorization: Bearer $TOKEN" "https://api.cloudflare.com/client/v4/zones?name=<domain>"`

### Record update not reflected
- Cloudflare DNS updates are near-instant
- If using proxied records, check if the record type supports proxying
- TXT, MX, and CNAME records for email should never be proxied

---

## Testing Tools

### Command-line
```bash
# Full DNS check
dig +short TXT <domain>                    # SPF
dig +short TXT _dmarc.<domain>             # DMARC
dig +short TXT <selector>._domainkey.<domain>  # DKIM
dig +short MX <domain>                     # MX records
dig +short TXT default._bimi.<domain>      # BIMI
dig +short TXT _mta-sts.<domain>           # MTA-STS
```

### Online Tools
- **mail-tester.com**: Send a test email, get a deliverability score (1-10)
- **MXToolbox.com**: Comprehensive DNS, blacklist, and deliverability checks
- **LearnDMARC.com**: Visual DMARC flow simulator
- **dmarcian.com**: DMARC report analysis (free tier available)
- **Google Postmaster Tools**: Deliverability metrics for Gmail
- **Cloudflare DMARC Management**: Free DMARC report monitoring (for Cloudflare users)
- **Postmark DMARC**: Free weekly DMARC digest reports
