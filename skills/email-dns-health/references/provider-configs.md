# Email Provider DNS Configuration Reference

## Google Workspace

### SPF
```
include:_spf.google.com
```
- DNS lookups: ~4
- Required for all Google Workspace domains

### DKIM
- Selector: `google`
- Key size: 2048-bit RSA (default, recommended)
- Setup: Google Admin Console > Apps > Google Workspace > Gmail > Authenticate Email
- Record: `google._domainkey.<domain>` TXT with the generated key
- Rotation: Manual via admin console

### MX Records (priority order)
```
1  ASPMX.L.GOOGLE.COM.
5  ALT1.ASPMX.L.GOOGLE.COM.
5  ALT2.ASPMX.L.GOOGLE.COM.
10 ALT3.ASPMX.L.GOOGLE.COM.
10 ALT4.ASPMX.L.GOOGLE.COM.
```

### DMARC
Recommended starting point:
```
v=DMARC1; p=none; rua=mailto:dmarc@<domain>
```

---

## Microsoft 365

### SPF
```
include:spf.protection.outlook.com
```
- DNS lookups: ~2
- Efficient SPF footprint

### DKIM
- Setup: Microsoft 365 Defender > Email & collaboration > Policies > DKIM
- Two CNAME records:
  ```
  selector1._domainkey.<domain> → selector1-<domain>._domainkey.<tenant>.onmicrosoft.com
  selector2._domainkey.<domain> → selector2-<domain>._domainkey.<tenant>.onmicrosoft.com
  ```
- Key rotation: Automatic by Microsoft
- Key size: 2048-bit RSA (rotated to 1024-bit then back to 2048-bit automatically)

### MX Records
```
0 <domain>.mail.protection.outlook.com.
```

---

## Infomaniak

### SPF
```
include:spf.infomaniak.ch
```
- DNS lookups: 1-2
- Very efficient

### DKIM
- Selector: Date-based (e.g., `20250919`)
- Setup: Infomaniak Manager > Email > Domain > DKIM
- New selectors created with dates, e.g., `20250919._domainkey.<domain>`
- Key size: 2048-bit RSA

### MX Records
```
5  mta.infomaniak.ch.
```

---

## SendGrid (Twilio)

### SPF
- Uses CNAME-based automated security — **0 SPF lookups**
- Three CNAME records generated in SendGrid dashboard:
  ```
  em1234.<domain> → u1234.wl.sendgrid.net
  s1._domainkey.<domain> → s1.domainkey.u1234.wl.sendgrid.net
  s2._domainkey.<domain> → s2.domainkey.u1234.wl.sendgrid.net
  ```
- Bypasses SPF lookup limit entirely via CNAME flattening

### DKIM
- Selectors: `s1`, `s2`
- Managed via CNAME delegation — automatic rotation
- Key size: 2048-bit RSA

### Setup
1. Go to Settings > Sender Authentication > Domain Authentication
2. Enter your domain and DNS host
3. Add the generated CNAME records to your DNS
4. Click Verify in SendGrid dashboard

---

## Mailgun

### SPF
```
include:mailgun.org
```
- DNS lookups: ~2

### DKIM
- Selector: `mx` or varies by domain
- Record: `mx._domainkey.<domain>` or custom CNAME
- Key size: 2048-bit RSA

### MX Records (for receiving)
```
10 mxa.mailgun.org.
10 mxb.mailgun.org.
```

### Setup
1. Mailgun Dashboard > Sending > Domains > Add Domain
2. Add SPF TXT record
3. Add DKIM TXT or CNAME record
4. Add MX records (if receiving via Mailgun)
5. Verify in dashboard

---

## Amazon SES

### SPF
- Custom MAIL FROM subdomain approach:
  ```
  mail.<domain> TXT "v=spf1 include:amazonses.com -all"
  ```
- DNS lookups: ~1
- Or use Easy DKIM (CNAME-based, 0 lookups on main domain)

### DKIM (Easy DKIM)
- Three CNAME records:
  ```
  <token1>._domainkey.<domain> → <token1>.dkim.amazonses.com
  <token2>._domainkey.<domain> → <token2>.dkim.amazonses.com
  <token3>._domainkey.<domain> → <token3>.dkim.amazonses.com
  ```
- Key rotation: Automatic by AWS
- Key size: 2048-bit RSA (default)

### Setup
1. AWS Console > SES > Verified identities > Create identity
2. Choose domain, enable Easy DKIM
3. Add the 3 CNAME records to DNS
4. Optionally configure custom MAIL FROM domain
5. Wait for verification (usually minutes)

---

## Resend

### SPF/DKIM
- Uses subdomain delegation — records generated in Resend dashboard
- CNAME-based: **0 SPF lookups** on main domain
- Typical records:
  ```
  send.<domain> CNAME  → ... (varies)
  resend._domainkey.<domain> CNAME → ...
  ```

### Setup
1. Resend Dashboard > Domains > Add Domain
2. Add generated DNS records (typically 2-3 CNAMEs + 1 TXT)
3. Click Verify

---

## Fastmail

### SPF
```
include:spf.messagingengine.com
```

### DKIM
- Selectors: `fm1`, `fm2`, `fm3`
- CNAME records:
  ```
  fm1._domainkey.<domain> → fm1.<domain>.dkim.fmhosted.com
  fm2._domainkey.<domain> → fm2.<domain>.dkim.fmhosted.com
  fm3._domainkey.<domain> → fm3.<domain>.dkim.fmhosted.com
  ```

### MX Records
```
10 in1-smtp.messagingengine.com.
20 in2-smtp.messagingengine.com.
```

---

## ProtonMail

### SPF
```
include:_spf.protonmail.ch
```

### DKIM
- Selectors: `protonmail`, `protonmail2`, `protonmail3`
- CNAME records provided in Proton admin console

### MX Records
```
10 mail.protonmail.ch.
20 mailsec.protonmail.ch.
```

---

## Zoho Mail

### SPF
```
include:zoho.com
```
(or regional: `include:zoho.eu`, `include:zoho.in`)

### DKIM
- Selector: `zoho` or `zmail`
- Setup: Zoho Admin Console > Email Authentication > DKIM
- TXT record with generated key

### MX Records
```
10 mx.zoho.com.
20 mx2.zoho.com.
50 mx3.zoho.com.
```

---

## Non-Sending Domain Configuration

For domains that should never send email, add these records to prevent spoofing:

```
<domain>         TXT   "v=spf1 -all"
*._domainkey.<domain> TXT   "v=DKIM1; p="
_dmarc.<domain>  TXT   "v=DMARC1; p=reject; rua=mailto:dmarc@<primary-domain>"
<domain>         MX    0 .
```

The null MX record (`0 .`) signals that the domain does not accept email (RFC 7505).

---

## SPF Lookup Cost Summary

| Provider | Mechanism | Lookups |
|----------|-----------|---------|
| Google Workspace | `include:_spf.google.com` | ~4 |
| Microsoft 365 | `include:spf.protection.outlook.com` | ~2 |
| Infomaniak | `include:spf.infomaniak.ch` | 1-2 |
| Amazon SES | `include:amazonses.com` | ~1 |
| SendGrid | CNAME-based | 0 |
| Resend | CNAME-based | 0 |
| Mailgun | `include:mailgun.org` | ~2 |
| Fastmail | `include:spf.messagingengine.com` | ~2 |
| ProtonMail | `include:_spf.protonmail.ch` | ~2 |
| Zoho | `include:zoho.com` | ~2 |

**Total limit: 10 DNS lookups.** Plan your SPF record carefully when using multiple providers.
