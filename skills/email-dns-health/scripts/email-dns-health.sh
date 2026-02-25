#!/usr/bin/env bash
# email-dns-health — Email DNS health checker
# Uses dig + jq for zero-dependency DNS auditing.
# All output is JSON to stdout, errors to stderr.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# ─── Utilities ────────────────────────────────────────────────────────────────

json_error() {
  local code="$1" hint="$2" recoverable="${3:-true}"
  echo "{\"error\": \"$code\", \"hint\": \"$hint\", \"recoverable\": $recoverable}" >&2
  if [[ "$recoverable" == "true" ]]; then exit 1; else exit 2; fi
}

check_dep() {
  local name="$1"
  if command -v "$name" &>/dev/null; then
    local ver
    ver=$("$name" -v 2>/dev/null || "$name" --version 2>/dev/null | head -1 || echo "unknown")
    echo "{\"status\": \"ok\", \"version\": \"$ver\"}"
  else
    echo "{\"status\": \"missing\", \"hint\": \"Install $name\"}"
  fi
}

dig_txt() {
  local domain="$1"
  dig +short TXT "$domain" 2>/dev/null | tr -d '"' | tr '\n' ' ' | sed 's/  */ /g;s/^ *//;s/ *$//'
}

dig_mx() {
  local domain="$1"
  dig +short MX "$domain" 2>/dev/null | sort -n
}

dig_cname() {
  local domain="$1"
  dig +short CNAME "$domain" 2>/dev/null | head -1 | sed 's/\.$//'
}

# ─── Provider Detection ──────────────────────────────────────────────────────

detect_provider_from_mx() {
  local mx_records="$1"
  local providers=""

  if echo "$mx_records" | grep -qi "google\|gmail\|googlemail"; then
    providers="${providers}google-workspace,"
  fi
  if echo "$mx_records" | grep -qi "outlook\|microsoft\|protection\.outlook"; then
    providers="${providers}microsoft-365,"
  fi
  if echo "$mx_records" | grep -qi "infomaniak"; then
    providers="${providers}infomaniak,"
  fi
  if echo "$mx_records" | grep -qi "protonmail\|proton\|protonmx"; then
    providers="${providers}protonmail,"
  fi
  if echo "$mx_records" | grep -qi "fastmail"; then
    providers="${providers}fastmail,"
  fi
  if echo "$mx_records" | grep -qi "zoho"; then
    providers="${providers}zoho,"
  fi
  if echo "$mx_records" | grep -qi "mimecast"; then
    providers="${providers}mimecast,"
  fi
  if echo "$mx_records" | grep -qi "barracuda"; then
    providers="${providers}barracuda,"
  fi

  echo "${providers%,}"
}

detect_provider_from_spf() {
  local spf="$1"
  local providers=""

  if echo "$spf" | grep -qi "_spf\.google\|include:google"; then
    providers="${providers}google-workspace,"
  fi
  if echo "$spf" | grep -qi "spf\.protection\.outlook\|include:spf\.protection"; then
    providers="${providers}microsoft-365,"
  fi
  if echo "$spf" | grep -qi "spf\.infomaniak"; then
    providers="${providers}infomaniak,"
  fi
  if echo "$spf" | grep -qi "sendgrid\|sendgrid\.net"; then
    providers="${providers}sendgrid,"
  fi
  if echo "$spf" | grep -qi "mailgun\.org"; then
    providers="${providers}mailgun,"
  fi
  if echo "$spf" | grep -qi "amazonses\|ses\.amazonaws"; then
    providers="${providers}amazon-ses,"
  fi
  if echo "$spf" | grep -qi "resend"; then
    providers="${providers}resend,"
  fi
  if echo "$spf" | grep -qi "protonmail\|proton"; then
    providers="${providers}protonmail,"
  fi
  if echo "$spf" | grep -qi "fastmail"; then
    providers="${providers}fastmail,"
  fi
  if echo "$spf" | grep -qi "zoho"; then
    providers="${providers}zoho,"
  fi

  echo "${providers%,}"
}

get_common_selectors() {
  local providers="$1"
  local selectors="default"

  if echo "$providers" | grep -qi "google"; then
    selectors="$selectors google"
  fi
  if echo "$providers" | grep -qi "microsoft"; then
    selectors="$selectors selector1 selector2"
  fi
  if echo "$providers" | grep -qi "infomaniak"; then
    # Infomaniak uses date-based selectors; try recent patterns
    local year
    year=$(date +%Y)
    local prev_year=$((year - 1))
    selectors="$selectors ${year}0101 ${year}0601 ${prev_year}0101 ${prev_year}0601 ${prev_year}0919"
  fi
  if echo "$providers" | grep -qi "mailgun"; then
    selectors="$selectors mx k1"
  fi
  if echo "$providers" | grep -qi "sendgrid"; then
    selectors="$selectors s1 s2 smtpapi"
  fi
  if echo "$providers" | grep -qi "protonmail"; then
    selectors="$selectors protonmail protonmail2 protonmail3"
  fi
  if echo "$providers" | grep -qi "fastmail"; then
    selectors="$selectors fm1 fm2 fm3"
  fi
  if echo "$providers" | grep -qi "zoho"; then
    selectors="$selectors zoho zmail"
  fi
  if echo "$providers" | grep -qi "amazon-ses"; then
    # SES uses random selectors via CNAME; try common patterns
    selectors="$selectors ses"
  fi

  # Always try these common selectors
  selectors="$selectors mail dkim k1 k2"

  # Deduplicate
  echo "$selectors" | tr ' ' '\n' | sort -u | tr '\n' ' '
}

# ─── SPF Lookup Counter ──────────────────────────────────────────────────────

count_spf_lookups() {
  local domain="$1"
  local depth="${2:-0}"
  local max_depth=5
  local count=0
  local details=""

  if [[ "$depth" -gt "$max_depth" ]]; then
    echo "0|too-deep"
    return
  fi

  local spf
  spf=$(dig_txt "$domain" | grep -i "v=spf1" || true)

  if [[ -z "$spf" ]]; then
    echo "0|no-spf"
    return
  fi

  # Count mechanisms that require DNS lookups
  # include, a, mx, ptr, exists, redirect each cost 1 lookup
  local includes
  includes=$(echo "$spf" | grep -oiE 'include:[^ ]+' || true)
  local a_mechs
  a_mechs=$(echo "$spf" | grep -oiE '\ba[:/]' | wc -l | tr -d ' ')
  local mx_mechs
  mx_mechs=$(echo "$spf" | grep -oiE '\bmx[:/]?' | wc -l | tr -d ' ')
  local ptr_mechs
  ptr_mechs=$(echo "$spf" | grep -oiE '\bptr[:/]?' | wc -l | tr -d ' ')
  local exists_mechs
  exists_mechs=$(echo "$spf" | grep -oiE 'exists:' | wc -l | tr -d ' ')
  local redirect
  redirect=$(echo "$spf" | grep -oiE 'redirect=[^ ]+' || true)

  # a mechanism alone (just "a" without qualifier) also costs 1 lookup
  local bare_a
  bare_a=$(echo "$spf" | grep -oiE '(^| )[+~?-]?a( |$)' | wc -l | tr -d ' ')

  count=$((a_mechs + bare_a + mx_mechs + ptr_mechs + exists_mechs))

  # Each include costs 1 lookup + recursive lookups
  if [[ -n "$includes" ]]; then
    while IFS= read -r inc; do
      local inc_domain
      inc_domain=$(echo "$inc" | sed 's/include://i')
      count=$((count + 1))
      local sub_result
      sub_result=$(count_spf_lookups "$inc_domain" $((depth + 1)))
      local sub_count
      sub_count=$(echo "$sub_result" | cut -d'|' -f1)
      count=$((count + sub_count))
      details="${details}${inc_domain}:$((sub_count + 1)),"
    done <<< "$includes"
  fi

  # Redirect costs 1 lookup + recursive
  if [[ -n "$redirect" ]]; then
    local redir_domain
    redir_domain=$(echo "$redirect" | sed 's/redirect=//i')
    count=$((count + 1))
    local sub_result
    sub_result=$(count_spf_lookups "$redir_domain" $((depth + 1)))
    local sub_count
    sub_count=$(echo "$sub_result" | cut -d'|' -f1)
    count=$((count + sub_count))
    details="${details}redirect:${redir_domain}:$((sub_count + 1)),"
  fi

  echo "${count}|${details%,}"
}

# ─── Commands ─────────────────────────────────────────────────────────────────

cmd_preflight() {
  local dig_ok=true jq_ok=true

  if ! command -v dig &>/dev/null; then
    dig_ok=false
  fi
  if ! command -v jq &>/dev/null; then
    jq_ok=false
  fi

  # If jq is missing, we cannot use it to format output — use printf instead
  if [[ "$jq_ok" == "false" ]]; then
    local dig_status_json
    if [[ "$dig_ok" == "true" ]]; then
      local dig_ver
      dig_ver=$(dig -v 2>&1 | head -1 || echo "unknown")
      dig_status_json="{\"status\":\"ok\",\"version\":\"$dig_ver\"}"
    else
      dig_status_json="{\"status\":\"missing\",\"hint\":\"brew install bind (macOS) or apt install dnsutils (Linux)\"}"
    fi
    local jq_status_json="{\"status\":\"missing\",\"hint\":\"brew install jq (macOS) or apt install jq (Linux)\"}"
    printf '{"ready":false,"dependencies":{"dig":%s,"jq":%s},"credentials":{},"hint":"Missing required dependencies — see each dependency hint for install instructions"}\n' \
      "$dig_status_json" "$jq_status_json"
    return
  fi

  # jq is available — safe to use for formatting
  local dig_status jq_status ready="true"

  dig_status=$(check_dep dig)
  jq_status=$(check_dep jq)

  if echo "$dig_status" | grep -q '"missing"'; then
    ready="false"
  fi

  # Check optional Cloudflare API token (for DNS fix workflow)
  # Single canonical config path: ~/.claude/email-dns-health/.env
  local env_file="$HOME/.claude/email-dns-health/.env"
  if [[ -z "${CLOUDFLARE_API_TOKEN:-}" ]] && [[ -f "$env_file" ]]; then
    # shellcheck disable=SC1090
    source "$env_file" 2>/dev/null || true
  fi

  local cf_token_status
  if [[ -z "${CLOUDFLARE_API_TOKEN:-}" ]]; then
    cf_token_status='{"status":"not_configured","required":false,"hint":"Optional. Set CLOUDFLARE_API_TOKEN in ~/.claude/email-dns-health/.env for automatic DNS fixes. Obtain at https://dash.cloudflare.com/profile/api-tokens (Zone:DNS:Edit permission)."}'
  else
    # Live validation: test actual API access with a lightweight call
    local cf_test
    cf_test=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
      "https://api.cloudflare.com/client/v4/zones?per_page=1" 2>/dev/null || echo "000")
    if [[ "$cf_test" == "200" ]]; then
      cf_token_status='{"status":"valid","required":false,"hint":"Cloudflare API token is valid. Automatic DNS fixes available."}'
    elif [[ "$cf_test" == "403" ]]; then
      cf_token_status='{"status":"invalid","required":false,"hint":"Cloudflare API token returned 403. Token needs Zone:DNS:Edit permission. Regenerate at https://dash.cloudflare.com/profile/api-tokens and update ~/.claude/email-dns-health/.env"}'
    elif [[ "$cf_test" == "401" ]]; then
      cf_token_status='{"status":"expired","required":false,"hint":"Cloudflare API token is expired or revoked. Regenerate at https://dash.cloudflare.com/profile/api-tokens and update ~/.claude/email-dns-health/.env"}'
    else
      cf_token_status='{"status":"unreachable","required":false,"hint":"Could not reach Cloudflare API (HTTP '$cf_test'). Check network connectivity. Token will be retested when needed."}'
    fi
  fi

  jq -n \
    --argjson ready "$ready" \
    --argjson dig_dep "$dig_status" \
    --argjson jq_dep "$jq_status" \
    --argjson cf_token "$cf_token_status" \
    '{
      ready: $ready,
      dependencies: {
        dig: $dig_dep,
        jq: $jq_dep
      },
      credentials: {
        cloudflare_api_token: $cf_token
      },
      hint: (if $ready then "All checks passed" else "Missing required dependencies — see each dependency hint for install instructions" end)
    }'
}

cmd_check_spf() {
  local domain="$1"
  local spf
  spf=$(dig_txt "$domain" | grep -i "v=spf1" || true)

  if [[ -z "$spf" ]]; then
    jq -n --arg domain "$domain" '{
      status: "missing",
      score: 0,
      max_score: 30,
      domain: $domain,
      record: null,
      lookup_count: 0,
      lookup_details: null,
      qualifier: null,
      issues: ["No SPF record found"],
      hint: "No SPF record found. Email from this domain cannot be authenticated via SPF."
    }'
    return
  fi

  local lookup_result
  lookup_result=$(count_spf_lookups "$domain")
  local lookup_count
  lookup_count=$(echo "$lookup_result" | cut -d'|' -f1)
  local lookup_details
  lookup_details=$(echo "$lookup_result" | cut -d'|' -f2-)

  # Determine all mechanism qualifier
  local qualifier="unknown"
  if echo "$spf" | grep -q "\-all"; then
    qualifier="-all (fail)"
  elif echo "$spf" | grep -q "\~all"; then
    qualifier="~all (softfail)"
  elif echo "$spf" | grep -q "?all"; then
    qualifier="?all (neutral)"
  elif echo "$spf" | grep -q "+all\|[^~?-]all"; then
    qualifier="+all (pass - DANGEROUS)"
  fi

  local issues="[]"
  if [[ "$lookup_count" -gt 10 ]]; then
    issues=$(echo "$issues" | jq '. + ["SPF exceeds 10 DNS lookup limit ('$lookup_count'/10). Emails will fail SPF checks."]')
  elif [[ "$lookup_count" -gt 7 ]]; then
    issues=$(echo "$issues" | jq '. + ["SPF approaching 10 DNS lookup limit ('$lookup_count'/10). Plan for optimization."]')
  fi
  if echo "$qualifier" | grep -q "DANGEROUS"; then
    issues=$(echo "$issues" | jq '. + ["+all allows any server to send as this domain. Use -all or ~all."]')
  fi
  if echo "$qualifier" | grep -q "softfail"; then
    issues=$(echo "$issues" | jq '. + ["~all (softfail) is acceptable during DMARC rollout but should be hardened to -all when DMARC is at reject."]')
  fi
  if echo "$qualifier" | grep -q "neutral"; then
    issues=$(echo "$issues" | jq '. + ["?all (neutral) provides no protection. Use ~all or -all."]')
  fi
  if echo "$spf" | grep -qiE '\bptr[: ]'; then
    issues=$(echo "$issues" | jq '. + ["ptr mechanism is deprecated (RFC 7208). Remove it."]')
  fi

  local status="ok"
  local spf_score=30
  local issue_count
  issue_count=$(echo "$issues" | jq 'length')
  if [[ "$issue_count" -gt 0 ]]; then
    if [[ "$lookup_count" -gt 10 ]] || echo "$qualifier" | grep -q "DANGEROUS"; then
      status="critical"
      spf_score=0
    else
      status="warning"
      spf_score=20
    fi
  fi

  jq -n \
    --arg status "$status" \
    --argjson score "$spf_score" \
    --arg domain "$domain" \
    --arg record "$spf" \
    --argjson lookup_count "$lookup_count" \
    --arg lookup_details "$lookup_details" \
    --arg qualifier "$qualifier" \
    --argjson issues "$issues" \
    '{
      status: $status,
      score: $score,
      max_score: 30,
      domain: $domain,
      record: $record,
      lookup_count: $lookup_count,
      lookup_details: $lookup_details,
      qualifier: $qualifier,
      issues: $issues,
      hint: ("SPF: " + $status + " (" + ($lookup_count|tostring) + "/10 lookups, " + $qualifier + ")")
    }'
}

cmd_check_dkim() {
  local domain="$1"
  local selector="${2:-}"
  local results="[]"

  if [[ -n "$selector" ]]; then
    # Check specific selector
    local dkim
    dkim=$(dig_txt "${selector}._domainkey.${domain}")
    local cname
    cname=$(dig_cname "${selector}._domainkey.${domain}")

    if [[ -n "$dkim" ]] || [[ -n "$cname" ]]; then
      local key_length="unknown"
      local algorithm="unknown"
      local flags=""

      if [[ -n "$dkim" ]]; then
        # Extract key type
        algorithm=$(echo "$dkim" | grep -oiE 'k=[^;]+' | sed 's/k=//' || echo "rsa")
        [[ -z "$algorithm" ]] && algorithm="rsa"

        # Extract flags
        flags=$(echo "$dkim" | grep -oiE 't=[^;]+' | sed 's/t=//' || true)

        # Estimate key length from p= value
        local pubkey
        pubkey=$(echo "$dkim" | tr -d ' \t\n\r' | grep -oE 'p=[A-Za-z0-9+/=]+' | sed 's/p=//' || true)
        if [[ -n "$pubkey" ]]; then
          local keylen=${#pubkey}
          # Base64 encoded key length estimation
          if [[ "$keylen" -gt 350 ]]; then
            key_length="2048"
          elif [[ "$keylen" -gt 170 ]]; then
            key_length="1024"
          elif [[ "$keylen" -gt 80 ]]; then
            key_length="512"
          elif [[ "$keylen" -lt 10 ]]; then
            key_length="empty"
          fi
        fi

        # Check for null key (non-sending domain)
        if echo "$dkim" | grep -qE 'p=\s*;|p=\s*$'; then
          key_length="null-key"
        fi
      fi

      local entry
      entry=$(jq -n \
        --arg selector "$selector" \
        --arg record "${dkim:-CNAME: $cname}" \
        --arg key_length "$key_length" \
        --arg algorithm "$algorithm" \
        --arg flags "$flags" \
        --arg type "$([ -n "$cname" ] && echo "cname" || echo "txt")" \
        '{selector: $selector, record: $record, key_length: $key_length, algorithm: $algorithm, flags: $flags, type: $type}')
      results=$(echo "$results" | jq --argjson e "$entry" '. + [$e]')
    fi
  else
    # Auto-detect: first detect providers, then try their selectors
    local mx_records spf_record all_providers
    mx_records=$(dig_mx "$domain" || true)
    spf_record=$(dig_txt "$domain" | grep -i "v=spf1" || true)
    local mx_providers spf_providers
    mx_providers=$(detect_provider_from_mx "$mx_records")
    spf_providers=$(detect_provider_from_spf "$spf_record")
    all_providers="${mx_providers},${spf_providers}"

    local selectors
    selectors=$(get_common_selectors "$all_providers")

    for sel in $selectors; do
      local dkim
      dkim=$(dig_txt "${sel}._domainkey.${domain}")
      local cname
      cname=$(dig_cname "${sel}._domainkey.${domain}")

      if [[ -n "$dkim" ]] || [[ -n "$cname" ]]; then
        local key_length="unknown"
        local algorithm="unknown"
        local flags=""

        if [[ -n "$dkim" ]]; then
          algorithm=$(echo "$dkim" | grep -oiE 'k=[^;]+' | sed 's/k=//' || echo "rsa")
          [[ -z "$algorithm" ]] && algorithm="rsa"
          flags=$(echo "$dkim" | grep -oiE 't=[^;]+' | sed 's/t=//' || true)
          local pubkey
          pubkey=$(echo "$dkim" | tr -d ' \t\n\r' | grep -oE 'p=[A-Za-z0-9+/=]+' | sed 's/p=//' || true)
          if [[ -n "$pubkey" ]]; then
            local keylen=${#pubkey}
            if [[ "$keylen" -gt 350 ]]; then
              key_length="2048"
            elif [[ "$keylen" -gt 170 ]]; then
              key_length="1024"
            elif [[ "$keylen" -gt 80 ]]; then
              key_length="512"
            elif [[ "$keylen" -lt 10 ]]; then
              key_length="empty"
            fi
          fi
          if echo "$dkim" | grep -qE 'p=\s*;|p=\s*$'; then
            key_length="null-key"
          fi
        fi

        local entry
        entry=$(jq -n \
          --arg selector "$sel" \
          --arg record "${dkim:-CNAME: $cname}" \
          --arg key_length "$key_length" \
          --arg algorithm "$algorithm" \
          --arg flags "$flags" \
          --arg type "$([ -n "$cname" ] && echo "cname" || echo "txt")" \
          '{selector: $selector, record: $record, key_length: $key_length, algorithm: $algorithm, flags: $flags, type: $type}')
        results=$(echo "$results" | jq --argjson e "$entry" '. + [$e]')
      fi
    done
  fi

  local found_count
  found_count=$(echo "$results" | jq 'length')
  local issues="[]"

  if [[ "$found_count" -eq 0 ]]; then
    issues=$(echo "$issues" | jq '. + ["No DKIM records found. Try specifying a selector with: check-dkim <domain> <selector>"]')
  else
    # Check key strengths
    local weak_keys
    weak_keys=$(echo "$results" | jq '[.[] | select(.key_length == "512" or .key_length == "1024")] | length')
    if [[ "$weak_keys" -gt 0 ]]; then
      issues=$(echo "$issues" | jq '. + ["Found DKIM key(s) with < 2048-bit RSA. Upgrade to 2048-bit minimum."]')
    fi
  fi

  local status="ok"
  local dkim_score=30
  if [[ "$found_count" -eq 0 ]]; then
    status="missing"
    dkim_score=0
  elif [[ $(echo "$issues" | jq 'length') -gt 0 ]]; then
    status="warning"
    dkim_score=20
  fi

  jq -n \
    --arg status "$status" \
    --argjson score "$dkim_score" \
    --arg domain "$domain" \
    --argjson keys "$results" \
    --argjson issues "$issues" \
    --argjson found_count "$found_count" \
    '{
      status: $status,
      score: $score,
      max_score: 30,
      domain: $domain,
      keys_found: $found_count,
      keys: $keys,
      issues: $issues,
      hint: ("DKIM: " + $status + " (" + ($found_count|tostring) + " key(s) found)")
    }'
}

cmd_check_dmarc() {
  local domain="$1"
  local dmarc
  dmarc=$(dig_txt "_dmarc.${domain}" | grep -i "v=DMARC1" || true)

  if [[ -z "$dmarc" ]]; then
    jq -n --arg domain "$domain" '{
      status: "missing",
      score: 0,
      max_score: 40,
      domain: $domain,
      record: null,
      policy: null,
      subdomain_policy: null,
      rua: null,
      ruf: null,
      pct: null,
      issues: ["No DMARC record found. Email authentication results are not enforced."],
      hint: "No DMARC record found. Add a _dmarc TXT record."
    }'
    return
  fi

  local policy sp rua ruf pct

  policy=$(echo "$dmarc" | grep -oiE 'p=[^;]+' | head -1 | sed 's/p=//i' || true)
  sp=$(echo "$dmarc" | grep -oiE 'sp=[^;]+' | sed 's/sp=//i' || true)
  rua=$(echo "$dmarc" | grep -oiE 'rua=[^;]+' | sed 's/rua=//i' || true)
  ruf=$(echo "$dmarc" | grep -oiE 'ruf=[^;]+' | sed 's/ruf=//i' || true)
  pct=$(echo "$dmarc" | grep -oiE 'pct=[0-9]+' | sed 's/pct=//i' || true)

  local issues="[]"
  local status="ok"
  local dmarc_score=40

  if [[ "$policy" == "none" ]]; then
    issues=$(echo "$issues" | jq '. + ["DMARC policy is none (monitoring only). Advance to quarantine when compliance > 98%."]')
    status="warning"
    dmarc_score=15
  elif [[ "$policy" == "quarantine" ]]; then
    dmarc_score=33
  fi
  # reject = 40 (default)

  if [[ -z "$rua" ]]; then
    issues=$(echo "$issues" | jq '. + ["No aggregate report address (rua). Add rua= to receive DMARC reports."]')
  fi
  if [[ -n "$pct" ]] && [[ "$pct" -lt 100 ]] && [[ "$policy" != "none" ]]; then
    issues=$(echo "$issues" | jq --arg pct "$pct" '. + ["pct=" + $pct + " — only partial enforcement. Increase to 100 when ready."]')
  fi

  jq -n \
    --arg status "$status" \
    --argjson score "$dmarc_score" \
    --arg domain "$domain" \
    --arg record "$dmarc" \
    --arg policy "${policy:-none}" \
    --arg sp "${sp:-inherit}" \
    --arg rua "${rua:-none}" \
    --arg ruf "${ruf:-none}" \
    --arg pct "${pct:-100}" \
    --argjson issues "$issues" \
    '{
      status: $status,
      score: $score,
      max_score: 40,
      domain: $domain,
      record: $record,
      policy: $policy,
      subdomain_policy: $sp,
      rua: $rua,
      ruf: $ruf,
      pct: ($pct|tonumber),
      issues: $issues,
      hint: ("DMARC: " + $status + " (policy=" + $policy + ")")
    }'
}

cmd_detect_provider() {
  local domain="$1"
  local mx_records spf_record

  mx_records=$(dig_mx "$domain" || true)
  spf_record=$(dig_txt "$domain" | grep -i "v=spf1" || true)

  local mx_providers spf_providers
  mx_providers=$(detect_provider_from_mx "$mx_records")
  spf_providers=$(detect_provider_from_spf "$spf_record")

  # Merge and deduplicate
  local all_providers
  all_providers=$(echo "${mx_providers},${spf_providers}" | tr ',' '\n' | grep -v '^$' | sort -u | tr '\n' ',' | sed 's/,$//')

  # Separate into hosting (MX-detected) and sending (SPF-only)
  local hosting_providers sending_providers
  hosting_providers=$(echo "$mx_providers" | tr ',' '\n' | grep -v '^$' | sort -u | tr '\n' ',' | sed 's/,$//')
  sending_providers=$(echo "$spf_providers" | tr ',' '\n' | grep -v '^$' | sort -u | tr '\n' ',' | sed 's/,$//')

  # Remove hosting providers from sending list
  local send_only=""
  if [[ -n "$sending_providers" ]]; then
    for p in $(echo "$sending_providers" | tr ',' ' '); do
      if ! echo "$hosting_providers" | grep -q "$p"; then
        send_only="${send_only}${p},"
      fi
    done
    send_only="${send_only%,}"
  fi

  jq -n \
    --arg domain "$domain" \
    --arg hosting "${hosting_providers:-none}" \
    --arg sending "${send_only:-none}" \
    --arg all "${all_providers:-none}" \
    --arg mx "${mx_records:-none}" \
    --arg spf "${spf_record:-none}" \
    '{
      status: "ok",
      domain: $domain,
      hosting_provider: $hosting,
      sending_services: $sending,
      all_providers: $all,
      raw_mx: $mx,
      raw_spf: $spf,
      hint: ("Hosting: " + $hosting + " | Sending: " + (if $sending == "none" then "same as hosting" else $sending end))
    }'
}

cmd_check_bimi() {
  local domain="$1"
  local bimi
  bimi=$(dig_txt "default._bimi.${domain}" || true)

  if [[ -z "$bimi" ]] || ! echo "$bimi" | grep -qi "v=BIMI1"; then
    jq -n --arg domain "$domain" '{
      status: "missing",
      score: 0,
      max_score: 10,
      bonus: true,
      domain: $domain,
      record: null,
      logo: null,
      vmc: null,
      hint: "No BIMI record found."
    }'
    return
  fi

  local logo vmc
  logo=$(echo "$bimi" | grep -oiE 'l=[^;]+' | sed 's/l=//i' || true)
  vmc=$(echo "$bimi" | grep -oiE 'a=[^;]+' | sed 's/a=//i' || true)

  jq -n \
    --arg domain "$domain" \
    --arg record "$bimi" \
    --arg logo "${logo:-none}" \
    --arg vmc "${vmc:-none}" \
    '{
      status: "ok",
      score: 10,
      max_score: 10,
      bonus: true,
      domain: $domain,
      record: $record,
      logo: $logo,
      vmc: $vmc,
      hint: ("BIMI: present" + (if $vmc != "none" then " with VMC" else " without VMC" end))
    }'
}

cmd_check_mta_sts() {
  local domain="$1"
  local mta_sts
  mta_sts=$(dig_txt "_mta-sts.${domain}" || true)

  if [[ -z "$mta_sts" ]] || ! echo "$mta_sts" | grep -qi "v=STSv1"; then
    jq -n --arg domain "$domain" '{
      status: "missing",
      score: 0,
      max_score: 10,
      bonus: true,
      domain: $domain,
      record: null,
      hint: "No MTA-STS record found."
    }'
    return
  fi

  jq -n \
    --arg domain "$domain" \
    --arg record "$mta_sts" \
    '{
      status: "ok",
      score: 10,
      max_score: 10,
      bonus: true,
      domain: $domain,
      record: $record,
      hint: "MTA-STS: present"
    }'
}

cmd_audit() {
  local domain="$1"

  # Run all checks
  local spf_result dkim_result dmarc_result bimi_result mta_sts_result
  local mx_records provider_result

  spf_result=$(cmd_check_spf "$domain")
  dkim_result=$(cmd_check_dkim "$domain")
  dmarc_result=$(cmd_check_dmarc "$domain")
  bimi_result=$(cmd_check_bimi "$domain")
  mta_sts_result=$(cmd_check_mta_sts "$domain")
  mx_records=$(dig_mx "$domain" || true)
  provider_result=$(cmd_detect_provider "$domain")

  # Sum scores from each check (120-point scale)
  # Core (SPF 30 + DKIM 30 + DMARC 40) = 100 — determines deliverability
  # Bonus (BIMI 10 + MTA-STS 10) = 20 — nice-to-have
  local score
  score=$(echo "$spf_result $dkim_result $dmarc_result $bimi_result $mta_sts_result" \
    | jq -s '[.[].score] | add')

  local grade
  if [[ "$score" -ge 100 ]]; then
    grade="A"
  elif [[ "$score" -ge 80 ]]; then
    grade="B"
  elif [[ "$score" -ge 60 ]]; then
    grade="C"
  elif [[ "$score" -ge 40 ]]; then
    grade="D"
  else
    grade="F"
  fi

  # Collect all issues
  local all_issues
  all_issues=$(jq -n \
    --argjson spf_issues "$(echo "$spf_result" | jq '.issues')" \
    --argjson dkim_issues "$(echo "$dkim_result" | jq '.issues')" \
    --argjson dmarc_issues "$(echo "$dmarc_result" | jq '.issues')" \
    '$spf_issues + $dkim_issues + $dmarc_issues')

  # Check MX
  local mx_status="ok"
  if [[ -z "$mx_records" ]]; then
    mx_status="missing"
    all_issues=$(echo "$all_issues" | jq '. + ["No MX records found."]')
  fi

  # Build final result
  jq -n \
    --arg domain "$domain" \
    --arg grade "$grade" \
    --argjson score "$score" \
    --argjson spf "$spf_result" \
    --argjson dkim "$dkim_result" \
    --argjson dmarc "$dmarc_result" \
    --argjson bimi "$bimi_result" \
    --argjson mta_sts "$mta_sts_result" \
    --argjson provider "$provider_result" \
    --arg mx_status "$mx_status" \
    --arg mx_records "${mx_records:-none}" \
    --argjson issues "$all_issues" \
    '{
      status: "ok",
      domain: $domain,
      grade: $grade,
      score: $score,
      max_score: 120,
      core_score: (if $score > 100 then 100 else $score end),
      core_max: 100,
      bonus_score: (if $score > 100 then ($score - 100) else 0 end),
      bonus_max: 20,
      spf: $spf,
      dkim: $dkim,
      dmarc: $dmarc,
      bimi: $bimi,
      mta_sts: $mta_sts,
      mx: {status: $mx_status, records: $mx_records},
      provider: $provider,
      issues: $issues,
      issue_count: ($issues | length),
      hint: ($domain + ": Grade " + $grade + " (" + ($score|tostring) + "/120, core " + (if $score > 100 then "100" else ($score|tostring) end) + "/100) — " + (($issues | length)|tostring) + " issue(s)")
    }'
}

cmd_setup_guide() {
  local provider="$1"
  local provider_lower
  provider_lower=$(echo "$provider" | tr '[:upper:]' '[:lower:]')

  # Check if references file exists
  local ref_file="${SCRIPT_DIR}/../references/provider-configs.md"
  if [[ ! -f "$ref_file" ]]; then
    json_error "file_not_found" "Provider configs reference file not found at $ref_file" "false"
  fi

  jq -n \
    --arg provider "$provider_lower" \
    --arg ref_file "$ref_file" \
    '{
      status: "ok",
      provider: $provider,
      reference_file: $ref_file,
      hint: "Read the reference file for detailed setup instructions for " + $provider
    }'
}

# ─── Main ─────────────────────────────────────────────────────────────────────

case "${1:-}" in
  preflight)
    cmd_preflight
    ;;
  check-spf)
    [[ -z "${2:-}" ]] && json_error "missing_arg" "Usage: email-dns-health.sh check-spf <domain>" "true"
    cmd_check_spf "$2"
    ;;
  check-dkim)
    [[ -z "${2:-}" ]] && json_error "missing_arg" "Usage: email-dns-health.sh check-dkim <domain> [selector]" "true"
    cmd_check_dkim "$2" "${3:-}"
    ;;
  check-dmarc)
    [[ -z "${2:-}" ]] && json_error "missing_arg" "Usage: email-dns-health.sh check-dmarc <domain>" "true"
    cmd_check_dmarc "$2"
    ;;
  detect-provider)
    [[ -z "${2:-}" ]] && json_error "missing_arg" "Usage: email-dns-health.sh detect-provider <domain>" "true"
    cmd_detect_provider "$2"
    ;;
  check-bimi)
    [[ -z "${2:-}" ]] && json_error "missing_arg" "Usage: email-dns-health.sh check-bimi <domain>" "true"
    cmd_check_bimi "$2"
    ;;
  check-mta-sts)
    [[ -z "${2:-}" ]] && json_error "missing_arg" "Usage: email-dns-health.sh check-mta-sts <domain>" "true"
    cmd_check_mta_sts "$2"
    ;;
  audit)
    [[ -z "${2:-}" ]] && json_error "missing_arg" "Usage: email-dns-health.sh audit <domain>" "true"
    cmd_audit "$2"
    ;;
  setup-guide)
    [[ -z "${2:-}" ]] && json_error "missing_arg" "Usage: email-dns-health.sh setup-guide <provider>" "true"
    cmd_setup_guide "$2"
    ;;
  *)
    echo '{"error": "unknown_command", "hint": "Usage: email-dns-health.sh <preflight|audit|check-spf|check-dkim|check-dmarc|check-bimi|check-mta-sts|detect-provider|setup-guide> [args...]", "recoverable": true}' >&2
    exit 1
    ;;
esac
