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
  local dig_status jq_status ready="true"

  dig_status=$(check_dep dig)
  jq_status=$(check_dep jq)

  if echo "$dig_status" | grep -q '"missing"'; then
    ready="false"
  fi
  if echo "$jq_status" | grep -q '"missing"'; then
    ready="false"
  fi

  jq -n \
    --argjson ready "$ready" \
    --argjson dig_dep "$dig_status" \
    --argjson jq_dep "$jq_status" \
    '{
      ready: $ready,
      dependencies: {
        dig: $dig_dep,
        jq: $jq_dep
      },
      hint: (if $ready then "All checks passed" else "Missing required dependencies" end)
    }'
}

cmd_check_spf() {
  local domain="$1"
  local spf
  spf=$(dig_txt "$domain" | grep -i "v=spf1" || true)

  if [[ -z "$spf" ]]; then
    jq -n --arg domain "$domain" '{
      status: "missing",
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
  local issue_count
  issue_count=$(echo "$issues" | jq 'length')
  if [[ "$issue_count" -gt 0 ]]; then
    if [[ "$lookup_count" -gt 10 ]] || echo "$qualifier" | grep -q "DANGEROUS"; then
      status="critical"
    else
      status="warning"
    fi
  fi

  jq -n \
    --arg status "$status" \
    --arg domain "$domain" \
    --arg record "$spf" \
    --argjson lookup_count "$lookup_count" \
    --arg lookup_details "$lookup_details" \
    --arg qualifier "$qualifier" \
    --argjson issues "$issues" \
    '{
      status: $status,
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
        pubkey=$(echo "$dkim" | grep -oE 'p=[A-Za-z0-9+/=]+' | sed 's/p=//' || true)
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
          pubkey=$(echo "$dkim" | grep -oE 'p=[A-Za-z0-9+/=]+' | sed 's/p=//' || true)
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
  if [[ "$found_count" -eq 0 ]]; then
    status="missing"
  elif [[ $(echo "$issues" | jq 'length') -gt 0 ]]; then
    status="warning"
  fi

  jq -n \
    --arg status "$status" \
    --arg domain "$domain" \
    --argjson keys "$results" \
    --argjson issues "$issues" \
    --argjson found_count "$found_count" \
    '{
      status: $status,
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

  if [[ "$policy" == "none" ]]; then
    issues=$(echo "$issues" | jq '. + ["DMARC policy is none (monitoring only). Advance to quarantine when compliance > 98%."]')
    status="warning"
  fi
  if [[ -z "$rua" ]]; then
    issues=$(echo "$issues" | jq '. + ["No aggregate report address (rua). Add rua= to receive DMARC reports."]')
  fi
  if [[ -n "$pct" ]] && [[ "$pct" -lt 100 ]] && [[ "$policy" != "none" ]]; then
    issues=$(echo "$issues" | jq --arg pct "$pct" '. + ["pct=" + $pct + " — only partial enforcement. Increase to 100 when ready."]')
  fi

  jq -n \
    --arg status "$status" \
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

  # Calculate grade
  local score=0
  local max_score=100

  # SPF: 25 points
  local spf_status
  spf_status=$(echo "$spf_result" | jq -r '.status')
  case "$spf_status" in
    ok) score=$((score + 25)) ;;
    warning) score=$((score + 15)) ;;
    *) ;;
  esac

  # DKIM: 25 points
  local dkim_status dkim_key_count
  dkim_status=$(echo "$dkim_result" | jq -r '.status')
  dkim_key_count=$(echo "$dkim_result" | jq '.keys_found')
  case "$dkim_status" in
    ok)
      score=$((score + 25))
      # Bonus for 2048-bit keys
      local has_strong
      has_strong=$(echo "$dkim_result" | jq '[.keys[] | select(.key_length == "2048")] | length')
      if [[ "$has_strong" -gt 0 ]]; then
        score=$((score + 0))  # Already included in base
      fi
      ;;
    warning) score=$((score + 15)) ;;
    *) ;;
  esac

  # DMARC: 30 points
  local dmarc_status dmarc_policy
  dmarc_status=$(echo "$dmarc_result" | jq -r '.status')
  dmarc_policy=$(echo "$dmarc_result" | jq -r '.policy // "none"')
  case "$dmarc_status" in
    ok)
      case "$dmarc_policy" in
        reject) score=$((score + 30)) ;;
        quarantine) score=$((score + 25)) ;;
        none) score=$((score + 10)) ;;
        *) score=$((score + 10)) ;;
      esac
      ;;
    warning) score=$((score + 10)) ;;
    *) ;;
  esac

  # BIMI: 10 points
  local bimi_status
  bimi_status=$(echo "$bimi_result" | jq -r '.status')
  if [[ "$bimi_status" == "ok" ]]; then
    score=$((score + 10))
  fi

  # MTA-STS: 10 points
  local mta_sts_status
  mta_sts_status=$(echo "$mta_sts_result" | jq -r '.status')
  if [[ "$mta_sts_status" == "ok" ]]; then
    score=$((score + 10))
  fi

  # Determine grade
  local grade
  if [[ "$score" -ge 90 ]]; then
    grade="A"
  elif [[ "$score" -ge 75 ]]; then
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
      max_score: 100,
      spf: $spf,
      dkim: $dkim,
      dmarc: $dmarc,
      bimi: $bimi,
      mta_sts: $mta_sts,
      mx: {status: $mx_status, records: $mx_records},
      provider: $provider,
      issues: $issues,
      issue_count: ($issues | length),
      hint: ($domain + ": Grade " + $grade + " (" + ($score|tostring) + "/100) — " + (($issues | length)|tostring) + " issue(s)")
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
