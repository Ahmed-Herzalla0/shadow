#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# SHADOW v6 - Module Output Wrapper
# ═══════════════════════════════════════════════════════════════════════════════
# Wraps module execution and produces normalized JSON output
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ═══════════════════════════════════════════════════════════════════════════════
# JSON HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

json_escape() {
    # Escape string for JSON
    local str="$1"
    str="${str//\\/\\\\}"
    str="${str//\"/\\\"}"
    str="${str//$'\n'/\\n}"
    str="${str//$'\t'/\\t}"
    echo "$str"
}

json_array() {
    # Convert file lines to JSON array
    local file="$1"
    local max="${2:-1000}"
    
    if [[ ! -f "$file" ]]; then
        echo "[]"
        return
    fi
    
    local first=true
    echo -n "["
    head -n "$max" "$file" | while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        $first || echo -n ","
        first=false
        echo -n "\"$(json_escape "$line")\""
    done
    echo "]"
}

json_count() {
    # Count lines in file, return 0 if not exists
    local file="$1"
    [[ -f "$file" ]] && wc -l < "$file" || echo 0
}

# ═══════════════════════════════════════════════════════════════════════════════
# MODULE OUTPUT GENERATORS
# ═══════════════════════════════════════════════════════════════════════════════

generate_intel_json() {
    local base="$1"
    local target="$2"
    
    local asn_number="" asn_name="" asn_country=""
    
    if [[ -f "$base/intel/asn.txt" ]]; then
        IFS='|' read -r asn_number asn_name asn_country < <(head -1 "$base/intel/asn.txt")
    fi
    
    cat <<EOF
{
  "module": "01_intel",
  "target": "$target",
  "timestamp": "$(date -Iseconds)",
  "success": true,
  "data": {
    "asn": {
      "number": "$(json_escape "${asn_number:-}")",
      "name": "$(json_escape "${asn_name:-}")",
      "country": "$(json_escape "${asn_country:-}")"
    },
    "ip_ranges": $(json_array "$base/intel/ip_ranges.txt" 100),
    "related_domains": $(json_array "$base/intel/related_domains.txt" 100)
  }
}
EOF
}

generate_subdomains_json() {
    local base="$1"
    local target="$2"
    
    local total=$(json_count "$base/subdomains/all.txt")
    local unique=$(sort -u "$base/subdomains/all.txt" 2>/dev/null | wc -l || echo 0)
    
    cat <<EOF
{
  "module": "02_subdomains",
  "target": "$target",
  "timestamp": "$(date -Iseconds)",
  "success": true,
  "data": {
    "total_found": $total,
    "unique_count": $unique,
    "subdomains": $(json_array "$base/subdomains/all.txt" 500),
    "wildcards": $(json_array "$base/subdomains/wildcards.txt" 50)
  }
}
EOF
}

generate_dns_json() {
    local base="$1"
    local target="$2"
    
    local resolved=$(json_count "$base/dns/resolved.txt")
    
    # Extract unique IPs
    local ips="[]"
    if [[ -f "$base/dns/ips.txt" ]]; then
        ips=$(json_array "$base/dns/ips.txt" 500)
    fi
    
    cat <<EOF
{
  "module": "03_dns",
  "target": "$target",
  "timestamp": "$(date -Iseconds)",
  "success": true,
  "data": {
    "resolved_count": $resolved,
    "ips": $ips,
    "potential_takeovers": $(json_array "$base/dns/takeovers.txt" 100)
  }
}
EOF
}

generate_http_json() {
    local base="$1"
    local target="$2"
    
    local alive=$(json_count "$base/http/alive.txt")
    
    # Parse technologies
    local tech_json="{}"
    if [[ -f "$base/http/tech_summary.txt" ]]; then
        tech_json="{"
        local first=true
        while read -r count tech; do
            [[ -z "$tech" ]] && continue
            $first || tech_json+=","
            first=false
            tech_json+="\"$(json_escape "$tech")\": $count"
        done < "$base/http/tech_summary.txt"
        tech_json+="}"
    fi
    
    # WAF detection
    local waf="null"
    if [[ -f "$base/http/waf.txt" ]]; then
        waf="\"$(head -1 "$base/http/waf.txt")\""
    fi
    
    cat <<EOF
{
  "module": "05_http",
  "target": "$target",
  "timestamp": "$(date -Iseconds)",
  "success": true,
  "data": {
    "alive_count": $alive,
    "technologies_found": $tech_json,
    "waf_detected": $waf,
    "cdn_hosts": $(json_array "$base/http/cdn_hosts.txt" 200),
    "direct_hosts": $(json_array "$base/http/direct_hosts.txt" 200),
    "interesting_titles": $(json_array "$base/http/interesting_titles.txt" 100),
    "status_403": $(json_array "$base/http/403_targets.txt" 100)
  }
}
EOF
}

generate_content_json() {
    local base="$1"
    local target="$2"
    
    cat <<EOF
{
  "module": "06_content",
  "target": "$target",
  "timestamp": "$(date -Iseconds)",
  "success": true,
  "data": {
    "paths_found": $(json_count "$base/content/directories.txt"),
    "admin_panels": $(json_array "$base/content/admin.txt" 100),
    "backup_files": $(json_array "$base/content/backups.txt" 100),
    "config_files": $(json_array "$base/content/configs.txt" 100),
    "interesting_paths": $(json_array "$base/content/interesting.txt" 200)
  }
}
EOF
}

generate_js_json() {
    local base="$1"
    local target="$2"
    
    cat <<EOF
{
  "module": "07_js",
  "target": "$target",
  "timestamp": "$(date -Iseconds)",
  "success": true,
  "data": {
    "files_analyzed": $(json_count "$base/js/files.txt"),
    "endpoints_found": $(json_count "$base/js/endpoints.txt"),
    "secrets_found": $(json_count "$base/js/secrets.txt"),
    "endpoints": $(json_array "$base/js/endpoints.txt" 500),
    "secrets": $(json_array "$base/js/secrets.txt" 100),
    "source_maps": $(json_array "$base/js/sourcemaps.txt" 50)
  }
}
EOF
}

generate_params_json() {
    local base="$1"
    local target="$2"
    
    cat <<EOF
{
  "module": "08_params",
  "target": "$target",
  "timestamp": "$(date -Iseconds)",
  "success": true,
  "data": {
    "urls_found": $(json_count "$base/params/urls.txt"),
    "params_found": $(json_count "$base/params/parameters.txt"),
    "xss_candidates": $(json_array "$base/params/xss.txt" 200),
    "sqli_candidates": $(json_array "$base/params/sqli.txt" 200),
    "ssrf_candidates": $(json_array "$base/params/ssrf.txt" 200),
    "idor_candidates": $(json_array "$base/params/idor.txt" 200),
    "lfi_candidates": $(json_array "$base/params/lfi.txt" 200),
    "redirect_candidates": $(json_array "$base/params/redirect.txt" 200)
  }
}
EOF
}

generate_vuln_json() {
    local base="$1"
    local target="$2"
    
    # Count by severity from nuclei JSON
    local critical=0 high=0 medium=0 total=0
    
    if [[ -f "$base/vuln/nuclei.json" ]]; then
        total=$(wc -l < "$base/vuln/nuclei.json")
        critical=$(grep -c '"severity":"critical"' "$base/vuln/nuclei.json" 2>/dev/null || echo 0)
        high=$(grep -c '"severity":"high"' "$base/vuln/nuclei.json" 2>/dev/null || echo 0)
        medium=$(grep -c '"severity":"medium"' "$base/vuln/nuclei.json" 2>/dev/null || echo 0)
    fi
    
    # Parse vulnerabilities into array
    local vulns="[]"
    if [[ -f "$base/vuln/nuclei.json" ]]; then
        vulns=$(cat "$base/vuln/nuclei.json" | jq -s '.[0:100]' 2>/dev/null || echo "[]")
    fi
    
    cat <<EOF
{
  "module": "09_vuln",
  "target": "$target",
  "timestamp": "$(date -Iseconds)",
  "success": true,
  "data": {
    "total_found": $total,
    "critical_count": $critical,
    "high_count": $high,
    "medium_count": $medium,
    "vulnerabilities": $vulns
  }
}
EOF
}

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN WRAPPER
# ═══════════════════════════════════════════════════════════════════════════════

generate_module_json() {
    local module="$1"
    local base="$2"
    local target="$3"
    local output_file="$4"
    
    local json=""
    
    case "$module" in
        01_intel)     json=$(generate_intel_json "$base" "$target") ;;
        02_subdomains) json=$(generate_subdomains_json "$base" "$target") ;;
        03_dns)       json=$(generate_dns_json "$base" "$target") ;;
        05_http)      json=$(generate_http_json "$base" "$target") ;;
        06_content)   json=$(generate_content_json "$base" "$target") ;;
        07_js)        json=$(generate_js_json "$base" "$target") ;;
        08_params)    json=$(generate_params_json "$base" "$target") ;;
        09_vuln)      json=$(generate_vuln_json "$base" "$target") ;;
        *)
            echo "{\"error\": \"Unknown module: $module\"}" > "$output_file"
            return 1
            ;;
    esac
    
    echo "$json" | jq '.' > "$output_file" 2>/dev/null || echo "$json" > "$output_file"
    
    return 0
}

# Run if executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    if [[ $# -lt 4 ]]; then
        echo "Usage: $0 <module> <base_dir> <target> <output_file>"
        echo "Example: $0 05_http /output/example.com example.com /output/example.com/http.json"
        exit 1
    fi
    
    generate_module_json "$1" "$2" "$3" "$4"
fi
