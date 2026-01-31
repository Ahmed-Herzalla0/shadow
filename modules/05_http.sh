#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# SHADOW v5 - Module 05: HTTP Probing & Analysis
# ═══════════════════════════════════════════════════════════════════════════════
# Probes HTTP services and extracts metadata
# ═══════════════════════════════════════════════════════════════════════════════

MODULE="05_HTTP"

run() {
    local target="$1"
    local base="$2"
    
    banner "🌍 HTTP PROBING → $target"
    
    mkdir -p "$base/http"
    
    # Determine input source
    local input_file=""
    if [[ -s "$base/ports/http_targets.txt" ]]; then
        input_file="$base/ports/http_targets.txt"
    elif [[ -s "$base/dns/alive.txt" ]]; then
        input_file="$base/dns/alive.txt"
    elif [[ "${SINGLE_MODE:-0}" == "1" ]]; then
        # Single domain mode - create input file with target
        log_info "Single domain mode - probing $target only"
        mkdir -p "$base/dns"
        echo "$target" > "$base/dns/alive.txt"
        input_file="$base/dns/alive.txt"
    else
        log_error "No targets for HTTP probing"
        return 1
    fi
    
    local total_targets=$(wc -l < "$input_file")
    log_info "Probing $total_targets HTTP targets..."
    
    # ─────────────────────────────────────────────────────────────────────────
    # HTTPX Probing
    # ─────────────────────────────────────────────────────────────────────────
    if require_tool "httpx"; then
        log_info "Running HTTPX..."
        
        local silent_flag=""
        [[ "${VERBOSE:-0}" != "1" ]] && silent_flag="-silent"
        
        # Full probe with all details
        httpx -l "$input_file" \
              $silent_flag \
              -title \
              -status-code \
              -content-length \
              -tech-detect \
              -follow-redirects \
              -web-server \
              -content-type \
              -cdn \
              -threads 50 \
              -timeout 10 \
              -o "$base/http/httpx_full.txt"
        
        # Just alive hosts
        httpx -l "$input_file" \
              $silent_flag \
              -o "$base/http/alive.txt"
        
        # JSON output for parsing
        httpx -l "$input_file" \
              $silent_flag \
              -title \
              -status-code \
              -tech-detect \
              -json \
              -o "$base/http/httpx.json"
    fi
    
    # ─────────────────────────────────────────────────────────────────────────
    # Technology Detection
    # ─────────────────────────────────────────────────────────────────────────
    log_info "Analyzing technologies..."
    
    # Extract technologies from httpx output
    if [[ -f "$base/http/httpx.json" ]]; then
        jq -r 'select(.tech != null) | "\(.url) \(.tech | join(","))"' \
            "$base/http/httpx.json" 2>/dev/null > "$base/http/technologies.txt"
        
        # Group by technology
        jq -r '.tech[]?' "$base/http/httpx.json" 2>/dev/null | \
            sort | uniq -c | sort -rn > "$base/http/tech_summary.txt"
    fi
    
    # ─────────────────────────────────────────────────────────────────────────
    # Status Code Analysis
    # ─────────────────────────────────────────────────────────────────────────
    log_info "Analyzing status codes..."
    
    # Group by status code
    grep -oE '\[([0-9]+)\]' "$base/http/httpx_full.txt" 2>/dev/null | \
        tr -d '[]' | sort | uniq -c | sort -rn > "$base/http/status_codes.txt"
    
    # Interesting status codes
    grep -E '\[(401|403|500|502|503)\]' "$base/http/httpx_full.txt" > "$base/http/interesting_status.txt" 2>/dev/null
    
    # 403 targets (potential bypass)
    grep '\[403\]' "$base/http/httpx_full.txt" 2>/dev/null | \
        awk '{print $1}' > "$base/http/403_targets.txt"
    
    # ─────────────────────────────────────────────────────────────────────────
    # Title Analysis
    # ─────────────────────────────────────────────────────────────────────────
    log_info "Analyzing page titles..."
    
    # Extract interesting titles
    local interesting_titles=(
        "admin"
        "login"
        "dashboard"
        "panel"
        "console"
        "jenkins"
        "gitlab"
        "grafana"
        "kibana"
        "phpmyadmin"
        "webmail"
        "portal"
        "internal"
        "staging"
        "dev"
        "test"
        "api"
        "swagger"
        "debug"
    )
    
    for title in "${interesting_titles[@]}"; do
        grep -i "$title" "$base/http/httpx_full.txt" >> "$base/http/interesting_titles.txt" 2>/dev/null
    done
    
    sort -u "$base/http/interesting_titles.txt" -o "$base/http/interesting_titles.txt" 2>/dev/null
    
    # ─────────────────────────────────────────────────────────────────────────
    # CDN/WAF Detection
    # ─────────────────────────────────────────────────────────────────────────
    log_info "Detecting CDN/WAF..."
    
    if [[ -f "$base/http/httpx.json" ]]; then
        jq -r 'select(.cdn == true) | .url' "$base/http/httpx.json" > "$base/http/cdn_hosts.txt" 2>/dev/null
        jq -r 'select(.cdn == false) | .url' "$base/http/httpx.json" > "$base/http/direct_hosts.txt" 2>/dev/null
    fi
    
    # WAF detection via headers
    if check_tool "wafw00f"; then
        log_info "Running WAF detection..."
        head -50 "$base/http/alive.txt" | while read -r url; do
            wafw00f "$url" -a 2>/dev/null >> "$base/http/waf_detection.txt"
        done &
    fi
    
    # ─────────────────────────────────────────────────────────────────────────
    # Favicon Hash (for Shodan correlation)
    # ─────────────────────────────────────────────────────────────────────────
    log_info "Extracting favicon hashes..."
    
    while IFS= read -r url; do
        local favicon_hash=$(curl -s -L "${url}/favicon.ico" 2>/dev/null | md5sum | cut -d' ' -f1)
        if [[ -n "$favicon_hash" && "$favicon_hash" != "d41d8cd98f00b204e9800998ecf8427e" ]]; then
            echo "$url $favicon_hash" >> "$base/http/favicon_hashes.txt"
        fi
    done < <(head -100 "$base/http/alive.txt") 2>/dev/null
    
    # ─────────────────────────────────────────────────────────────────────────
    # Response Size Grouping (find unique apps)
    # ─────────────────────────────────────────────────────────────────────────
    log_info "Grouping by response size..."
    
    grep -oE '\[[0-9]+\]$' "$base/http/httpx_full.txt" 2>/dev/null | \
        tr -d '[]' | sort | uniq -c | sort -rn > "$base/http/response_sizes.txt"
    
    # ─────────────────────────────────────────────────────────────────────────
    # Stats
    # ─────────────────────────────────────────────────────────────────────────
    separator
    log_success "HTTP probing complete!"
    
    show_stats "Live HTTP hosts" "$base/http/alive.txt"
    show_stats "Behind CDN" "$base/http/cdn_hosts.txt"
    show_stats "Direct access" "$base/http/direct_hosts.txt"
    show_stats "403 Forbidden" "$base/http/403_targets.txt"
    show_stats "Interesting titles" "$base/http/interesting_titles.txt"
    
    separator
    log_info "Top technologies:"
    head -10 "$base/http/tech_summary.txt" 2>/dev/null
    
    # Copy for next modules
    cp "$base/http/alive.txt" "$base/http_live.txt" 2>/dev/null
    
    save_stat "http_alive" "$(wc -l < "$base/http/alive.txt" 2>/dev/null)" "$base"
    
    # ─────────────────────────────────────────────────────────────────────────
    # Generate JSON Output
    # ─────────────────────────────────────────────────────────────────────────
    log_info "Generating JSON output..."
    
    local script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    if [[ -f "${script_dir}/utils/output_wrapper.sh" ]]; then
        source "${script_dir}/utils/output_wrapper.sh"
        generate_module_json "05_http" "$base" "$target" "$base/http/output.json"
        log_success "JSON output: $base/http/output.json"
    fi
    
    return 0
}
