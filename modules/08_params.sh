#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# SHADOW v5 - Module 08: Parameter Discovery
# ═══════════════════════════════════════════════════════════════════════════════
# Discovers URLs and parameters using single tool approach
# Uses Katana for crawling with noise detection
# ═══════════════════════════════════════════════════════════════════════════════

MODULE="08_PARAMS"

# Load noise detection
source "${SCRIPT_DIR}/utils/noise.sh"

run() {
    local target="$1"
    local base="$2"
    
    banner "🔎 PARAMETER DISCOVERY → $target"
    
    mkdir -p "$base/params"
    
    local http_file="$base/http/alive.txt"
    
    # Initialize noise detection
    noise_init
    
    # Single domain mode - create http input file if missing
    if [[ ! -s "$http_file" ]] && [[ "${SINGLE_MODE:-0}" == "1" ]]; then
        log_info "Single domain mode - discovering params on $target"
        mkdir -p "$base/http"
        echo "https://$target" > "$http_file"
        echo "http://$target" >> "$http_file"
    fi
    
    if [[ ! -s "$http_file" ]]; then
        log_error "No HTTP hosts found"
        return 1
    fi
    
    # ─────────────────────────────────────────────────────────────────────────
    # URL Discovery with Katana (Single Tool Approach)
    # ─────────────────────────────────────────────────────────────────────────
    # Using only Katana for active crawling - reduces noise on server
    # Katana handles: JavaScript parsing, form discovery, link extraction
    # ─────────────────────────────────────────────────────────────────────────
    
    # Proxy support for Burp Suite
    local proxy_opt=""
    [[ "${ENABLE_PROXY:-false}" == "true" ]] && proxy_opt="-proxy ${PROXY_URL:-http://127.0.0.1:8080}"
    
    if require_tool "katana"; then
        log_info "🕷️ Running Katana crawler (single tool mode)..."
        log_info "   Depth: 3 | JS Parsing: enabled | Forms: enabled"
        
        # Create temp file to monitor output
        local temp_output=$(mktemp)
        
        # Run Katana with noise-aware settings
        katana -list "$http_file" \
               -d 3 \
               -jc \
               -kf all \
               -ef "png,jpg,jpeg,gif,svg,ico,woff,woff2,ttf,eot,mp4,mp3,pdf" \
               -c 10 \
               -rl "${KATANA_RATE:-50}" \
               -timeout 10 \
               -retry 2 \
               $proxy_opt \
               -silent \
               -o "$temp_output" 2>&1 | while IFS= read -r line; do
            # Monitor for rate limiting indicators
            if echo "$line" | grep -qiE "429|rate.?limit|too.?many|blocked"; then
                log_warn "⚠️ Rate limiting detected!"
                noise_check_response 429 "katana"
            fi
        done
        
        # Move output to final location
        mv "$temp_output" "$base/params/katana.txt" 2>/dev/null
    else
        log_error "Katana not installed - required for URL discovery"
        return 1
    fi
    
    # ─────────────────────────────────────────────────────────────────────────
    # Merge URLs (simplified - only katana + existing data)
    # ─────────────────────────────────────────────────────────────────────────
    log_info "Merging and deduplicating URLs..."
    
    # Add JS endpoints if available from previous module
    if [[ -f "$base/js/endpoints.txt" ]]; then
        cat "$base/js/endpoints.txt" >> "$base/params/from_js.txt"
    fi
    
    # Merge katana output with any existing endpoints
    cat "$base/params/katana.txt" "$base/params/from_js.txt" 2>/dev/null | \
        grep -E "^https?://" | \
        sort -u > "$base/params/all_urls.txt"
    
    dedupe_urls "$base/params/all_urls.txt"

    # Apply scope filtering on URLs
    if [[ "${ENABLE_SCOPE_FILTERING:-true}" == "true" ]]; then
        filter_scope_urls "$base/params/all_urls.txt"
    fi
    
    local total_urls=$(wc -l < "$base/params/all_urls.txt" 2>/dev/null || echo 0)
    log_success "Total unique URLs: $total_urls"
    
    # ─────────────────────────────────────────────────────────────────────────
    # Parameter Extraction
    # ─────────────────────────────────────────────────────────────────────────
    log_info "Extracting parameters..."
    
    # URLs with parameters
    grep "?" "$base/params/all_urls.txt" > "$base/params/urls_with_params.txt" 2>/dev/null
    
    # Extract unique parameters
    if check_tool "unfurl"; then
        cat "$base/params/urls_with_params.txt" | unfurl keys | sort | uniq -c | sort -rn > "$base/params/param_names.txt" 2>/dev/null
        cat "$base/params/urls_with_params.txt" | unfurl format '%d%p' | sort -u > "$base/params/endpoints.txt" 2>/dev/null
    else
        # Manual extraction
        grep -oE "[?&][a-zA-Z0-9_-]+=" "$base/params/urls_with_params.txt" | \
            sed 's/[?&]//;s/=//' | \
            sort | uniq -c | sort -rn > "$base/params/param_names.txt" 2>/dev/null
    fi
    
    # ─────────────────────────────────────────────────────────────────────────
    # INTELLIGENT PARAM CLASSIFICATION (New!)
    # ─────────────────────────────────────────────────────────────────────────
    log_info "Classifying parameters by vulnerability type..."
    
    local interesting="${INTERESTING_PARAMS:-id|user|account|redirect|next|return|url|file|path}"
    
    # Extract just parameter names
    awk '{print $2}' "$base/params/param_names.txt" 2>/dev/null > "$base/params/param_list.txt"
    
    # Interesting params (high value)
    grep -Ei "$interesting" "$base/params/param_list.txt" > "$base/params/interesting_params.txt" 2>/dev/null
    
    # URLs with interesting params
    grep -Ei "[\?&]($interesting)=" "$base/params/urls_with_params.txt" > "$base/params/priority_urls.txt" 2>/dev/null
    
    local priority_count=$(wc -l < "$base/params/priority_urls.txt" 2>/dev/null || echo 0)
    log_found "High-priority param URLs: $priority_count"
    
    # ─────────────────────────────────────────────────────────────────────────
    # AUTH SURFACE EXTRACTION (New!)
    # ─────────────────────────────────────────────────────────────────────────
    log_info "Extracting auth-related endpoints..."
    
    local auth_patterns="${AUTH_PATTERNS:-login|logout|callback|oauth|sso|auth|token|session|register|signup|password|reset|forgot}"
    
    grep -Ei "$auth_patterns" "$base/params/all_urls.txt" > "$base/params/auth_urls.txt" 2>/dev/null
    
    local auth_count=$(wc -l < "$base/params/auth_urls.txt" 2>/dev/null || echo 0)
    log_found "Auth-related URLs: $auth_count"
    
    # ─────────────────────────────────────────────────────────────────────────
    # APPLY URL LIMITS (Prevent runaway scans)
    # ─────────────────────────────────────────────────────────────────────────
    if [[ "${ENABLE_LIMITS:-true}" == "true" ]]; then
        local max_urls="${MAX_URLS:-10000}"
        local current_urls=$(wc -l < "$base/params/all_urls.txt" 2>/dev/null || echo 0)
        
        if [[ $current_urls -gt $max_urls ]]; then
            log_warn "Limiting URLs from $current_urls to $max_urls"
            mv "$base/params/all_urls.txt" "$base/params/all_urls_full.txt"
            head -n "$max_urls" "$base/params/all_urls_full.txt" > "$base/params/all_urls.txt"
            log_info "Full list saved to: all_urls_full.txt"
        fi
    fi
    
    # ─────────────────────────────────────────────────────────────────────────
    # GF Patterns (for vuln categories)
    # ─────────────────────────────────────────────────────────────────────────
    if check_tool "gf"; then
        log_info "Categorizing URLs with GF patterns..."
        
        local patterns=("xss" "sqli" "ssrf" "redirect" "rce" "lfi" "ssti" "idor" "debug_logic" "interestingparams")
        
        for pattern in "${patterns[@]}"; do
            cat "$base/params/all_urls.txt" | gf "$pattern" > "$base/params/gf_${pattern}.txt" 2>/dev/null
            
            local count=$(wc -l < "$base/params/gf_${pattern}.txt" 2>/dev/null || echo 0)
            if [[ $count -gt 0 ]]; then
                log_found "$pattern: $count potential targets"
            fi
        done
    fi
    
    # ─────────────────────────────────────────────────────────────────────────
    # Arjun - Hidden Parameter Discovery
    # ─────────────────────────────────────────────────────────────────────────
    if check_tool "arjun"; then
        log_info "Running Arjun for hidden parameters..."
        
        # Get unique endpoints (without params)
        if [[ -s "$base/params/endpoints.txt" ]]; then
            head -50 "$base/params/endpoints.txt" | \
                arjun -i /dev/stdin \
                      -t 10 \
                      -oT "$base/params/arjun.txt" 2>/dev/null
        fi
    fi
    
    # ─────────────────────────────────────────────────────────────────────────
    # x8 - Parameter Bruteforce
    # ─────────────────────────────────────────────────────────────────────────
    if check_tool "x8"; then
        log_info "Running x8 for parameter bruteforce..."
        
        head -20 "$base/params/endpoints.txt" 2>/dev/null | while read -r url; do
            x8 -u "$url" \
               -w "${SCRIPT_DIR}/wordlists/params.txt" \
               --threads 10 2>/dev/null >> "$base/params/x8.txt"
        done
    fi
    
    # ─────────────────────────────────────────────────────────────────────────
    # Prepare for vulnerability scanning
    # ─────────────────────────────────────────────────────────────────────────
    log_info "Preparing targets for vulnerability scanning..."
    
    # Copy main files to root for vuln module
    cp "$base/params/all_urls.txt" "$base/urls.txt" 2>/dev/null
    cp "$base/params/urls_with_params.txt" "$base/params.txt" 2>/dev/null
    
    # ─────────────────────────────────────────────────────────────────────────
    # Stats
    # ─────────────────────────────────────────────────────────────────────────
    separator
    log_success "Parameter discovery complete!"
    
    show_stats "Total URLs" "$base/params/all_urls.txt"
    show_stats "URLs with params" "$base/params/urls_with_params.txt"
    show_stats "Unique parameters" "$base/params/param_names.txt"
    
    separator
    log_info "Top parameters:"
    head -10 "$base/params/param_names.txt" 2>/dev/null
    
    save_stat "total_urls" "$total_urls" "$base"
    save_stat "urls_with_params" "$(wc -l < "$base/params/urls_with_params.txt" 2>/dev/null)" "$base"
    
    return 0
}
