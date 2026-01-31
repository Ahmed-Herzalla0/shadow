#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# SHADOW v5 - Module 09: Vulnerability Scanning
# ═══════════════════════════════════════════════════════════════════════════════
# Automated vulnerability detection with noise detection & auto-pause
# ═══════════════════════════════════════════════════════════════════════════════

MODULE="09_VULN"

# Load noise detection
source "${SCRIPT_DIR}/utils/noise.sh"
source "${SCRIPT_DIR}/utils/cleanup.sh"

run() {
    local target="$1"
    local base="$2"
    
    banner "💀 VULNERABILITY SCANNING → $target"
    
    mkdir -p "$base/vulns"
    
    # Initialize noise detection
    noise_init
    
    # ─────────────────────────────────────────────────────────────────────────
    # Input Files - Only alive.txt is required!
    # ─────────────────────────────────────────────────────────────────────────
    local http_file="$base/http/alive.txt"
    local params_file="$base/params/all_urls.txt"
    
    # Single domain mode - create http input file if missing
    if [[ ! -s "$http_file" ]] && [[ "${SINGLE_MODE:-0}" == "1" ]]; then
        log_info "Single domain mode - scanning $target"
        mkdir -p "$base/http"
        echo "https://$target" > "$http_file"
        echo "http://$target" >> "$http_file"
    fi
    
    if [[ ! -s "$http_file" ]]; then
        log_error "No alive hosts found in: $http_file"
        return 1
    fi
    
    local target_count=$(wc -l < "$http_file")
    log_info "Scanning $target_count alive targets"
    
    # ─────────────────────────────────────────────────────────────────────────
    # Nuclei - Template-based scanning with Noise Detection
    # ─────────────────────────────────────────────────────────────────────────
    if require_tool "nuclei"; then
        log_info "Running Nuclei vulnerability scanner..."
        
        local silent_flag=""
        [[ "${VERBOSE:-0}" != "1" ]] && silent_flag="-silent"
        
        # Proxy support for Burp Suite
        local proxy_opt=""
        [[ "${ENABLE_PROXY:-false}" == "true" ]] && proxy_opt="-proxy ${PROXY_URL:-http://127.0.0.1:8080}"
        
        # Rate limiting based on stealth mode
        local nuclei_rate="${NUCLEI_RATE:-100}"
        local nuclei_conc="${NUCLEI_CONCURRENCY:-20}"
        
        if [[ "${STEALTH_MODE:-false}" == "true" ]]; then
            nuclei_rate=30
            nuclei_conc=5
            log_info "🥷 Stealth mode: rate=$nuclei_rate, concurrency=$nuclei_conc"
        fi
        
        # ─────────────────────────────────────────────────────────────────────
        # Run nuclei with output monitoring for noise detection
        # ─────────────────────────────────────────────────────────────────────
        run_nuclei_with_noise() {
            local label="$1"
            local extra_args="$2"
            local output_file="$3"
            
            log_info "  → $label"
            
            local temp_out=$(mktemp)
            
            nuclei -l "$http_file" \
                   $extra_args \
                   -rl "$nuclei_rate" \
                   -c "$nuclei_conc" \
                   $proxy_opt \
                   $silent_flag \
                   -o "$temp_out" 2>&1 | while IFS= read -r line; do
                # Check for rate limiting in nuclei output
                if echo "$line" | grep -qiE "429|rate.?limit|too.?many|connection.?refused"; then
                    noise_check_response 429 "nuclei:$label"
                fi
            done
            
            [[ -s "$temp_out" ]] && mv "$temp_out" "$output_file"
            rm -f "$temp_out" 2>/dev/null
        }
        
        # Critical and High severity
        run_nuclei_with_noise "Critical/High vulnerabilities" \
            "-severity critical,high" \
            "$base/vulns/nuclei_critical.txt"
        
        # Medium severity  
        run_nuclei_with_noise "Medium vulnerabilities" \
            "-severity medium" \
            "$base/vulns/nuclei_medium.txt"
        
        # CVEs
        run_nuclei_with_noise "Known CVEs" \
            "-tags cve -severity critical,high" \
            "$base/vulns/nuclei_cves.txt"
        
        # Takeovers (important!)
        run_nuclei_with_noise "Subdomain takeovers" \
            "-tags takeover" \
            "$base/vulns/nuclei_takeover.txt"
        
        # Merge all nuclei results
        cat "$base/vulns"/nuclei_*.txt 2>/dev/null | sort -u > "$base/vulns/nuclei_all.txt"
    fi
    
    # ─────────────────────────────────────────────────────────────────────────
    # XSS Testing
    # ─────────────────────────────────────────────────────────────────────────
    if [[ -s "$base/params/gf_xss.txt" ]] || [[ -s "$params_file" ]]; then
        log_info "Testing for XSS vulnerabilities..."
        
        local xss_file="$base/params/gf_xss.txt"
        [[ ! -s "$xss_file" ]] && xss_file="$params_file"
        
        # Dalfox
        if check_tool "dalfox"; then
            log_info "Running Dalfox..."
            
            # Proxy support for Burp Suite
            local proxy_opt=""
            [[ "${ENABLE_PROXY:-false}" == "true" ]] && proxy_opt="--proxy ${PROXY_URL:-http://127.0.0.1:8080}"
            
            dalfox file "$xss_file" \
                   --skip-bav \
                   --waf-evasion \
                   $proxy_opt \
                   -o "$base/vulns/dalfox.txt" 2>/dev/null
        fi
        
        # kxss
        if check_tool "kxss"; then
            log_info "Running kxss..."
            cat "$xss_file" | kxss > "$base/vulns/kxss.txt" 2>/dev/null
        fi
    fi
    
    # ─────────────────────────────────────────────────────────────────────────
    # SQLi Testing
    # ─────────────────────────────────────────────────────────────────────────
    if [[ -s "$base/params/gf_sqli.txt" ]]; then
        log_info "Testing for SQL Injection..."
        
        # SQLMap (limited, safe mode)
        if check_tool "sqlmap"; then
            log_info "Running SQLMap (safe mode)..."
            
            # Proxy support for Burp Suite
            local proxy_opt=""
            [[ "${ENABLE_PROXY:-false}" == "true" ]] && proxy_opt="--proxy=${PROXY_URL:-http://127.0.0.1:8080}"
            
            head -20 "$base/params/gf_sqli.txt" | while read -r url; do
                sqlmap -u "$url" \
                       --batch \
                       --level 1 \
                       --risk 1 \
                       --threads 5 \
                       $proxy_opt \
                       --output-dir="$base/vulns/sqlmap/" \
                       --smart 2>/dev/null
            done
        fi
        
        # Ghauri
        if check_tool "ghauri"; then
            log_info "Running Ghauri..."
            head -30 "$base/params/gf_sqli.txt" | while read -r url; do
                ghauri -u "$url" --batch >> "$base/vulns/ghauri.txt" 2>/dev/null
            done
        fi
    fi
    
    # ─────────────────────────────────────────────────────────────────────────
    # SSRF Testing
    # ─────────────────────────────────────────────────────────────────────────
    if [[ -s "$base/params/gf_ssrf.txt" ]]; then
        log_info "Testing for SSRF..."
        
        # Using interactsh/collaborator replacement
        local ssrf_payload="http://169.254.169.254/latest/meta-data/"
        
        while IFS= read -r url; do
            local test_url=$(echo "$url" | sed "s|=.*|=$ssrf_payload|")
            local response=$(curl -s --max-time 5 "$test_url" 2>/dev/null)
            
            if echo "$response" | grep -q "ami-id\|instance-id"; then
                echo "$test_url" >> "$base/vulns/ssrf_confirmed.txt"
                log_critical "SSRF confirmed: $test_url"
            fi
        done < <(head -50 "$base/params/gf_ssrf.txt")
    fi
    
    # ─────────────────────────────────────────────────────────────────────────
    # Open Redirect Testing
    # ─────────────────────────────────────────────────────────────────────────
    if [[ -s "$base/params/gf_redirect.txt" ]]; then
        log_info "Testing for Open Redirects..."
        
        # OpenRedirex
        if check_tool "openredirex"; then
            cat "$base/params/gf_redirect.txt" | \
                openredirex -p "https://evil.com" > "$base/vulns/open_redirects.txt" 2>/dev/null
        fi
    fi
    
    # ─────────────────────────────────────────────────────────────────────────
    # LFI Testing
    # ─────────────────────────────────────────────────────────────────────────
    if [[ -s "$base/params/gf_lfi.txt" ]]; then
        log_info "Testing for LFI..."
        
        local lfi_payloads=(
            "....//....//....//....//etc/passwd"
            "..%2f..%2f..%2f..%2fetc%2fpasswd"
            "/etc/passwd"
            "....//....//....//....//windows/system.ini"
        )
        
        while IFS= read -r url; do
            for payload in "${lfi_payloads[@]}"; do
                local test_url=$(echo "$url" | sed "s|=.*|=$payload|")
                local response=$(curl -s --max-time 5 "$test_url" 2>/dev/null)
                
                if echo "$response" | grep -qE "root:.*:0:0:|\\[fonts\\]"; then
                    echo "$test_url" >> "$base/vulns/lfi_confirmed.txt"
                    log_critical "LFI confirmed: $test_url"
                fi
            done
        done < <(head -30 "$base/params/gf_lfi.txt")
    fi
    
    # ─────────────────────────────────────────────────────────────────────────
    # 403 Bypass Testing
    # ─────────────────────────────────────────────────────────────────────────
    if [[ -s "$base/http/403_targets.txt" ]]; then
        log_info "Testing 403 bypass techniques..."
        
        # byp4xx
        if check_tool "byp4xx"; then
            while IFS= read -r url; do
                byp4xx "$url" >> "$base/vulns/403_bypass.txt" 2>/dev/null
            done < <(head -20 "$base/http/403_targets.txt")
        fi
    fi
    
    # ─────────────────────────────────────────────────────────────────────────
    # CORS Misconfiguration
    # ─────────────────────────────────────────────────────────────────────────
    log_info "Testing CORS configurations..."
    
    if check_tool "corsy"; then
        corsy -i "$http_file" -o "$base/vulns/cors.txt" 2>/dev/null
    else
        # Manual CORS check
        while IFS= read -r url; do
            local cors_header=$(curl -s -I -H "Origin: https://evil.com" "$url" 2>/dev/null | grep -i "access-control-allow-origin")
            if echo "$cors_header" | grep -qi "evil.com\|\*"; then
                echo "$url: $cors_header" >> "$base/vulns/cors.txt"
            fi
        done < <(head -100 "$http_file")
    fi
    
    # ─────────────────────────────────────────────────────────────────────────
    # Subdomain Takeover
    # ─────────────────────────────────────────────────────────────────────────
    if [[ -s "$base/dns/potential_takeovers.txt" ]]; then
        log_info "Verifying subdomain takeovers..."
        
        if check_tool "subjack"; then
            subjack -w "$base/dns/potential_takeovers.txt" \
                    -t 20 \
                    -timeout 30 \
                    -ssl \
                    -o "$base/vulns/subjack.txt" 2>/dev/null
        fi
        
        if check_tool "nuclei"; then
            cat "$base/dns/potential_takeovers.txt" | \
                nuclei -tags takeover -silent >> "$base/vulns/takeovers.txt" 2>/dev/null
        fi
    fi
    
    # ─────────────────────────────────────────────────────────────────────────
    # Summary Report
    # ─────────────────────────────────────────────────────────────────────────
    separator
    log_success "Vulnerability scanning complete!"
    
    # Show noise detection stats
    log_info "Noise stats: $(noise_status)"
    
    # Count findings
    echo ""
    log_info "=== VULNERABILITY SUMMARY ==="
    separator
    
    # Critical findings
    local critical_count=0
    for file in nuclei_critical ssrf_confirmed lfi_confirmed; do
        if [[ -s "$base/vulns/${file}.txt" ]]; then
            local c=$(wc -l < "$base/vulns/${file}.txt")
            critical_count=$((critical_count + c))
        fi
    done
    
    if [[ $critical_count -gt 0 ]]; then
        echo -e "${RED}${SKULL} CRITICAL: $critical_count findings${NC}"
    fi
    
    show_stats "Nuclei Critical/High" "$base/vulns/nuclei_critical.txt"
    show_stats "Nuclei Medium" "$base/vulns/nuclei_medium.txt"
    show_stats "XSS (Dalfox)" "$base/vulns/dalfox.txt"
    show_stats "CORS Issues" "$base/vulns/cors.txt"
    show_stats "Open Redirects" "$base/vulns/open_redirects.txt"
    show_stats "Takeovers" "$base/vulns/takeovers.txt"
    
    # Create summary file
    {
        echo "=== SHADOW v5 VULNERABILITY REPORT ==="
        echo "Target: $target"
        echo "Date: $(date)"
        echo ""
        echo "=== CRITICAL FINDINGS ==="
        cat "$base/vulns/nuclei_critical.txt" 2>/dev/null
        cat "$base/vulns/ssrf_confirmed.txt" 2>/dev/null
        cat "$base/vulns/lfi_confirmed.txt" 2>/dev/null
        echo ""
        echo "=== HIGH FINDINGS ==="
        cat "$base/vulns/dalfox.txt" 2>/dev/null
        echo ""
        echo "=== MEDIUM FINDINGS ==="
        cat "$base/vulns/nuclei_medium.txt" 2>/dev/null
    } > "$base/vulns/SUMMARY.txt"
    
    save_stat "vulns_critical" "$critical_count" "$base"
    save_stat "vulns_nuclei" "$(wc -l < "$base/vulns/nuclei_all.txt" 2>/dev/null)" "$base"
    
    # ─────────────────────────────────────────────────────────────────────────
    # Generate JSON Output
    # ─────────────────────────────────────────────────────────────────────────
    log_info "Generating JSON output..."
    
    if [[ -f "${SCRIPT_DIR}/utils/output_wrapper.sh" ]]; then
        source "${SCRIPT_DIR}/utils/output_wrapper.sh"
        generate_module_json "09_vuln" "$base" "$target" "$base/vulns/output.json"
        log_success "JSON output: $base/vulns/output.json"
    fi
    
    # ─────────────────────────────────────────────────────────────────────────
    # Cleanup unnecessary files from previous stages
    # ─────────────────────────────────────────────────────────────────────────
    if [[ "${AUTO_CLEANUP:-true}" == "true" ]]; then
        log_info "🧹 Cleaning up unnecessary files..."
        
        # We only need alive.txt and vuln results at this point
        # Remove intermediate files from previous modules
        cleanup_after_module "$base" "08_params"
        
        # Remove empty files in vulns directory
        find "$base/vulns" -type f -empty -delete 2>/dev/null
        
        log_success "Cleanup complete"
    fi
    
    return 0
}
