#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# SHADOW v5 - Module 07: JavaScript Analysis
# ═══════════════════════════════════════════════════════════════════════════════
# Extracts and analyzes JavaScript files for secrets and endpoints
# ═══════════════════════════════════════════════════════════════════════════════

MODULE="07_JS"

run() {
    local target="$1"
    local base="$2"
    
    banner "📜 JAVASCRIPT ANALYSIS → $target"
    
    mkdir -p "$base/js"
    mkdir -p "$base/js/files"
    
    local http_file="$base/http/alive.txt"
    
    # Single domain mode - create http input file if missing
    if [[ ! -s "$http_file" ]] && [[ "${SINGLE_MODE:-0}" == "1" ]]; then
        log_info "Single domain mode - analyzing JS on $target"
        mkdir -p "$base/http"
        echo "https://$target" > "$http_file"
        echo "http://$target" >> "$http_file"
    fi
    
    if [[ ! -s "$http_file" ]]; then
        log_error "No HTTP hosts found. Run HTTP probing first."
        return 1
    fi
    
    # ─────────────────────────────────────────────────────────────────────────
    # Extract JS URLs
    # ─────────────────────────────────────────────────────────────────────────
    log_info "Extracting JavaScript URLs..."

    local temp_dir
    temp_dir=$(mktemp -d)
    local subjs_file="$temp_dir/subjs.txt"
    local getjs_file="$temp_dir/getjs.txt"
    local katana_file="$temp_dir/katana.txt"
    
    # Using subjs
    if check_tool "subjs"; then
        cat "$http_file" | subjs -c 20 > "$subjs_file" 2>/dev/null &
    fi
    
    # Using getJS
    if check_tool "getJS"; then
        while IFS= read -r url; do
            getJS --url "$url" --complete 2>/dev/null
        done < <(head -100 "$http_file") >> "$getjs_file" 2>/dev/null &
    fi
    
    # Using katana for crawling JS
    if check_tool "katana"; then
        log_info "Crawling with Katana..."
        katana -list "$http_file" \
               -jc \
               -ef png,jpg,gif,css,woff,woff2,svg,ico \
               -d 2 \
               -c 20 \
               -silent \
               -o "$katana_file" 2>/dev/null &
    fi
    
    wait
    
    # Merge JS URLs from sources
    : > "$base/js/js_urls.txt"
    [[ -f "$subjs_file" ]] && cat "$subjs_file" >> "$base/js/js_urls.txt"
    [[ -f "$getjs_file" ]] && cat "$getjs_file" >> "$base/js/js_urls.txt"

    # Extract JS from katana output
    if [[ -f "$katana_file" ]]; then
        grep -E "\.js(\?|$)" "$katana_file" >> "$base/js/js_urls.txt" 2>/dev/null
    fi
    
    # Dedupe
    sort -u "$base/js/js_urls.txt" -o "$base/js/js_urls.txt" 2>/dev/null

    rm -rf "$temp_dir"
    
    local js_count=$(wc -l < "$base/js/js_urls.txt" 2>/dev/null || echo 0)
    log_success "Found $js_count JavaScript files"
    
    # ─────────────────────────────────────────────────────────────────────────
    # Download JS Files
    # ─────────────────────────────────────────────────────────────────────────
    if [[ $js_count -gt 0 ]]; then
        log_info "Downloading JavaScript files..."
        
        local count=0
        while IFS= read -r js_url; do
            ((count++))
            local max_js_files="${MAX_JS_FILES:-500}"
            if [[ $count -gt $max_js_files ]]; then
                log_warn "Limiting to ${max_js_files} JS files"
                break
            fi
            
            local filename=$(echo "$js_url" | md5sum | cut -d' ' -f1).js
            curl -s -L --max-time 10 "$js_url" > "$base/js/files/$filename" 2>/dev/null
            echo "$js_url" > "$base/js/files/${filename}.url"
            
        done < "$base/js/js_urls.txt"
        
        log_success "Downloaded $count JavaScript files"
    fi
    
    # ─────────────────────────────────────────────────────────────────────────
    # LinkFinder - Extract Endpoints
    # ─────────────────────────────────────────────────────────────────────────
    if check_tool "linkfinder"; then
        log_info "Running LinkFinder..."
        
        for js_file in "$base/js/files"/*.js; do
            if [[ -f "$js_file" ]]; then
                python3 $(which linkfinder) -i "$js_file" -o cli 2>/dev/null >> "$base/js/endpoints.txt"
            fi
        done 2>/dev/null
        
        sort -u "$base/js/endpoints.txt" -o "$base/js/endpoints.txt" 2>/dev/null
    fi
    
    # ─────────────────────────────────────────────────────────────────────────
    # Regex-based extraction
    # ─────────────────────────────────────────────────────────────────────────
    log_info "Extracting secrets and endpoints with regex..."
    
    # API Endpoints
    grep -rhoE "(https?://[^\"'\`\s>]+|/api/[^\"'\`\s>]+|/v[0-9]+/[^\"'\`\s>]+)" \
        "$base/js/files/" 2>/dev/null | sort -u > "$base/js/api_endpoints.txt"
    
    # AWS Keys
    grep -rhoE "AKIA[0-9A-Z]{16}" "$base/js/files/" 2>/dev/null | sort -u > "$base/js/aws_keys.txt"
    
    # AWS Secret
    grep -rhoE "['\"][A-Za-z0-9/+=]{40}['\"]" "$base/js/files/" 2>/dev/null | sort -u >> "$base/js/potential_secrets.txt"
    
    # Google API Keys
    grep -rhoE "AIza[0-9A-Za-z_-]{35}" "$base/js/files/" 2>/dev/null | sort -u > "$base/js/google_keys.txt"
    
    # Private Keys
    grep -rhoE "-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----" \
        "$base/js/files/" 2>/dev/null | sort -u > "$base/js/private_keys.txt"
    
    # JWT Tokens
    grep -rhoE "eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*" \
        "$base/js/files/" 2>/dev/null | sort -u > "$base/js/jwt_tokens.txt"
    
    # Bearer Tokens
    grep -rhoE "[Bb]earer\s+[A-Za-z0-9_-]+" "$base/js/files/" 2>/dev/null | sort -u > "$base/js/bearer_tokens.txt"
    
    # Generic API Keys
    grep -rhoiE "(api[_-]?key|apikey|api[_-]?secret)['\"]?\s*[:=]\s*['\"][A-Za-z0-9_-]+['\"]" \
        "$base/js/files/" 2>/dev/null | sort -u >> "$base/js/api_keys.txt"
    
    # Passwords
    grep -rhoiE "(password|passwd|pwd)['\"]?\s*[:=]\s*['\"][^'\"]+['\"]" \
        "$base/js/files/" 2>/dev/null | sort -u > "$base/js/passwords.txt"
    
    # Internal URLs
    grep -rhoE "https?://(localhost|127\.0\.0\.1|10\.[0-9.]+|192\.168\.[0-9.]+|172\.(1[6-9]|2[0-9]|3[01])\.[0-9.]+)[^\"'\`\s>]*" \
        "$base/js/files/" 2>/dev/null | sort -u > "$base/js/internal_urls.txt"
    
    # S3 Buckets
    grep -rhoE "[a-zA-Z0-9.-]+\.s3\.amazonaws\.com|s3://[a-zA-Z0-9.-]+" \
        "$base/js/files/" 2>/dev/null | sort -u > "$base/js/s3_buckets.txt"
    
    # ─────────────────────────────────────────────────────────────────────────
    # SecretFinder (if available)
    # ─────────────────────────────────────────────────────────────────────────
    if check_tool "secretfinder"; then
        log_info "Running SecretFinder..."
        
        for js_file in "$base/js/files"/*.js; do
            if [[ -f "$js_file" ]]; then
                python3 $(which secretfinder) -i "$js_file" -o cli 2>/dev/null
            fi
        done > "$base/js/secretfinder.txt" 2>/dev/null
    fi
    
    # ─────────────────────────────────────────────────────────────────────────
    # Beautify and check for source maps
    # ─────────────────────────────────────────────────────────────────────────
    log_info "Checking for source maps..."
    
    grep -rhoE "//# sourceMappingURL=[^\s]+" "$base/js/files/" 2>/dev/null | \
        sed 's|//# sourceMappingURL=||' | sort -u > "$base/js/source_maps.txt"
    
    # Try to download source maps
    if [[ -s "$base/js/source_maps.txt" ]]; then
        mkdir -p "$base/js/maps"
        while IFS= read -r map_url; do
            if [[ "$map_url" =~ ^http ]]; then
                curl -s -L --max-time 10 "$map_url" > "$base/js/maps/$(basename "$map_url")" 2>/dev/null
            fi
        done < "$base/js/source_maps.txt"
    fi
    
    # ─────────────────────────────────────────────────────────────────────────
    # Merge endpoints for next modules
    # ─────────────────────────────────────────────────────────────────────────
    cat "$base/js/endpoints.txt" "$base/js/api_endpoints.txt" 2>/dev/null | \
        sort -u > "$base/js/all_endpoints.txt"
    
    # ─────────────────────────────────────────────────────────────────────────
    # Stats
    # ─────────────────────────────────────────────────────────────────────────
    separator
    log_success "JavaScript analysis complete!"
    
    show_stats "JS files analyzed" "$base/js/js_urls.txt"
    show_stats "Endpoints found" "$base/js/all_endpoints.txt"
    show_stats "API keys found" "$base/js/api_keys.txt"
    show_stats "AWS keys found" "$base/js/aws_keys.txt"
    show_stats "JWT tokens found" "$base/js/jwt_tokens.txt"
    show_stats "Internal URLs" "$base/js/internal_urls.txt"
    show_stats "S3 buckets" "$base/js/s3_buckets.txt"
    
    # Critical findings
    for file in aws_keys google_keys private_keys passwords jwt_tokens; do
        if [[ -s "$base/js/${file}.txt" ]]; then
            log_critical "Found ${file}!"
            head -5 "$base/js/${file}.txt"
        fi
    done
    
    save_stat "js_files" "$js_count" "$base"
    save_stat "js_endpoints" "$(wc -l < "$base/js/all_endpoints.txt" 2>/dev/null)" "$base"
    
    return 0
}
