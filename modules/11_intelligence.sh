#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# SHADOW v5 - Module 11: Intelligence Analysis
# ═══════════════════════════════════════════════════════════════════════════════
# Advanced analysis: Auth mapping, param intel, JS filtering, scoring
# This is where script kiddie becomes professional hunter
# ═══════════════════════════════════════════════════════════════════════════════

MODULE="11_INTEL"

run() {
    local target="$1"
    local base="$2"
    
    banner "🧠 INTELLIGENCE ANALYSIS → $target"
    
    mkdir -p "$base/intel"
    
    # ─────────────────────────────────────────────────────────────────────────
    # 1. AUTH SURFACE MAPPING
    # ─────────────────────────────────────────────────────────────────────────
    log_info "Mapping authentication surface..."
    
    local auth_patterns="${AUTH_PATTERNS:-login|logout|callback|oauth|sso|auth|token|session|register|signup|password|reset|forgot|verify|confirm|2fa|mfa|otp}"
    
    # Extract auth-related URLs
    if [[ -f "$base/params/all_urls.txt" ]]; then
        grep -Ei "$auth_patterns" "$base/params/all_urls.txt" > "$base/intel/auth_endpoints.txt" 2>/dev/null
        
        local auth_count=$(wc -l < "$base/intel/auth_endpoints.txt" 2>/dev/null || echo 0)
        log_found "Auth endpoints: $auth_count"
        
        # Categorize auth endpoints
        grep -Ei "login|signin|sign-in" "$base/intel/auth_endpoints.txt" > "$base/intel/auth_login.txt" 2>/dev/null
        grep -Ei "logout|signout|sign-out" "$base/intel/auth_endpoints.txt" > "$base/intel/auth_logout.txt" 2>/dev/null
        grep -Ei "register|signup|sign-up|create.?account" "$base/intel/auth_endpoints.txt" > "$base/intel/auth_register.txt" 2>/dev/null
        grep -Ei "callback|oauth|sso" "$base/intel/auth_endpoints.txt" > "$base/intel/auth_oauth.txt" 2>/dev/null
        grep -Ei "reset|forgot|recover" "$base/intel/auth_endpoints.txt" > "$base/intel/auth_recovery.txt" 2>/dev/null
        grep -Ei "2fa|mfa|otp|verify|confirm" "$base/intel/auth_endpoints.txt" > "$base/intel/auth_mfa.txt" 2>/dev/null
        grep -Ei "token|api.?key|bearer" "$base/intel/auth_endpoints.txt" > "$base/intel/auth_tokens.txt" 2>/dev/null
    fi
    
    # Extract from HTTP responses
    if [[ -f "$base/http/httpx_full.txt" ]]; then
        grep -Ei "$auth_patterns" "$base/http/httpx_full.txt" > "$base/intel/auth_hosts.txt" 2>/dev/null
    fi
    
    # ─────────────────────────────────────────────────────────────────────────
    # 2. PARAMETER INTELLIGENCE
    # ─────────────────────────────────────────────────────────────────────────
    log_info "Analyzing parameters intelligently..."
    
    local interesting_params="${INTERESTING_PARAMS:-id|user|account|org|role|admin|redirect|next|return|url|file|path|doc|page|action|cmd|exec|callback}"
    
    if [[ -f "$base/params/all_urls.txt" ]]; then
        # Extract all unique parameter names
        if check_tool "unfurl"; then
            cat "$base/params/all_urls.txt" | unfurl keys 2>/dev/null | sort -u > "$base/intel/all_params.txt"
        else
            grep -oE "[?&][a-zA-Z0-9_-]+=" "$base/params/all_urls.txt" | \
                sed 's/[?&]//;s/=//' | sort -u > "$base/intel/all_params.txt"
        fi
        
        # Classify parameters by danger level
        log_info "Classifying parameters..."
        
        # IDOR suspects (id-like params)
        grep -Ei "^(id|user.?id|account.?id|org.?id|order.?id|doc.?id|file.?id|item.?id|product.?id|uid|uuid|guid|ref|reference)$" \
            "$base/intel/all_params.txt" > "$base/intel/params_idor.txt" 2>/dev/null
        
        # Redirect suspects
        grep -Ei "^(redirect|url|next|return|redir|destination|target|goto|continue|returnurl|return_to|callback|forward|ref|source|site|go)$" \
            "$base/intel/all_params.txt" > "$base/intel/params_redirect.txt" 2>/dev/null
        
        # File/Path suspects (LFI/RFI)
        grep -Ei "^(file|path|filepath|doc|document|template|page|include|require|src|source|dir|folder|root|style|view|layout)$" \
            "$base/intel/all_params.txt" > "$base/intel/params_lfi.txt" 2>/dev/null
        
        # Command execution suspects
        grep -Ei "^(cmd|exec|command|run|execute|ping|query|search|daemon|upload|download|log|email|host|ip|port)$" \
            "$base/intel/all_params.txt" > "$base/intel/params_rce.txt" 2>/dev/null
        
        # SQL injection suspects
        grep -Ei "^(id|user|name|email|search|query|filter|sort|order|column|table|field|category|item|product|type|select|where|limit)$" \
            "$base/intel/all_params.txt" > "$base/intel/params_sqli.txt" 2>/dev/null
        
        # SSRF suspects
        grep -Ei "^(url|uri|host|domain|server|site|link|api|proxy|webhook|callback|feed|request|fetch|load|img|image)$" \
            "$base/intel/all_params.txt" > "$base/intel/params_ssrf.txt" 2>/dev/null
        
        # XSS suspects
        grep -Ei "^(search|query|q|keyword|name|title|message|comment|text|content|body|value|input|data|html|error|success|alert|msg)$" \
            "$base/intel/all_params.txt" > "$base/intel/params_xss.txt" 2>/dev/null
        
        # Get URLs with interesting params
        grep -Ei "[\?&]($interesting_params)=" "$base/params/all_urls.txt" > "$base/intel/urls_interesting_params.txt" 2>/dev/null
        
        log_found "Interesting param URLs: $(wc -l < "$base/intel/urls_interesting_params.txt" 2>/dev/null || echo 0)"
    fi
    
    # ─────────────────────────────────────────────────────────────────────────
    # 3. JS RUNTIME ANALYSIS (Smart Filtering)
    # ─────────────────────────────────────────────────────────────────────────
    log_info "Filtering security-relevant JavaScript..."
    
    local js_patterns="${JS_SECURITY_PATTERNS:-postMessage|innerHTML|outerHTML|document\.write|eval|location\.|cookie|localStorage|sessionStorage|fetch\(|XMLHttpRequest}"
    
    if [[ -d "$base/js/files" ]]; then
        # Find JS files with security-relevant patterns
        grep -rlE "$js_patterns" "$base/js/files/" 2>/dev/null | while read -r js_file; do
            local url_file="${js_file}.url"
            if [[ -f "$url_file" ]]; then
                echo "$(cat "$url_file")" >> "$base/intel/js_interesting.txt"
            fi
        done
        
        # Detailed analysis of interesting JS
        : > "$base/intel/js_analysis.txt"
        
        for pattern in "postMessage" "innerHTML" "eval(" "document.write" "location.href" "cookie" "localStorage"; do
            local matches=$(grep -rl "$pattern" "$base/js/files/" 2>/dev/null | wc -l)
            if [[ $matches -gt 0 ]]; then
                echo "$pattern: $matches files" >> "$base/intel/js_analysis.txt"
            fi
        done
        
        # DOM XSS candidates
        grep -rlE "(innerHTML|outerHTML|document\.write|\.html\()" "$base/js/files/" 2>/dev/null | while read -r f; do
            local url_file="${f}.url"
            [[ -f "$url_file" ]] && cat "$url_file"
        done > "$base/intel/js_dom_xss.txt" 2>/dev/null
        
        # postMessage handlers (potential XSS)
        grep -rlE "addEventListener.*message|onmessage" "$base/js/files/" 2>/dev/null | while read -r f; do
            local url_file="${f}.url"
            [[ -f "$url_file" ]] && cat "$url_file"
        done > "$base/intel/js_postmessage.txt" 2>/dev/null
        
        log_found "Security-relevant JS files: $(wc -l < "$base/intel/js_interesting.txt" 2>/dev/null || echo 0)"
    fi
    
    # ─────────────────────────────────────────────────────────────────────────
    # 4. HTTP BEHAVIOR ANALYSIS
    # ─────────────────────────────────────────────────────────────────────────
    log_info "Analyzing HTTP behavior patterns..."
    
    if [[ -f "$base/http/httpx.json" ]]; then
        # Status code distribution for logic bug hunting
        jq -r '.status_code' "$base/http/httpx.json" 2>/dev/null | sort | uniq -c | sort -rn > "$base/intel/status_distribution.txt"
        
        # 401 vs 403 (auth vs authz)
        jq -r 'select(.status_code == 401) | .url' "$base/http/httpx.json" > "$base/intel/http_401_auth.txt" 2>/dev/null
        jq -r 'select(.status_code == 403) | .url' "$base/http/httpx.json" > "$base/intel/http_403_authz.txt" 2>/dev/null
        
        # Redirects (potential open redirect)
        jq -r 'select(.status_code >= 300 and .status_code < 400) | .url' "$base/http/httpx.json" > "$base/intel/http_redirects.txt" 2>/dev/null
        
        # Server errors (potential injection points)
        jq -r 'select(.status_code >= 500) | .url' "$base/http/httpx.json" > "$base/intel/http_500_errors.txt" 2>/dev/null
        
        log_found "401 Authentication: $(wc -l < "$base/intel/http_401_auth.txt" 2>/dev/null || echo 0)"
        log_found "403 Authorization: $(wc -l < "$base/intel/http_403_authz.txt" 2>/dev/null || echo 0)"
        log_found "500 Errors: $(wc -l < "$base/intel/http_500_errors.txt" 2>/dev/null || echo 0)"
    fi
    
    # Header analysis
    if [[ -f "$base/http/httpx_full.txt" ]]; then
        # Look for interesting headers in responses
        grep -Ei "x-debug|x-forwarded|x-original|x-real|x-request-id" "$base/http/httpx_full.txt" > "$base/intel/debug_headers.txt" 2>/dev/null
    fi
    
    # ─────────────────────────────────────────────────────────────────────────
    # 5. TARGET SCORING
    # ─────────────────────────────────────────────────────────────────────────
    if [[ "${ENABLE_SCORING:-true}" == "true" ]]; then
        log_info "Scoring targets for prioritization..."
        
        : > "$base/intel/scored_targets.txt"
        
        # Score each alive URL
        if [[ -f "$base/http/httpx.json" ]]; then
            while IFS= read -r line; do
                local url=$(echo "$line" | jq -r '.url' 2>/dev/null)
                local status=$(echo "$line" | jq -r '.status_code' 2>/dev/null)
                local title=$(echo "$line" | jq -r '.title // ""' 2>/dev/null)
                local tech=$(echo "$line" | jq -r '.tech // []' 2>/dev/null)
                local score=0
                
                # Status code scoring
                [[ "$status" == "200" ]] && score=$((score + ${SCORE_200:-1}))
                [[ "$status" == "401" ]] && score=$((score + 2))  # Auth interesting
                [[ "$status" == "403" ]] && score=$((score + 2))  # Bypass candidate
                [[ "$status" == "500" ]] && score=$((score + 3))  # Error = vuln potential
                
                # Has parameters?
                if grep -qF "$url" "$base/params/urls_with_params.txt" 2>/dev/null; then
                    score=$((score + ${SCORE_HAS_PARAMS:-2}))
                fi
                
                # Auth related?
                if echo "$url" | grep -qEi "$auth_patterns"; then
                    score=$((score + ${SCORE_AUTH_RELATED:-3}))
                fi
                
                # Admin panel?
                if echo "$url$title" | grep -qEi "admin|dashboard|panel|console|manage"; then
                    score=$((score + ${SCORE_ADMIN_PANEL:-4}))
                fi
                
                # API endpoint?
                if echo "$url" | grep -qEi "/api/|/v[0-9]+/|graphql|rest"; then
                    score=$((score + ${SCORE_API_ENDPOINT:-2}))
                fi
                
                # Interesting tech?
                if echo "$tech" | grep -qEi "php|asp|jsp|jenkins|gitlab|grafana"; then
                    score=$((score + ${SCORE_INTERESTING_TECH:-3}))
                fi
                
                echo "$score $url" >> "$base/intel/scored_targets.txt"
                
            done < <(cat "$base/http/httpx.json")
            
            # Sort by score (highest first)
            sort -rn "$base/intel/scored_targets.txt" -o "$base/intel/scored_targets.txt"
            
            log_success "Scored $(wc -l < "$base/intel/scored_targets.txt") targets"
        fi
    fi
    
    # ─────────────────────────────────────────────────────────────────────────
    # 6. PRIORITY REPORT
    # ─────────────────────────────────────────────────────────────────────────
    log_info "Generating priority report..."
    
    cat > "$base/intel/PRIORITY_REPORT.txt" << EOF
═══════════════════════════════════════════════════════════════════════════════
                    SHADOW INTELLIGENCE REPORT
                    Target: $target
                    Generated: $(date)
═══════════════════════════════════════════════════════════════════════════════

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔴 HIGH PRIORITY TARGETS (Start Here!)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Top 20 Scored Targets:
$(head -20 "$base/intel/scored_targets.txt" 2>/dev/null || echo "No scored targets")

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔑 AUTHENTICATION SURFACE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Login Endpoints ($(wc -l < "$base/intel/auth_login.txt" 2>/dev/null || echo 0)):
$(head -10 "$base/intel/auth_login.txt" 2>/dev/null || echo "None found")

OAuth/SSO ($(wc -l < "$base/intel/auth_oauth.txt" 2>/dev/null || echo 0)):
$(head -10 "$base/intel/auth_oauth.txt" 2>/dev/null || echo "None found")

Password Recovery ($(wc -l < "$base/intel/auth_recovery.txt" 2>/dev/null || echo 0)):
$(head -10 "$base/intel/auth_recovery.txt" 2>/dev/null || echo "None found")

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🎯 IDOR CANDIDATES (Check These!)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

IDOR Parameters Found:
$(cat "$base/intel/params_idor.txt" 2>/dev/null | head -20 || echo "None found")

Sample URLs with ID params:
$(grep -Ei "[?&](id|user.?id|account.?id|order.?id)=" "$base/intel/urls_interesting_params.txt" 2>/dev/null | head -10 || echo "None found")

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔀 OPEN REDIRECT CANDIDATES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Redirect Parameters:
$(cat "$base/intel/params_redirect.txt" 2>/dev/null || echo "None found")

Sample URLs:
$(grep -Ei "[?&](redirect|url|next|return|callback)=" "$base/intel/urls_interesting_params.txt" 2>/dev/null | head -10 || echo "None found")

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📂 LFI/PATH TRAVERSAL CANDIDATES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

File Parameters:
$(cat "$base/intel/params_lfi.txt" 2>/dev/null || echo "None found")

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🌐 SSRF CANDIDATES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

URL/Fetch Parameters:
$(cat "$base/intel/params_ssrf.txt" 2>/dev/null || echo "None found")

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📜 JAVASCRIPT ANALYSIS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Security Pattern Distribution:
$(cat "$base/intel/js_analysis.txt" 2>/dev/null || echo "No JS analyzed")

DOM XSS Candidates ($(wc -l < "$base/intel/js_dom_xss.txt" 2>/dev/null || echo 0)):
$(head -5 "$base/intel/js_dom_xss.txt" 2>/dev/null || echo "None found")

PostMessage Handlers ($(wc -l < "$base/intel/js_postmessage.txt" 2>/dev/null || echo 0)):
$(head -5 "$base/intel/js_postmessage.txt" 2>/dev/null || echo "None found")

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
⚠️ ERROR ENDPOINTS (Potential Vulns)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

500 Errors:
$(head -10 "$base/intel/http_500_errors.txt" 2>/dev/null || echo "None found")

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🛡️ 403 BYPASS CANDIDATES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

$(head -10 "$base/intel/http_403_authz.txt" 2>/dev/null || echo "None found")

═══════════════════════════════════════════════════════════════════════════════
                    NEXT STEPS
═══════════════════════════════════════════════════════════════════════════════

1. Pick ONE endpoint from "High Priority Targets"
2. Open Burp Suite → Proxy → Intercept
3. Navigate to that endpoint manually
4. Analyze request/response in Repeater
5. Test for IDOR/Logic bugs

Remember: Burp is for ANALYSIS, not for running these tools through!

EOF
    
    # Copy important files to root
    [[ -s "$base/intel/auth_endpoints.txt" ]] && cp "$base/intel/auth_endpoints.txt" "$base/subs_intel.txt"
    
    # ─────────────────────────────────────────────────────────────────────────
    # 7. CHECKPOINT (if enabled)
    # ─────────────────────────────────────────────────────────────────────────
    if [[ "${ENABLE_CHECKPOINTS:-false}" == "true" ]]; then
        separator
        log_warn "═══════════════════════════════════════════════════════════════"
        log_warn "  CHECKPOINT: Intelligence analysis complete"
        log_warn "═══════════════════════════════════════════════════════════════"
        echo ""
        cat "$base/intel/PRIORITY_REPORT.txt" | head -50
        echo ""
        log_warn "Read the report: $base/intel/PRIORITY_REPORT.txt"
        echo ""
        read -p "🎯 Pick ONE endpoint to analyze manually (or 'skip'): " chosen_endpoint
        
        if [[ -z "$chosen_endpoint" || "$chosen_endpoint" == "skip" ]]; then
            log_warn "Skipped manual analysis checkpoint"
        else
            echo "$chosen_endpoint" >> "$base/intel/manual_targets.txt"
            log_success "Saved: $chosen_endpoint"
        fi
    fi
    
    separator
    log_success "Intelligence analysis complete!"
    log_info "Priority report: $base/intel/PRIORITY_REPORT.txt"
    
    # Stats summary
    separator
    show_stats "Auth endpoints" "$base/intel/auth_endpoints.txt"
    show_stats "Interesting param URLs" "$base/intel/urls_interesting_params.txt"
    show_stats "Security-relevant JS" "$base/intel/js_interesting.txt"
    show_stats "Scored targets" "$base/intel/scored_targets.txt"
    
    return 0
}
