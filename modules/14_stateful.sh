#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# SHADOW v5 - State-Aware Testing Module
# ═══════════════════════════════════════════════════════════════════════════════
# Authenticated testing with session management
# Login once, test everything with valid session
# ═══════════════════════════════════════════════════════════════════════════════

MODULE="14_STATEFUL"

# Session storage
SESSION_DIR="$HOME/.shadow/sessions"

run() {
    local target="$1"
    local base="$2"
    
    banner "🔐 STATE-AWARE TESTING → $target"
    
    mkdir -p "$base/stateful"
    mkdir -p "$SESSION_DIR"
    
    local cookie_file="$SESSION_DIR/${target}_cookies.txt"
    local session_file="$SESSION_DIR/${target}_session.json"
    
    # ─────────────────────────────────────────────────────────────────────────
    # 1. CHECK FOR EXISTING SESSION
    # ─────────────────────────────────────────────────────────────────────────
    if [[ -f "$cookie_file" ]]; then
        local age=$(($(date +%s) - $(stat -c %Y "$cookie_file" 2>/dev/null || echo 0)))
        local max_age="${SESSION_MAX_AGE:-3600}"  # 1 hour default
        
        if [[ $age -lt $max_age ]]; then
            log_info "Using existing session (age: ${age}s)"
        else
            log_warn "Session expired (age: ${age}s > ${max_age}s)"
            rm -f "$cookie_file"
        fi
    fi
    
    # ─────────────────────────────────────────────────────────────────────────
    # 2. SESSION SETUP (Manual or Automated)
    # ─────────────────────────────────────────────────────────────────────────
    if [[ ! -f "$cookie_file" ]]; then
        log_info "No active session found."
        
        if [[ "${ENABLE_MANUAL_LOGIN:-true}" == "true" ]]; then
            separator
            log_warn "═══════════════════════════════════════════════════════════════"
            log_warn "  SESSION SETUP REQUIRED"
            log_warn "═══════════════════════════════════════════════════════════════"
            echo ""
            echo "Options:"
            echo "  1. Paste cookies manually"
            echo "  2. Import from browser (copy as cURL)"
            echo "  3. Skip authenticated testing"
            echo ""
            read -p "Choice [1-3]: " session_choice
            
            case "$session_choice" in
                1)
                    echo ""
                    echo "Paste cookies in format: name=value; name2=value2"
                    read -p "Cookies: " manual_cookies
                    echo "$manual_cookies" > "$cookie_file"
                    log_success "Cookies saved"
                    ;;
                2)
                    echo ""
                    echo "Paste the 'Cookie:' header value from cURL:"
                    read -p "Cookie header: " curl_cookies
                    echo "$curl_cookies" > "$cookie_file"
                    log_success "Cookies imported"
                    ;;
                3)
                    log_warn "Skipping authenticated testing"
                    echo "unauthenticated" > "$base/stateful/mode.txt"
                    ;;
            esac
        fi
    fi
    
    # ─────────────────────────────────────────────────────────────────────────
    # 3. TEST WITH/WITHOUT SESSION
    # ─────────────────────────────────────────────────────────────────────────
    local high_value="$base/brain/high_value.txt"
    
    if [[ ! -f "$high_value" ]]; then
        high_value="$base/params/all_urls.txt"
    fi
    
    if [[ ! -s "$high_value" ]]; then
        log_error "No URLs to test"
        return 1
    fi
    
    # Take sample for testing
    head -100 "$high_value" > "$base/stateful/test_sample.txt"
    
    log_info "Testing $(wc -l < "$base/stateful/test_sample.txt") endpoints..."
    
    # Test WITHOUT auth
    log_info "Testing without authentication..."
    : > "$base/stateful/unauth_results.txt"
    
    while IFS= read -r url; do
        local response=$(curl -s -o /dev/null -w "%{http_code}|%{size_download}|%{redirect_url}" \
            --max-time 10 "$url" 2>/dev/null)
        echo "$url|$response" >> "$base/stateful/unauth_results.txt"
    done < "$base/stateful/test_sample.txt"
    
    # Test WITH auth (if we have cookies)
    if [[ -f "$cookie_file" && -s "$cookie_file" ]]; then
        log_info "Testing with authentication..."
        : > "$base/stateful/auth_results.txt"
        
        local cookies=$(cat "$cookie_file")
        
        while IFS= read -r url; do
            local response=$(curl -s -o /dev/null -w "%{http_code}|%{size_download}|%{redirect_url}" \
                --max-time 10 \
                -H "Cookie: $cookies" \
                "$url" 2>/dev/null)
            echo "$url|$response" >> "$base/stateful/auth_results.txt"
        done < "$base/stateful/test_sample.txt"
    fi
    
    # ─────────────────────────────────────────────────────────────────────────
    # 4. COMPARE RESULTS (Find Auth-Dependent Behavior)
    # ─────────────────────────────────────────────────────────────────────────
    log_info "Analyzing authentication differences..."
    
    : > "$base/stateful/auth_diff.txt"
    : > "$base/stateful/access_gained.txt"
    : > "$base/stateful/access_lost.txt"
    
    if [[ -f "$base/stateful/auth_results.txt" ]]; then
        while IFS='|' read -r url unauth_status unauth_size unauth_redirect; do
            # Find same URL in auth results
            local auth_line=$(grep "^$url|" "$base/stateful/auth_results.txt" 2>/dev/null)
            
            if [[ -n "$auth_line" ]]; then
                local auth_status=$(echo "$auth_line" | cut -d'|' -f2)
                local auth_size=$(echo "$auth_line" | cut -d'|' -f3)
                
                # Status code changed?
                if [[ "$unauth_status" != "$auth_status" ]]; then
                    echo "$url: $unauth_status → $auth_status" >> "$base/stateful/auth_diff.txt"
                    
                    # Access gained with auth?
                    if [[ "$unauth_status" =~ ^(401|403|302)$ ]] && [[ "$auth_status" == "200" ]]; then
                        echo "$url" >> "$base/stateful/access_gained.txt"
                    fi
                    
                    # Access lost with auth? (weird, potential bug)
                    if [[ "$unauth_status" == "200" ]] && [[ "$auth_status" =~ ^(401|403)$ ]]; then
                        echo "$url (WEIRD: auth reduces access!)" >> "$base/stateful/access_lost.txt"
                    fi
                fi
                
                # Size significantly different? (different content)
                if [[ -n "$unauth_size" && -n "$auth_size" ]]; then
                    local size_diff=$((auth_size - unauth_size))
                    if [[ ${size_diff#-} -gt 1000 ]]; then  # More than 1KB difference
                        echo "$url: size diff ${size_diff} bytes" >> "$base/stateful/size_diff.txt"
                    fi
                fi
            fi
        done < "$base/stateful/unauth_results.txt"
    fi
    
    # ─────────────────────────────────────────────────────────────────────────
    # 5. FIND AUTHORIZATION ISSUES
    # ─────────────────────────────────────────────────────────────────────────
    log_info "Looking for authorization issues..."
    
    # Endpoints that should require auth but don't
    : > "$base/stateful/no_auth_required.txt"
    
    # Check for sensitive endpoints accessible without auth
    while IFS='|' read -r url status size redirect; do
        if [[ "$status" == "200" ]]; then
            # Is this a sensitive endpoint?
            if echo "$url" | grep -qEi "admin|user|account|profile|settings|api.*me|private|internal"; then
                echo "$url (200 without auth!)" >> "$base/stateful/no_auth_required.txt"
            fi
        fi
    done < "$base/stateful/unauth_results.txt"
    
    # ─────────────────────────────────────────────────────────────────────────
    # 6. GENERATE REPORT
    # ─────────────────────────────────────────────────────────────────────────
    cat > "$base/stateful/STATEFUL_REPORT.txt" << EOF
═══════════════════════════════════════════════════════════════════════════════
                    🔐 STATEFUL TESTING REPORT
                    Target: $target
                    Generated: $(date)
═══════════════════════════════════════════════════════════════════════════════

Session: $(if [[ -f "$cookie_file" ]]; then echo "Active"; else echo "None"; fi)
Tested endpoints: $(wc -l < "$base/stateful/test_sample.txt" 2>/dev/null || echo 0)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🚨 AUTHORIZATION ISSUES (High Priority!)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Sensitive endpoints accessible WITHOUT auth:
$(cat "$base/stateful/no_auth_required.txt" 2>/dev/null || echo "None found")

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔄 AUTH-DEPENDENT STATUS CHANGES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

$(head -20 "$base/stateful/auth_diff.txt" 2>/dev/null || echo "No differences")

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✅ ACCESS GAINED WITH AUTH
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

$(cat "$base/stateful/access_gained.txt" 2>/dev/null || echo "None")

These are authenticated endpoints - test for:
- IDOR (change user IDs)
- Privilege escalation (access other users' data)
- Business logic flaws

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
⚠️ WEIRD BEHAVIOR (Auth reduces access?!)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

$(cat "$base/stateful/access_lost.txt" 2>/dev/null || echo "None")

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📏 SIGNIFICANT SIZE DIFFERENCES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

$(head -10 "$base/stateful/size_diff.txt" 2>/dev/null || echo "None")

(Different content = different data = potential IDOR)

EOF
    
    separator
    log_success "Stateful testing complete!"
    log_info "Report: $base/stateful/STATEFUL_REPORT.txt"
    
    show_stats "Auth differences" "$base/stateful/auth_diff.txt"
    show_stats "Access gained" "$base/stateful/access_gained.txt"
    show_stats "No auth required" "$base/stateful/no_auth_required.txt"
    
    return 0
}

# ─────────────────────────────────────────────────────────────────────────────
# HELPER: Import cookies from browser
# ─────────────────────────────────────────────────────────────────────────────
import_cookies_from_curl() {
    local curl_command="$1"
    local output_file="$2"
    
    # Extract Cookie header from curl command
    echo "$curl_command" | grep -oP "(?<=-H 'Cookie: )[^']*" > "$output_file"
}

# ─────────────────────────────────────────────────────────────────────────────
# HELPER: Test single endpoint with session
# ─────────────────────────────────────────────────────────────────────────────
test_with_session() {
    local url="$1"
    local cookie_file="$2"
    
    if [[ -f "$cookie_file" ]]; then
        curl -s -b "$cookie_file" "$url"
    else
        curl -s "$url"
    fi
}
