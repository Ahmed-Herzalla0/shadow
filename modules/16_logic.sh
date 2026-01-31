#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# SHADOW v5 - Module 16: Business Logic Testing
# ═══════════════════════════════════════════════════════════════════════════════
# Tests for business logic flaws:
# - Cross-user access (IDOR/BOLA)
# - Time-based assumptions
# - Session handling
# - Business flow violations
# ═══════════════════════════════════════════════════════════════════════════════

MODULE="16_LOGIC"

# Session storage
SESSION_DIR="$HOME/.shadow/sessions"

run() {
    local target="$1"
    local base="$2"
    
    banner "🎭 BUSINESS LOGIC TESTING → $target"
    
    mkdir -p "$base/logic"
    mkdir -p "$SESSION_DIR"
    
    # ─────────────────────────────────────────────────────────────────────────
    # 1. MULTI-USER SETUP
    # ─────────────────────────────────────────────────────────────────────────
    log_info "Setting up multi-user testing..."
    
    local user_a_cookies="$SESSION_DIR/${target}_userA.txt"
    local user_b_cookies="$SESSION_DIR/${target}_userB.txt"
    
    if [[ ! -f "$user_a_cookies" ]] || [[ ! -f "$user_b_cookies" ]]; then
        separator
        log_warn "═══════════════════════════════════════════════════════════════"
        log_warn "  MULTI-USER SESSION SETUP"
        log_warn "═══════════════════════════════════════════════════════════════"
        echo ""
        echo "Business logic testing requires TWO user sessions."
        echo ""
        echo "User A (normal user):"
        read -p "  Paste cookies: " user_a_input
        echo "$user_a_input" > "$user_a_cookies"
        
        echo ""
        echo "User B (different user):"
        read -p "  Paste cookies: " user_b_input
        echo "$user_b_input" > "$user_b_cookies"
        
        log_success "Sessions saved"
    else
        log_info "Using existing sessions"
    fi
    
    # ─────────────────────────────────────────────────────────────────────────
    # 2. CROSS-USER ACCESS TESTING (IDOR/BOLA)
    # ─────────────────────────────────────────────────────────────────────────
    log_info "🔀 Testing cross-user access..."
    
    : > "$base/logic/cross_user.txt"
    
    # Get user-related endpoints
    local user_endpoints="$base/intel/auth_endpoints.txt"
    [[ ! -f "$user_endpoints" ]] && user_endpoints="$base/brain/high_value.txt"
    
    if [[ -s "$user_endpoints" ]]; then
        while IFS= read -r url; do
            # Skip non-user endpoints
            if ! echo "$url" | grep -qEi "user|account|profile|me|order|settings"; then
                continue
            fi
            
            # Request as User A
            local response_a=$(curl -s -o /dev/null -w "%{http_code}|%{size_download}" \
                --max-time 10 -b "$(cat "$user_a_cookies")" "$url" 2>/dev/null)
            local status_a=$(echo "$response_a" | cut -d'|' -f1)
            local size_a=$(echo "$response_a" | cut -d'|' -f2)
            
            # Request as User B
            local response_b=$(curl -s -o /dev/null -w "%{http_code}|%{size_download}" \
                --max-time 10 -b "$(cat "$user_b_cookies")" "$url" 2>/dev/null)
            local status_b=$(echo "$response_b" | cut -d'|' -f1)
            local size_b=$(echo "$response_b" | cut -d'|' -f2)
            
            # Both users can access with same data?
            if [[ "$status_a" == "200" ]] && [[ "$status_b" == "200" ]]; then
                # Size similar = same data = IDOR!
                local size_diff=$((size_a - size_b))
                if [[ ${size_diff#-} -lt 100 ]]; then
                    echo "🚨 POTENTIAL IDOR: $url" >> "$base/logic/cross_user.txt"
                    echo "   User A: $status_a ($size_a bytes)" >> "$base/logic/cross_user.txt"
                    echo "   User B: $status_b ($size_b bytes)" >> "$base/logic/cross_user.txt"
                    echo "   Same size = Same data = Broken access control!" >> "$base/logic/cross_user.txt"
                    echo "" >> "$base/logic/cross_user.txt"
                fi
            fi
            
        done < <(head -30 "$user_endpoints")
    fi
    
    local cross_user_findings=$(grep -c "🚨" "$base/logic/cross_user.txt" 2>/dev/null || echo 0)
    log_found "Cross-user access issues: $cross_user_findings"
    
    # ─────────────────────────────────────────────────────────────────────────
    # 3. TIME-BASED ASSUMPTION TESTING
    # ─────────────────────────────────────────────────────────────────────────
    log_info "⏱️ Testing time-based assumptions..."
    
    : > "$base/logic/time_based.txt"
    
    # Save current cookies
    local current_cookies=$(cat "$user_a_cookies")
    
    # Test 1: Request replay
    log_info "Testing request replay..."
    
    if [[ -s "$base/brain/high_value.txt" ]]; then
        local test_url=$(head -1 "$base/brain/high_value.txt")
        
        # First request
        local response1=$(curl -s -o /dev/null -w "%{http_code}" \
            --max-time 10 -b "$current_cookies" "$test_url" 2>/dev/null)
        
        # Wait and replay
        log_info "Waiting 5 seconds for replay test..."
        sleep 5
        
        local response2=$(curl -s -o /dev/null -w "%{http_code}" \
            --max-time 10 -b "$current_cookies" "$test_url" 2>/dev/null)
        
        if [[ "$response1" == "200" ]] && [[ "$response2" == "200" ]]; then
            echo "Replay test: Both requests succeeded (no replay protection?)" >> "$base/logic/time_based.txt"
        fi
    fi
    
    # Test 2: Race condition potential
    log_info "Testing for race condition endpoints..."
    
    grep -Ei "transfer|withdraw|credit|debit|purchase|buy|order|create|submit" \
        "$base/brain/high_value.txt" 2>/dev/null | head -10 > "$base/logic/race_candidates.txt"
    
    if [[ -s "$base/logic/race_candidates.txt" ]]; then
        echo "" >> "$base/logic/time_based.txt"
        echo "=== Race Condition Candidates ===" >> "$base/logic/time_based.txt"
        echo "Test these endpoints with concurrent requests:" >> "$base/logic/time_based.txt"
        cat "$base/logic/race_candidates.txt" >> "$base/logic/time_based.txt"
    fi
    
    # ─────────────────────────────────────────────────────────────────────────
    # 4. PARAMETER POLLUTION
    # ─────────────────────────────────────────────────────────────────────────
    log_info "🔧 Testing HTTP Parameter Pollution..."
    
    : > "$base/logic/param_pollution.txt"
    
    # Get URLs with ID parameters
    grep -E "[?&]id=" "$base/params/urls_with_params.txt" 2>/dev/null | head -20 | while IFS= read -r url; do
        # Add duplicate parameter
        local polluted="${url}&id=999"
        
        local original_response=$(curl -s -o /dev/null -w "%{http_code}" \
            --max-time 10 "$url" 2>/dev/null)
        local polluted_response=$(curl -s -o /dev/null -w "%{http_code}" \
            --max-time 10 "$polluted" 2>/dev/null)
        
        if [[ "$original_response" != "$polluted_response" ]]; then
            echo "🚨 HPP DETECTED: $url" >> "$base/logic/param_pollution.txt"
            echo "   Original: $original_response" >> "$base/logic/param_pollution.txt"
            echo "   With duplicate id=999: $polluted_response" >> "$base/logic/param_pollution.txt"
            echo "" >> "$base/logic/param_pollution.txt"
        fi
    done
    
    # ─────────────────────────────────────────────────────────────────────────
    # 5. PRIVILEGE ESCALATION PATHS
    # ─────────────────────────────────────────────────────────────────────────
    log_info "👑 Looking for privilege escalation paths..."
    
    : > "$base/logic/privesc.txt"
    
    # Find admin/role endpoints
    grep -Ei "admin|role|permission|privilege|access|level|group" \
        "$base/params/all_urls.txt" 2>/dev/null > "$base/logic/admin_endpoints.txt"
    
    if [[ -s "$base/logic/admin_endpoints.txt" ]]; then
        echo "=== Potential Privilege Escalation Endpoints ===" >> "$base/logic/privesc.txt"
        echo "" >> "$base/logic/privesc.txt"
        
        while IFS= read -r url; do
            # Test with normal user session
            local response=$(curl -s -o /dev/null -w "%{http_code}" \
                --max-time 10 -b "$(cat "$user_a_cookies")" "$url" 2>/dev/null)
            
            if [[ "$response" == "200" ]]; then
                echo "⚠️ ACCESSIBLE: $url" >> "$base/logic/privesc.txt"
            elif [[ "$response" == "403" ]]; then
                echo "🔒 Protected: $url (but try bypass techniques)" >> "$base/logic/privesc.txt"
            fi
        done < <(head -20 "$base/logic/admin_endpoints.txt")
    fi
    
    # ─────────────────────────────────────────────────────────────────────────
    # 6. STATE MANIPULATION
    # ─────────────────────────────────────────────────────────────────────────
    log_info "📊 Testing state manipulation..."
    
    : > "$base/logic/state_manipulation.txt"
    
    # Find state-changing endpoints
    grep -Ei "status|state|stage|step|phase|complete|finish|confirm|approve" \
        "$base/params/all_urls.txt" 2>/dev/null | head -20 > "$base/logic/state_endpoints.txt"
    
    if [[ -s "$base/logic/state_endpoints.txt" ]]; then
        echo "=== State Manipulation Candidates ===" >> "$base/logic/state_manipulation.txt"
        echo "" >> "$base/logic/state_manipulation.txt"
        echo "Test these for:" >> "$base/logic/state_manipulation.txt"
        echo "  - Skipping workflow steps" >> "$base/logic/state_manipulation.txt"
        echo "  - Changing status without authorization" >> "$base/logic/state_manipulation.txt"
        echo "  - Reversing completed actions" >> "$base/logic/state_manipulation.txt"
        echo "" >> "$base/logic/state_manipulation.txt"
        cat "$base/logic/state_endpoints.txt" >> "$base/logic/state_manipulation.txt"
    fi
    
    # ─────────────────────────────────────────────────────────────────────────
    # 7. NUMERICAL MANIPULATION
    # ─────────────────────────────────────────────────────────────────────────
    log_info "🔢 Testing numerical manipulation..."
    
    : > "$base/logic/numerical.txt"
    
    # Find price/quantity/amount endpoints
    grep -Ei "(price|amount|quantity|qty|total|cost|fee|discount|coupon)=" \
        "$base/params/urls_with_params.txt" 2>/dev/null | head -20 > "$base/logic/money_endpoints.txt"
    
    if [[ -s "$base/logic/money_endpoints.txt" ]]; then
        echo "=== Numerical Manipulation Candidates ===" >> "$base/logic/numerical.txt"
        echo "" >> "$base/logic/numerical.txt"
        echo "Test these with:" >> "$base/logic/numerical.txt"
        echo "  - Negative numbers (price=-100)" >> "$base/logic/numerical.txt"
        echo "  - Zero (quantity=0)" >> "$base/logic/numerical.txt"
        echo "  - Decimals (price=0.01)" >> "$base/logic/numerical.txt"
        echo "  - Large numbers (quantity=999999999)" >> "$base/logic/numerical.txt"
        echo "  - Scientific notation (price=1e10)" >> "$base/logic/numerical.txt"
        echo "" >> "$base/logic/numerical.txt"
        cat "$base/logic/money_endpoints.txt" >> "$base/logic/numerical.txt"
    fi
    
    # ─────────────────────────────────────────────────────────────────────────
    # GENERATE REPORT
    # ─────────────────────────────────────────────────────────────────────────
    cat > "$base/logic/LOGIC_REPORT.txt" << EOF
═══════════════════════════════════════════════════════════════════════════════
                    🎭 BUSINESS LOGIC TESTING REPORT
                    Target: $target
                    Generated: $(date)
═══════════════════════════════════════════════════════════════════════════════

Business logic bugs = Most valuable bugs
They can't be found by scanners. Only by THINKING.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔀 CROSS-USER ACCESS (IDOR/BOLA)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

$(cat "$base/logic/cross_user.txt" 2>/dev/null || echo "No findings")

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔧 HTTP PARAMETER POLLUTION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

$(cat "$base/logic/param_pollution.txt" 2>/dev/null || echo "No findings")

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
⏱️ TIME-BASED & RACE CONDITIONS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

$(cat "$base/logic/time_based.txt" 2>/dev/null || echo "No findings")

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
👑 PRIVILEGE ESCALATION PATHS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

$(cat "$base/logic/privesc.txt" 2>/dev/null || echo "No findings")

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📊 STATE MANIPULATION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

$(cat "$base/logic/state_manipulation.txt" 2>/dev/null || echo "No findings")

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔢 NUMERICAL MANIPULATION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

$(cat "$base/logic/numerical.txt" 2>/dev/null || echo "No findings")

═══════════════════════════════════════════════════════════════════════════════
                    🎯 MANUAL TESTING CHECKLIST
═══════════════════════════════════════════════════════════════════════════════

□ Can User A access User B's data?
□ Can I skip steps in a workflow?
□ Can I modify prices/quantities client-side?
□ Are there race conditions in critical operations?
□ Can expired tokens still be used?
□ Can I access admin functions as normal user?
□ Can I manipulate state transitions?
□ Are numerical inputs validated server-side?

Each "Yes" = Business logic vulnerability = $$$

EOF
    
    separator
    log_success "Business logic testing complete!"
    log_info "Report: $base/logic/LOGIC_REPORT.txt"
    
    show_stats "Cross-user issues" "$base/logic/cross_user.txt"
    show_stats "HPP findings" "$base/logic/param_pollution.txt"
    show_stats "Privesc candidates" "$base/logic/admin_endpoints.txt"
    
    return 0
}
