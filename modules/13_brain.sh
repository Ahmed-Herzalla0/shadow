#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# SHADOW v5 - Module 13: BRAIN (Intelligent Analysis Engine)
# ═══════════════════════════════════════════════════════════════════════════════
# This module makes the script "think" instead of just "run"
# Auto-pruning, Pattern detection, Differential analysis, Smart mutation
# ═══════════════════════════════════════════════════════════════════════════════

MODULE="13_BRAIN"

run() {
    local target="$1"
    local base="$2"
    
    banner "🧠 BRAIN ENGINE → $target"
    
    mkdir -p "$base/brain"
    
    # ─────────────────────────────────────────────────────────────────────────
    # 1. AUTO-PRUNING (Remove garbage, keep gold)
    # ─────────────────────────────────────────────────────────────────────────
    log_info "🗑️  Auto-pruning useless URLs..."
    
    local all_urls="$base/params/all_urls.txt"
    
    if [[ ! -s "$all_urls" ]]; then
        log_error "No URLs found. Run params module first."
        return 1
    fi
    
    local original_count=$(wc -l < "$all_urls")
    
    # Remove static files and garbage
    grep -Ev "\.(js|css|png|jpg|jpeg|gif|svg|woff|woff2|ttf|eot|ico|pdf|zip|rar|mp4|mp3|avi|mov)(\?|$)" \
        "$all_urls" > "$base/brain/no_static.txt" 2>/dev/null
    
    # Remove URLs without parameters (unless they're API endpoints)
    grep -E "(\?|/api/|/v[0-9]+/|/graphql|/rest/)" "$base/brain/no_static.txt" > "$base/brain/with_params.txt" 2>/dev/null
    
    # Remove known 404/410 from httpx results
    if [[ -f "$base/http/httpx.json" ]]; then
        # Get URLs that returned 404/410
        jq -r 'select(.status_code == 404 or .status_code == 410) | .url' \
            "$base/http/httpx.json" 2>/dev/null > "$base/brain/dead_urls.txt"
        
        # Remove dead URLs from candidates
        if [[ -s "$base/brain/dead_urls.txt" ]]; then
            grep -Fvf "$base/brain/dead_urls.txt" "$base/brain/with_params.txt" > "$base/brain/alive_params.txt" 2>/dev/null
            mv "$base/brain/alive_params.txt" "$base/brain/with_params.txt"
        fi
    fi
    
    # Final pruned list
    cp "$base/brain/with_params.txt" "$base/brain/candidates.txt" 2>/dev/null
    
    local pruned_count=$(wc -l < "$base/brain/candidates.txt" 2>/dev/null || echo 0)
    local removed=$((original_count - pruned_count))
    local percentage=$((removed * 100 / original_count))
    
    log_success "Pruned $removed URLs ($percentage% reduction)"
    log_found "Candidates remaining: $pruned_count"
    
    # ─────────────────────────────────────────────────────────────────────────
    # 2. PATTERN-BASED PRIORITIZATION
    # ─────────────────────────────────────────────────────────────────────────
    log_info "🎯 Detecting high-value patterns..."
    
    # High-value patterns
    local patterns=(
        "/api/"
        "/v[0-9]+/"
        "/me"
        "/user"
        "/admin"
        "/export"
        "/download"
        "/upload"
        "/import"
        "/callback"
        "/webhook"
        "/internal"
        "/private"
        "/debug"
        "/config"
        "/settings"
        "/account"
        "/profile"
        "/order"
        "/payment"
        "/invoice"
        "/delete"
        "/remove"
        "/update"
        "/edit"
        "/create"
        "/graphql"
    )
    
    : > "$base/brain/high_value.txt"
    
    for pattern in "${patterns[@]}"; do
        grep -Ei "$pattern" "$base/brain/candidates.txt" >> "$base/brain/high_value.txt" 2>/dev/null
    done
    
    sort -u "$base/brain/high_value.txt" -o "$base/brain/high_value.txt"
    
    local high_value_count=$(wc -l < "$base/brain/high_value.txt" 2>/dev/null || echo 0)
    log_found "High-value endpoints: $high_value_count"
    
    # Pattern distribution analysis
    log_info "Pattern distribution:"
    for pattern in "/api/" "/admin" "/user" "/export" "/callback"; do
        local count=$(grep -c "$pattern" "$base/brain/high_value.txt" 2>/dev/null || echo 0)
        if [[ $count -gt 0 ]]; then
            echo "  → $pattern: $count"
        fi
    done
    
    # ─────────────────────────────────────────────────────────────────────────
    # 3. DIFFERENTIAL BEHAVIOR DETECTION
    # ─────────────────────────────────────────────────────────────────────────
    if [[ "${ENABLE_DIFF_DETECTION:-true}" == "true" ]]; then
        log_info "🔍 Detecting auth-dependent behavior..."
        
        # Take sample of high-value URLs (max 50 for speed)
        head -50 "$base/brain/high_value.txt" > "$base/brain/diff_sample.txt" 2>/dev/null
        
        if [[ -s "$base/brain/diff_sample.txt" ]]; then
            # Request without auth headers
            httpx -l "$base/brain/diff_sample.txt" \
                  -silent \
                  -status-code \
                  -no-color \
                  -o "$base/brain/no_auth_response.txt" 2>/dev/null
            
            # Request with fake auth (to trigger different behavior)
            httpx -l "$base/brain/diff_sample.txt" \
                  -silent \
                  -status-code \
                  -no-color \
                  -H "Authorization: Bearer test123" \
                  -H "Cookie: session=test; auth=1" \
                  -o "$base/brain/with_auth_response.txt" 2>/dev/null
            
            # Compare responses
            : > "$base/brain/auth_diff.txt"
            
            while IFS= read -r line1; do
                url1=$(echo "$line1" | awk '{print $1}')
                status1=$(echo "$line1" | grep -oE '\[[0-9]+\]' | tr -d '[]')
                
                # Find same URL in auth response
                line2=$(grep "^$url1 " "$base/brain/with_auth_response.txt" 2>/dev/null)
                status2=$(echo "$line2" | grep -oE '\[[0-9]+\]' | tr -d '[]')
                
                if [[ -n "$status1" && -n "$status2" && "$status1" != "$status2" ]]; then
                    echo "$url1: $status1 → $status2 (AUTH DIFF!)" >> "$base/brain/auth_diff.txt"
                fi
            done < "$base/brain/no_auth_response.txt"
            
            local diff_count=$(wc -l < "$base/brain/auth_diff.txt" 2>/dev/null || echo 0)
            if [[ $diff_count -gt 0 ]]; then
                log_found "🚨 Auth-dependent endpoints: $diff_count"
            fi
        fi
    fi
    
    # ─────────────────────────────────────────────────────────────────────────
    # 4. PARAMETER MUTATION (Smart IDOR hunting)
    # ─────────────────────────────────────────────────────────────────────────
    log_info "🔄 Generating parameter mutations for IDOR..."
    
    : > "$base/brain/mutated_urls.txt"
    : > "$base/brain/idor_candidates.txt"
    
    # Find URLs with numeric IDs
    grep -E "[?&](id|user_id|account_id|order_id|doc_id|file_id|item_id|product_id)=[0-9]+" \
        "$base/brain/candidates.txt" > "$base/brain/numeric_id_urls.txt" 2>/dev/null
    
    if [[ -s "$base/brain/numeric_id_urls.txt" ]]; then
        while IFS= read -r url; do
            # Original
            echo "$url" >> "$base/brain/idor_candidates.txt"
            
            # Mutation: id=X → id=1
            echo "$url" | sed -E 's/(id=)[0-9]+/\11/g' >> "$base/brain/mutated_urls.txt"
            
            # Mutation: id=X → id=0
            echo "$url" | sed -E 's/(id=)[0-9]+/\10/g' >> "$base/brain/mutated_urls.txt"
            
            # Mutation: id=X → id=999999
            echo "$url" | sed -E 's/(id=)[0-9]+/\1999999/g' >> "$base/brain/mutated_urls.txt"
            
            # Mutation: id=X → id=-1
            echo "$url" | sed -E 's/(id=)[0-9]+/\1-1/g' >> "$base/brain/mutated_urls.txt"
            
            # Mutation: id=X → id=X+1
            current_id=$(echo "$url" | grep -oE 'id=[0-9]+' | head -1 | cut -d= -f2)
            if [[ -n "$current_id" ]]; then
                next_id=$((current_id + 1))
                echo "$url" | sed -E "s/(id=)[0-9]+/\1$next_id/g" >> "$base/brain/mutated_urls.txt"
            fi
            
        done < <(head -100 "$base/brain/numeric_id_urls.txt")
        
        sort -u "$base/brain/mutated_urls.txt" -o "$base/brain/mutated_urls.txt"
        
        local mutation_count=$(wc -l < "$base/brain/mutated_urls.txt" 2>/dev/null || echo 0)
        log_found "IDOR mutation URLs: $mutation_count"
    fi
    
    # ─────────────────────────────────────────────────────────────────────────
    # 5. CONFIDENCE SCORING (Enhanced)
    # ─────────────────────────────────────────────────────────────────────────
    log_info "📊 Calculating confidence scores..."
    
    : > "$base/brain/scored.txt"
    
    while IFS= read -r url; do
        local score=0
        local reasons=""
        
        # Has parameters? +2
        if echo "$url" | grep -q "?"; then
            score=$((score + 2))
            reasons="${reasons}params,"
        fi
        
        # Auth-related? +3
        if echo "$url" | grep -qEi "auth|login|user|account|session|token|oauth"; then
            score=$((score + 3))
            reasons="${reasons}auth,"
        fi
        
        # Admin/internal? +4
        if echo "$url" | grep -qEi "admin|internal|private|debug|config"; then
            score=$((score + 4))
            reasons="${reasons}admin,"
        fi
        
        # API endpoint? +2
        if echo "$url" | grep -qEi "/api/|/v[0-9]+/|graphql|rest"; then
            score=$((score + 2))
            reasons="${reasons}api,"
        fi
        
        # CRUD operation? +2
        if echo "$url" | grep -qEi "create|update|delete|edit|remove|add"; then
            score=$((score + 2))
            reasons="${reasons}crud,"
        fi
        
        # File operations? +3
        if echo "$url" | grep -qEi "upload|download|export|import|file|doc"; then
            score=$((score + 3))
            reasons="${reasons}file,"
        fi
        
        # ID parameter? +2
        if echo "$url" | grep -qE "[?&]id="; then
            score=$((score + 2))
            reasons="${reasons}idor,"
        fi
        
        # Redirect parameter? +2
        if echo "$url" | grep -qEi "[?&](redirect|url|next|return|callback)="; then
            score=$((score + 2))
            reasons="${reasons}redirect,"
        fi
        
        # In auth_diff? +5
        if grep -qF "$url" "$base/brain/auth_diff.txt" 2>/dev/null; then
            score=$((score + 5))
            reasons="${reasons}auth-diff,"
        fi
        
        echo "$score|$url|$reasons" >> "$base/brain/scored.txt"
        
    done < "$base/brain/high_value.txt"
    
    # Sort by score (highest first)
    sort -t'|' -k1 -rn "$base/brain/scored.txt" -o "$base/brain/scored.txt"
    
    # Create readable format
    awk -F'|' '{printf "%3d  %s  [%s]\n", $1, $2, $3}' "$base/brain/scored.txt" > "$base/brain/priority_list.txt"
    
    log_success "Scored $(wc -l < "$base/brain/scored.txt") endpoints"
    
    # ─────────────────────────────────────────────────────────────────────────
    # 6. GENERATE BRAIN REPORT
    # ─────────────────────────────────────────────────────────────────────────
    log_info "📋 Generating brain report..."
    
    cat > "$base/brain/BRAIN_REPORT.txt" << EOF
═══════════════════════════════════════════════════════════════════════════════
                    🧠 SHADOW BRAIN ANALYSIS
                    Target: $target
                    Generated: $(date)
═══════════════════════════════════════════════════════════════════════════════

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📊 PRUNING SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Original URLs:    $original_count
After pruning:    $pruned_count
Removed:          $removed ($percentage% garbage eliminated)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🎯 TOP 20 PRIORITY TARGETS (Start Here!)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

$(head -20 "$base/brain/priority_list.txt" 2>/dev/null || echo "No targets scored")

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🚨 AUTH-DEPENDENT ENDPOINTS (Logic Bugs!)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

$(cat "$base/brain/auth_diff.txt" 2>/dev/null || echo "No auth differences detected")

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔄 IDOR MUTATION TARGETS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Original URLs with numeric IDs:
$(head -10 "$base/brain/numeric_id_urls.txt" 2>/dev/null || echo "None found")

Mutated for IDOR testing:
$(head -10 "$base/brain/mutated_urls.txt" 2>/dev/null || echo "None generated")

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📁 HIGH-VALUE PATTERNS DETECTED
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

API endpoints:     $(grep -c "/api/" "$base/brain/high_value.txt" 2>/dev/null || echo 0)
Admin paths:       $(grep -ci "admin" "$base/brain/high_value.txt" 2>/dev/null || echo 0)
User endpoints:    $(grep -ci "user" "$base/brain/high_value.txt" 2>/dev/null || echo 0)
Export/Download:   $(grep -Eci "export|download" "$base/brain/high_value.txt" 2>/dev/null || echo 0)
Callbacks:         $(grep -ci "callback" "$base/brain/high_value.txt" 2>/dev/null || echo 0)

═══════════════════════════════════════════════════════════════════════════════
                    🎯 YOUR MISSION
═══════════════════════════════════════════════════════════════════════════════

1. Pick ONE endpoint from "Top 20 Priority Targets"
2. Open Burp Suite
3. Test manually in Repeater
4. Focus on:
   - IDOR (change IDs)
   - Auth bypass (remove cookies)
   - Logic flaws (change values)

Remember: Quality > Quantity
One good bug beats 1000 scanned URLs.

EOF
    
    # ─────────────────────────────────────────────────────────────────────────
    # 7. AUTO-STOP (Force human decision)
    # ─────────────────────────────────────────────────────────────────────────
    if [[ "${ENABLE_AUTO_STOP:-false}" == "true" ]]; then
        separator
        log_warn "═══════════════════════════════════════════════════════════════"
        log_warn "  🛑 AUTO-STOP: Decision Required"
        log_warn "═══════════════════════════════════════════════════════════════"
        echo ""
        echo "Top 10 targets discovered:"
        echo ""
        
        # Show numbered list
        head -10 "$base/brain/priority_list.txt" | nl
        
        echo ""
        log_warn "You MUST pick at least one endpoint to analyze manually."
        echo ""
        
        read -p "Enter target number (1-10) or 'skip' to continue: " choice
        
        if [[ "$choice" =~ ^[0-9]+$ ]] && [[ $choice -ge 1 ]] && [[ $choice -le 10 ]]; then
            local chosen=$(head -$choice "$base/brain/priority_list.txt" | tail -1)
            echo "$chosen" >> "$base/brain/manual_targets.txt"
            log_success "Saved for manual testing: $chosen"
        elif [[ "$choice" != "skip" ]]; then
            log_warn "Invalid choice. Continuing anyway..."
        fi
    fi
    
    # ─────────────────────────────────────────────────────────────────────────
    # CLEANUP
    # ─────────────────────────────────────────────────────────────────────────
    cleanup_temp_files "$base"
    
    separator
    log_success "Brain analysis complete!"
    log_info "Priority report: $base/brain/BRAIN_REPORT.txt"
    
    show_stats "Candidates after pruning" "$base/brain/candidates.txt"
    show_stats "High-value endpoints" "$base/brain/high_value.txt"
    show_stats "Auth-diff endpoints" "$base/brain/auth_diff.txt"
    show_stats "IDOR mutations" "$base/brain/mutated_urls.txt"
    
    return 0
}

# ─────────────────────────────────────────────────────────────────────────────
# CLEANUP FUNCTION
# ─────────────────────────────────────────────────────────────────────────────
cleanup_temp_files() {
    local base="$1"
    
    if [[ "${ENABLE_CLEANUP:-true}" == "true" ]]; then
        log_info "🧹 Cleaning up temporary files..."
        
        # Remove intermediate files we don't need
        rm -f "$base/brain/no_static.txt" 2>/dev/null
        rm -f "$base/brain/with_params.txt" 2>/dev/null
        rm -f "$base/brain/dead_urls.txt" 2>/dev/null
        rm -f "$base/brain/diff_sample.txt" 2>/dev/null
        rm -f "$base/brain/no_auth_response.txt" 2>/dev/null
        rm -f "$base/brain/with_auth_response.txt" 2>/dev/null
        
        # Remove empty files
        find "$base" -type f -empty -delete 2>/dev/null
        
        log_success "Cleanup complete"
    fi
}
