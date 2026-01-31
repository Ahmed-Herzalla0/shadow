#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# SHADOW v5 - Module 12: Change Detection (Delta Analysis)
# ═══════════════════════════════════════════════════════════════════════════════
# Compares current scan with previous scans to detect changes
# New deployments = New vulnerabilities
# ═══════════════════════════════════════════════════════════════════════════════

MODULE="12_DELTA"

run() {
    local target="$1"
    local base="$2"
    
    banner "📊 CHANGE DETECTION → $target"
    
    mkdir -p "$base/delta"
    
    # Storage for historical data
    local history_path="${DELTA_STORAGE_PATH:-$HOME/.shadow/history}"
    local target_history="$history_path/$target"
    
    mkdir -p "$target_history"
    
    # Current timestamp
    local timestamp=$(date +%Y%m%d_%H%M%S)
    
    # ─────────────────────────────────────────────────────────────────────────
    # 1. STORE CURRENT STATE
    # ─────────────────────────────────────────────────────────────────────────
    log_info "Storing current scan state..."
    
    mkdir -p "$target_history/$timestamp"
    
    # Copy important files for history
    [[ -f "$base/dns/alive.txt" ]] && cp "$base/dns/alive.txt" "$target_history/$timestamp/subs.txt"
    [[ -f "$base/http/alive.txt" ]] && cp "$base/http/alive.txt" "$target_history/$timestamp/http.txt"
    [[ -f "$base/params/all_urls.txt" ]] && cp "$base/params/all_urls.txt" "$target_history/$timestamp/urls.txt"
    [[ -f "$base/http/httpx.json" ]] && cp "$base/http/httpx.json" "$target_history/$timestamp/httpx.json"
    [[ -f "$base/http/tech_summary.txt" ]] && cp "$base/http/tech_summary.txt" "$target_history/$timestamp/tech.txt"
    
    # Save timestamp marker
    echo "$timestamp" > "$target_history/latest"
    
    log_success "Saved snapshot: $timestamp"
    
    # ─────────────────────────────────────────────────────────────────────────
    # 2. FIND PREVIOUS SCAN
    # ─────────────────────────────────────────────────────────────────────────
    local previous_scan=""
    local scans=($(ls -1d "$target_history"/[0-9]* 2>/dev/null | sort -r | head -10))
    
    if [[ ${#scans[@]} -lt 2 ]]; then
        log_warn "No previous scan found for comparison"
        log_info "This is the baseline scan. Run again later to see changes."
        
        # Create initial report
        cat > "$base/delta/DELTA_REPORT.txt" << EOF
═══════════════════════════════════════════════════════════════════════════════
                    SHADOW DELTA REPORT
                    Target: $target
                    Scan: $timestamp
═══════════════════════════════════════════════════════════════════════════════

⚠️  BASELINE SCAN - No previous data to compare

This is the first scan for this target.
Run another scan later to see:
- New subdomains
- New endpoints
- Technology changes
- Status code changes

Current Stats:
- Subdomains: $(wc -l < "$base/dns/alive.txt" 2>/dev/null || echo 0)
- HTTP alive: $(wc -l < "$base/http/alive.txt" 2>/dev/null || echo 0)
- URLs: $(wc -l < "$base/params/all_urls.txt" 2>/dev/null || echo 0)

Next scan will compare against this baseline.
EOF
        return 0
    fi
    
    # Get the previous scan (second newest)
    previous_scan="${scans[1]}"
    local prev_timestamp=$(basename "$previous_scan")
    
    log_info "Comparing with previous scan: $prev_timestamp"
    
    # ─────────────────────────────────────────────────────────────────────────
    # 3. SUBDOMAIN DIFF
    # ─────────────────────────────────────────────────────────────────────────
    log_info "Analyzing subdomain changes..."
    
    if [[ -f "$previous_scan/subs.txt" && -f "$target_history/$timestamp/subs.txt" ]]; then
        # New subdomains
        comm -13 <(sort "$previous_scan/subs.txt") <(sort "$target_history/$timestamp/subs.txt") > "$base/delta/new_subs.txt"
        
        # Removed subdomains
        comm -23 <(sort "$previous_scan/subs.txt") <(sort "$target_history/$timestamp/subs.txt") > "$base/delta/removed_subs.txt"
        
        local new_subs=$(wc -l < "$base/delta/new_subs.txt" 2>/dev/null || echo 0)
        local removed_subs=$(wc -l < "$base/delta/removed_subs.txt" 2>/dev/null || echo 0)
        
        if [[ $new_subs -gt 0 ]]; then
            log_found "🆕 NEW subdomains: $new_subs"
        fi
        if [[ $removed_subs -gt 0 ]]; then
            log_warn "❌ Removed subdomains: $removed_subs"
        fi
    fi
    
    # ─────────────────────────────────────────────────────────────────────────
    # 4. HTTP ENDPOINT DIFF
    # ─────────────────────────────────────────────────────────────────────────
    log_info "Analyzing HTTP endpoint changes..."
    
    if [[ -f "$previous_scan/http.txt" && -f "$target_history/$timestamp/http.txt" ]]; then
        # New HTTP endpoints
        comm -13 <(sort "$previous_scan/http.txt") <(sort "$target_history/$timestamp/http.txt") > "$base/delta/new_http.txt"
        
        # Down endpoints
        comm -23 <(sort "$previous_scan/http.txt") <(sort "$target_history/$timestamp/http.txt") > "$base/delta/down_http.txt"
        
        local new_http=$(wc -l < "$base/delta/new_http.txt" 2>/dev/null || echo 0)
        local down_http=$(wc -l < "$base/delta/down_http.txt" 2>/dev/null || echo 0)
        
        if [[ $new_http -gt 0 ]]; then
            log_found "🆕 NEW HTTP endpoints: $new_http"
        fi
        if [[ $down_http -gt 0 ]]; then
            log_warn "⬇️ Down HTTP endpoints: $down_http"
        fi
    fi
    
    # ─────────────────────────────────────────────────────────────────────────
    # 5. URL DIFF
    # ─────────────────────────────────────────────────────────────────────────
    log_info "Analyzing URL changes..."
    
    if [[ -f "$previous_scan/urls.txt" && -f "$target_history/$timestamp/urls.txt" ]]; then
        # New URLs
        comm -13 <(sort "$previous_scan/urls.txt") <(sort "$target_history/$timestamp/urls.txt") > "$base/delta/new_urls.txt"
        
        local new_urls=$(wc -l < "$base/delta/new_urls.txt" 2>/dev/null || echo 0)
        
        if [[ $new_urls -gt 0 ]]; then
            log_found "🆕 NEW URLs discovered: $new_urls"
        fi
    fi
    
    # ─────────────────────────────────────────────────────────────────────────
    # 6. TECHNOLOGY DIFF
    # ─────────────────────────────────────────────────────────────────────────
    log_info "Analyzing technology changes..."
    
    if [[ -f "$previous_scan/tech.txt" && -f "$target_history/$timestamp/tech.txt" ]]; then
        diff "$previous_scan/tech.txt" "$target_history/$timestamp/tech.txt" > "$base/delta/tech_diff.txt" 2>/dev/null
        
        if [[ -s "$base/delta/tech_diff.txt" ]]; then
            log_found "⚙️ Technology stack changed!"
        fi
    fi
    
    # ─────────────────────────────────────────────────────────────────────────
    # 7. STATUS CODE CHANGES
    # ─────────────────────────────────────────────────────────────────────────
    log_info "Analyzing status code changes..."
    
    if [[ -f "$previous_scan/httpx.json" && -f "$target_history/$timestamp/httpx.json" ]]; then
        # Extract URL:status pairs
        jq -r '"\(.url):\(.status_code)"' "$previous_scan/httpx.json" 2>/dev/null | sort > /tmp/prev_status.txt
        jq -r '"\(.url):\(.status_code)"' "$target_history/$timestamp/httpx.json" 2>/dev/null | sort > /tmp/curr_status.txt
        
        # Find status code changes
        : > "$base/delta/status_changes.txt"
        
        while IFS=: read -r url curr_status; do
            local prev_status=$(grep "^$url:" /tmp/prev_status.txt 2>/dev/null | cut -d: -f2)
            
            if [[ -n "$prev_status" && "$prev_status" != "$curr_status" ]]; then
                echo "$url: $prev_status → $curr_status" >> "$base/delta/status_changes.txt"
                
                # Highlight interesting changes
                if [[ "$prev_status" == "403" && "$curr_status" == "200" ]]; then
                    echo "$url" >> "$base/delta/was_403_now_200.txt"
                fi
                if [[ "$curr_status" == "500" ]]; then
                    echo "$url" >> "$base/delta/new_500_errors.txt"
                fi
            fi
        done < /tmp/curr_status.txt
        
        local status_changes=$(wc -l < "$base/delta/status_changes.txt" 2>/dev/null || echo 0)
        if [[ $status_changes -gt 0 ]]; then
            log_found "🔄 Status code changes: $status_changes"
        fi
        
        rm -f /tmp/prev_status.txt /tmp/curr_status.txt
    fi
    
    # ─────────────────────────────────────────────────────────────────────────
    # 8. GENERATE DELTA REPORT
    # ─────────────────────────────────────────────────────────────────────────
    log_info "Generating delta report..."
    
    cat > "$base/delta/DELTA_REPORT.txt" << EOF
═══════════════════════════════════════════════════════════════════════════════
                    SHADOW DELTA REPORT
                    Target: $target
═══════════════════════════════════════════════════════════════════════════════

Previous Scan: $prev_timestamp
Current Scan:  $timestamp
Time Elapsed:  $(calculate_time_diff "$prev_timestamp" "$timestamp")

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🆕 NEW DISCOVERIES (PRIORITY!)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

New Subdomains ($(wc -l < "$base/delta/new_subs.txt" 2>/dev/null || echo 0)):
$(head -20 "$base/delta/new_subs.txt" 2>/dev/null || echo "None")

New HTTP Endpoints ($(wc -l < "$base/delta/new_http.txt" 2>/dev/null || echo 0)):
$(head -20 "$base/delta/new_http.txt" 2>/dev/null || echo "None")

New URLs ($(wc -l < "$base/delta/new_urls.txt" 2>/dev/null || echo 0)):
$(head -20 "$base/delta/new_urls.txt" 2>/dev/null || echo "None")

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔄 STATUS CODE CHANGES (Check These!)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

$(cat "$base/delta/status_changes.txt" 2>/dev/null | head -20 || echo "No changes")

🎯 Was 403, Now 200 (Potential new access!):
$(cat "$base/delta/was_403_now_200.txt" 2>/dev/null || echo "None")

⚠️ New 500 Errors (Potential vulnerabilities!):
$(cat "$base/delta/new_500_errors.txt" 2>/dev/null || echo "None")

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
⚙️ TECHNOLOGY CHANGES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

$(cat "$base/delta/tech_diff.txt" 2>/dev/null || echo "No changes detected")

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
⬇️ REMOVED/DOWN
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Removed Subdomains ($(wc -l < "$base/delta/removed_subs.txt" 2>/dev/null || echo 0)):
$(head -10 "$base/delta/removed_subs.txt" 2>/dev/null || echo "None")

Down HTTP Endpoints ($(wc -l < "$base/delta/down_http.txt" 2>/dev/null || echo 0)):
$(head -10 "$base/delta/down_http.txt" 2>/dev/null || echo "None")

═══════════════════════════════════════════════════════════════════════════════
                    WHY CHANGES MATTER
═══════════════════════════════════════════════════════════════════════════════

🔥 New deployments = New vulnerabilities
🔥 Status changes = Configuration changes = Potential misconfigurations
🔥 New endpoints = Untested code = Higher bug probability
🔥 403 → 200 = Something was exposed that shouldn't be

FOCUS ON:
1. New subdomains first (fresh attack surface)
2. Status code changes (especially 403→200, new 500s)
3. New URLs with parameters

EOF
    
    separator
    log_success "Delta analysis complete!"
    log_info "Report: $base/delta/DELTA_REPORT.txt"
    
    # Summary
    show_stats "New subdomains" "$base/delta/new_subs.txt"
    show_stats "New HTTP endpoints" "$base/delta/new_http.txt"
    show_stats "New URLs" "$base/delta/new_urls.txt"
    show_stats "Status changes" "$base/delta/status_changes.txt"
    
    return 0
}

# Helper function to calculate time difference
calculate_time_diff() {
    local prev="$1"
    local curr="$2"
    
    # Simple date diff (approximate)
    local prev_date="${prev:0:8}"
    local curr_date="${curr:0:8}"
    
    if [[ "$prev_date" == "$curr_date" ]]; then
        echo "Same day"
    else
        echo "Different days ($prev_date → $curr_date)"
    fi
}
