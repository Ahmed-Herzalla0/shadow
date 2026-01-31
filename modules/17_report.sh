#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# SHADOW v5 - Module 17: Obsidian Report Generator
# ═══════════════════════════════════════════════════════════════════════════════
# Generates beautiful Markdown reports for Obsidian
# Auto-saves to Obsidian vault for easy reference
# ═══════════════════════════════════════════════════════════════════════════════

MODULE="17_REPORT"

# Obsidian vault path
OBSIDIAN_VAULT="${OBSIDIAN_VAULT_PATH:-/home/ahmad/Documents/Obsidian Vault/reports}"

run() {
    local target="$1"
    local base="$2"
    
    banner "📝 OBSIDIAN REPORT GENERATOR → $target"
    
    # Ensure Obsidian directory exists
    mkdir -p "$OBSIDIAN_VAULT"
    
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local report_file="$OBSIDIAN_VAULT/${target}_${timestamp}.md"
    local summary_file="$OBSIDIAN_VAULT/${target}_latest.md"
    
    log_info "Generating Obsidian report..."
    
    # ─────────────────────────────────────────────────────────────────────────
    # COLLECT ALL FINDINGS
    # ─────────────────────────────────────────────────────────────────────────
    
    # Critical findings
    local critical_count=0
    local high_count=0
    local medium_count=0
    local low_count=0
    local info_count=0
    
    # Arrays to store findings
    declare -a critical_findings=()
    declare -a high_findings=()
    declare -a medium_findings=()
    declare -a low_findings=()
    declare -a info_findings=()
    
    # ─────────────────────────────────────────────────────────────────────────
    # PARSE NUCLEI RESULTS
    # ─────────────────────────────────────────────────────────────────────────
    local nuclei_file=""
    if [[ -f "$base/vulns/nuclei_all.txt" ]]; then
        nuclei_file="$base/vulns/nuclei_all.txt"
    elif [[ -f "$base/vulns/nuclei_critical.txt" ]]; then
        nuclei_file="$base/vulns/nuclei_critical.txt"
    elif [[ -f "$base/vulns/nuclei.txt" ]]; then
        nuclei_file="$base/vulns/nuclei.txt"
    fi

    if [[ -n "$nuclei_file" ]]; then
        while IFS= read -r line; do
            if echo "$line" | grep -qi "critical"; then
                critical_findings+=("$line")
                ((critical_count++))
            elif echo "$line" | grep -qi "high"; then
                high_findings+=("$line")
                ((high_count++))
            elif echo "$line" | grep -qi "medium"; then
                medium_findings+=("$line")
                ((medium_count++))
            elif echo "$line" | grep -qi "low"; then
                low_findings+=("$line")
                ((low_count++))
            else
                info_findings+=("$line")
                ((info_count++))
            fi
        done < "$nuclei_file"
    fi
    
    # ─────────────────────────────────────────────────────────────────────────
    # PARSE ASSUMPTION BREAKER RESULTS
    # ─────────────────────────────────────────────────────────────────────────
    if [[ -f "$base/assume/header_bypass.txt" ]]; then
        while IFS= read -r line; do
            if echo "$line" | grep -q "🚨"; then
                high_findings+=("[Header Bypass] $line")
                ((high_count++))
            fi
        done < "$base/assume/header_bypass.txt"
    fi
    
    if [[ -f "$base/assume/method_confusion.txt" ]]; then
        while IFS= read -r line; do
            if echo "$line" | grep -q "🚨"; then
                high_findings+=("[Method Confusion] $line")
                ((high_count++))
            fi
        done < "$base/assume/method_confusion.txt"
    fi
    
    if [[ -f "$base/assume/path_traversal.txt" ]]; then
        while IFS= read -r line; do
            if echo "$line" | grep -q "🚨"; then
                critical_findings+=("[LFI] $line")
                ((critical_count++))
            fi
        done < "$base/assume/path_traversal.txt"
    fi
    
    if [[ -f "$base/assume/negative_test.txt" ]]; then
        while IFS= read -r line; do
            if echo "$line" | grep -q "🚨"; then
                medium_findings+=("[Negative Test] $line")
                ((medium_count++))
            fi
        done < "$base/assume/negative_test.txt"
    fi
    
    # ─────────────────────────────────────────────────────────────────────────
    # PARSE LOGIC RESULTS
    # ─────────────────────────────────────────────────────────────────────────
    if [[ -f "$base/logic/cross_user.txt" ]]; then
        while IFS= read -r line; do
            if echo "$line" | grep -q "🚨"; then
                critical_findings+=("[IDOR] $line")
                ((critical_count++))
            fi
        done < "$base/logic/cross_user.txt"
    fi
    
    if [[ -f "$base/logic/param_pollution.txt" ]]; then
        while IFS= read -r line; do
            if echo "$line" | grep -q "🚨"; then
                high_findings+=("[HPP] $line")
                ((high_count++))
            fi
        done < "$base/logic/param_pollution.txt"
    fi
    
    # ─────────────────────────────────────────────────────────────────────────
    # PARSE BRAIN/INTEL RESULTS
    # ─────────────────────────────────────────────────────────────────────────
    if [[ -f "$base/brain/auth_diff.txt" ]]; then
        while IFS= read -r line; do
            if [[ -n "$line" ]]; then
                high_findings+=("[Auth Diff] $line")
                ((high_count++))
            fi
        done < "$base/brain/auth_diff.txt"
    fi
    
    if [[ -f "$base/intel/http_500_errors.txt" ]]; then
        local error_count=$(wc -l < "$base/intel/http_500_errors.txt" 2>/dev/null || echo 0)
        if [[ $error_count -gt 0 ]]; then
            medium_findings+=("[Server Errors] $error_count endpoints returning 500")
            ((medium_count++))
        fi
    fi
    
    # ─────────────────────────────────────────────────────────────────────────
    # PARSE JS SECRETS
    # ─────────────────────────────────────────────────────────────────────────
    if [[ -f "$base/js/aws_keys.txt" ]] && [[ -s "$base/js/aws_keys.txt" ]]; then
        while IFS= read -r key; do
            critical_findings+=("[AWS Key Exposed] $key")
            ((critical_count++))
        done < "$base/js/aws_keys.txt"
    fi
    
    if [[ -f "$base/js/api_keys.txt" ]] && [[ -s "$base/js/api_keys.txt" ]]; then
        while IFS= read -r key; do
            high_findings+=("[API Key Exposed] $key")
            ((high_count++))
        done < <(head -10 "$base/js/api_keys.txt")
    fi
    
    if [[ -f "$base/js/jwt_tokens.txt" ]] && [[ -s "$base/js/jwt_tokens.txt" ]]; then
        while IFS= read -r token; do
            high_findings+=("[JWT Token Exposed] ${token:0:50}...")
            ((high_count++))
        done < <(head -5 "$base/js/jwt_tokens.txt")
    fi
    
    # ─────────────────────────────────────────────────────────────────────────
    # GENERATE MARKDOWN REPORT
    # ─────────────────────────────────────────────────────────────────────────
    
    cat > "$report_file" << EOF
---
tags: [security, recon, bug-bounty, ${target}]
date: $(date +%Y-%m-%d)
target: ${target}
status: review
severity: $(if [[ $critical_count -gt 0 ]]; then echo "critical"; elif [[ $high_count -gt 0 ]]; then echo "high"; elif [[ $medium_count -gt 0 ]]; then echo "medium"; else echo "low"; fi)
---

# 🎯 Security Report: ${target}

> **Scan Date:** $(date "+%Y-%m-%d %H:%M:%S")
> **Scanner:** SHADOW v5
> **Status:** Pending Review

---

## 📊 Executive Summary

| Severity | Count | Status |
|----------|-------|--------|
| 🔴 **Critical** | ${critical_count} | $(if [[ $critical_count -gt 0 ]]; then echo "⚠️ ACTION REQUIRED"; else echo "✅ Clear"; fi) |
| 🟠 **High** | ${high_count} | $(if [[ $high_count -gt 0 ]]; then echo "⚠️ Review Needed"; else echo "✅ Clear"; fi) |
| 🟡 **Medium** | ${medium_count} | $(if [[ $medium_count -gt 0 ]]; then echo "📝 Note"; else echo "✅ Clear"; fi) |
| 🟢 **Low** | ${low_count} | $(if [[ $low_count -gt 0 ]]; then echo "📝 Note"; else echo "✅ Clear"; fi) |
| ⚪ **Info** | ${info_count} | 📋 Reference |

**Total Findings:** $((critical_count + high_count + medium_count + low_count + info_count))

---

## 🔴 Critical Findings

EOF

    if [[ ${#critical_findings[@]} -gt 0 ]]; then
        for finding in "${critical_findings[@]}"; do
            # Parse finding
            local clean_finding=$(echo "$finding" | sed 's/🚨//g' | tr -d '\n')
            cat >> "$report_file" << EOF
### 🚨 Critical: ${clean_finding:0:80}

\`\`\`
$finding
\`\`\`

**Severity:** Critical 🔴
**Status:** [ ] Not Started
**Priority:** Immediate

---

EOF
        done
    else
        echo "> ✅ No critical findings" >> "$report_file"
        echo "" >> "$report_file"
    fi

    cat >> "$report_file" << EOF

## 🟠 High Findings

EOF

    if [[ ${#high_findings[@]} -gt 0 ]]; then
        for finding in "${high_findings[@]}"; do
            local clean_finding=$(echo "$finding" | sed 's/🚨//g' | tr -d '\n')
            cat >> "$report_file" << EOF
### ⚠️ High: ${clean_finding:0:80}

\`\`\`
$finding
\`\`\`

**Severity:** High 🟠
**Status:** [ ] Not Started

---

EOF
        done
    else
        echo "> ✅ No high findings" >> "$report_file"
        echo "" >> "$report_file"
    fi

    cat >> "$report_file" << EOF

## 🟡 Medium Findings

EOF

    if [[ ${#medium_findings[@]} -gt 0 ]]; then
        for finding in "${medium_findings[@]}"; do
            echo "- $finding" >> "$report_file"
        done
    else
        echo "> ✅ No medium findings" >> "$report_file"
    fi

    cat >> "$report_file" << EOF

---

## 🟢 Low & Informational

EOF

    if [[ ${#low_findings[@]} -gt 0 ]] || [[ ${#info_findings[@]} -gt 0 ]]; then
        for finding in "${low_findings[@]}"; do
            echo "- 🟢 $finding" >> "$report_file"
        done
        for finding in "${info_findings[@]}"; do
            echo "- ⚪ $finding" >> "$report_file"
        done
    else
        echo "> ✅ No low/info findings" >> "$report_file"
    fi

    # ─────────────────────────────────────────────────────────────────────────
    # ADD RECON SUMMARY
    # ─────────────────────────────────────────────────────────────────────────
    
    cat >> "$report_file" << EOF

---

## 📡 Reconnaissance Summary

### Subdomains
- **Total Found:** $(wc -l < "$base/subs/all_subs.txt" 2>/dev/null || echo "0")
- **Live (DNS):** $(wc -l < "$base/dns/alive.txt" 2>/dev/null || echo "0")
- **HTTP Alive:** $(wc -l < "$base/http/alive.txt" 2>/dev/null || echo "0")

### URLs & Parameters
- **Total URLs:** $(wc -l < "$base/params/all_urls.txt" 2>/dev/null || echo "0")
- **URLs with Params:** $(wc -l < "$base/params/urls_with_params.txt" 2>/dev/null || echo "0")
- **Unique Parameters:** $(wc -l < "$base/params/param_names.txt" 2>/dev/null || echo "0")

### JavaScript Analysis
- **JS Files Found:** $(wc -l < "$base/js/js_urls.txt" 2>/dev/null || echo "0")
- **Endpoints in JS:** $(wc -l < "$base/js/api_endpoints.txt" 2>/dev/null || echo "0")

---

## 🎯 Priority Targets

EOF

    # Add top scored targets
    if [[ -f "$base/brain/priority_list.txt" ]]; then
        echo "### Top 10 High-Value Endpoints" >> "$report_file"
        echo "" >> "$report_file"
        echo "| Score | URL | Tags |" >> "$report_file"
        echo "|-------|-----|------|" >> "$report_file"
        head -10 "$base/brain/priority_list.txt" 2>/dev/null | while IFS= read -r line; do
            local score=$(echo "$line" | awk '{print $1}')
            local url=$(echo "$line" | awk '{print $2}')
            local tags=$(echo "$line" | grep -oE '\[.*\]' || echo "")
            echo "| $score | \`$url\` | $tags |" >> "$report_file"
        done
        echo "" >> "$report_file"
    fi

    # ─────────────────────────────────────────────────────────────────────────
    # ADD AUTH SURFACE
    # ─────────────────────────────────────────────────────────────────────────
    
    cat >> "$report_file" << EOF

---

## 🔐 Authentication Surface

EOF

    if [[ -f "$base/intel/auth_endpoints.txt" ]]; then
        echo "### Auth Endpoints Found: $(wc -l < "$base/intel/auth_endpoints.txt")" >> "$report_file"
        echo "" >> "$report_file"
        echo "\`\`\`" >> "$report_file"
        head -20 "$base/intel/auth_endpoints.txt" >> "$report_file"
        echo "\`\`\`" >> "$report_file"
    fi

    # ─────────────────────────────────────────────────────────────────────────
    # ADD INTERESTING FINDINGS
    # ─────────────────────────────────────────────────────────────────────────
    
    cat >> "$report_file" << EOF

---

## 🔍 Interesting Findings

### IDOR Candidates
EOF

    if [[ -f "$base/intel/params_idor.txt" ]] && [[ -s "$base/intel/params_idor.txt" ]]; then
        echo "Parameters that suggest IDOR:" >> "$report_file"
        echo "\`\`\`" >> "$report_file"
        cat "$base/intel/params_idor.txt" >> "$report_file"
        echo "\`\`\`" >> "$report_file"
    else
        echo "> No IDOR candidates found" >> "$report_file"
    fi

    cat >> "$report_file" << EOF

### Open Redirect Candidates
EOF

    if [[ -f "$base/intel/params_redirect.txt" ]] && [[ -s "$base/intel/params_redirect.txt" ]]; then
        echo "\`\`\`" >> "$report_file"
        cat "$base/intel/params_redirect.txt" >> "$report_file"
        echo "\`\`\`" >> "$report_file"
    else
        echo "> No redirect candidates found" >> "$report_file"
    fi

    cat >> "$report_file" << EOF

### 403 Bypass Candidates
EOF

    if [[ -f "$base/http/403_targets.txt" ]] && [[ -s "$base/http/403_targets.txt" ]]; then
        echo "\`\`\`" >> "$report_file"
        head -10 "$base/http/403_targets.txt" >> "$report_file"
        echo "\`\`\`" >> "$report_file"
    else
        echo "> No 403 targets found" >> "$report_file"
    fi

    # ─────────────────────────────────────────────────────────────────────────
    # ADD TODO CHECKLIST
    # ─────────────────────────────────────────────────────────────────────────
    
    cat >> "$report_file" << EOF

---

## ✅ Testing Checklist

### Manual Testing Required
- [ ] Review all critical findings
- [ ] Test IDOR on user-specific endpoints
- [ ] Check for privilege escalation
- [ ] Test authentication bypass
- [ ] Validate all automated findings

### Burp Suite Tasks
- [ ] Import high-value URLs to scope
- [ ] Run active scan on auth endpoints
- [ ] Test business logic manually
- [ ] Check for race conditions

### Report Writing
- [ ] Document confirmed vulnerabilities
- [ ] Create PoC for each finding
- [ ] Calculate CVSS scores
- [ ] Write remediation steps

---

## 📁 Scan Files Location

\`\`\`
$base/
├── vulns/          # Vulnerability scan results
├── brain/          # Intelligent analysis
├── assume/         # Assumption breaker results
├── logic/          # Business logic tests
├── intel/          # Intelligence analysis
├── http/           # HTTP probing results
├── params/         # URLs and parameters
└── js/             # JavaScript analysis
\`\`\`

---

## 📝 Notes

> Add your manual testing notes here...

---

*Generated by SHADOW v5 - $(date)*
*Report: ${report_file}*
EOF

    # ─────────────────────────────────────────────────────────────────────────
    # CREATE LATEST SYMLINK/COPY
    # ─────────────────────────────────────────────────────────────────────────
    cp "$report_file" "$summary_file"
    
    # Also save in scan directory
    cp "$report_file" "$base/OBSIDIAN_REPORT.md"
    
    separator
    log_success "Obsidian report generated!"
    echo ""
    echo -e "${GREEN}📄 Report saved to:${NC}"
    echo -e "   ${WHITE}$report_file${NC}"
    echo -e "   ${WHITE}$summary_file${NC} (latest)"
    echo ""
    
    # Summary
    separator
    echo -e "${CYAN}📊 FINDINGS SUMMARY${NC}"
    separator
    echo -e "   🔴 Critical: ${RED}${critical_count}${NC}"
    echo -e "   🟠 High:     ${YELLOW}${high_count}${NC}"
    echo -e "   🟡 Medium:   ${YELLOW}${medium_count}${NC}"
    echo -e "   🟢 Low:      ${GREEN}${low_count}${NC}"
    echo -e "   ⚪ Info:     ${WHITE}${info_count}${NC}"
    separator
    
    # Open in Obsidian hint
    log_info "Open Obsidian and navigate to: reports/${target}_${timestamp}.md"
    
    return 0
}
