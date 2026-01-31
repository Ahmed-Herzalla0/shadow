#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# SHADOW v5 - Module 01: Intelligence Gathering
# ═══════════════════════════════════════════════════════════════════════════════
# Gathers ASN, CIDR, IP ranges, and organizational information
# ═══════════════════════════════════════════════════════════════════════════════

MODULE="01_INTEL"

run() {
    local target="$1"
    local base="$2"
    
    banner "🔍 INTEL GATHERING → $target"
    
    mkdir -p "$base/intel"
    
    # ─────────────────────────────────────────────────────────────────────────
    # ASN & Organization Discovery
    # ─────────────────────────────────────────────────────────────────────────
    log_info "Gathering ASN information..."
    
    local amass_pid=""
    local meta_pid=""
    
    if require_tool "amass"; then
        log_info "Running Amass Intel..."
        if [[ "${VERBOSE:-0}" == "1" ]]; then
            timeout 300 amass intel -d "$target" -whois -o "$base/intel/amass_intel.txt" &
        else
            timeout 300 amass intel -d "$target" -whois -o "$base/intel/amass_intel.txt" 2>/dev/null &
        fi
        amass_pid=$!
    fi
    
    if require_tool "metabigor"; then
        log_info "Running Metabigor for org..."
        if [[ "${VERBOSE:-0}" == "1" ]]; then
            metabigor net --org "$target" 2>&1 | tee "$base/intel/org_ranges.txt" &
        else
            metabigor net --org "$target" 2>/dev/null > "$base/intel/org_ranges.txt" &
        fi
        meta_pid=$!
    fi
    
    # Wait for background jobs
    [[ -n "$amass_pid" ]] && wait $amass_pid 2>/dev/null
    [[ -n "$meta_pid" ]] && wait $meta_pid 2>/dev/null
    
    # ─────────────────────────────────────────────────────────────────────────
    # ASN Mapping
    # ─────────────────────────────────────────────────────────────────────────
    if require_tool "asnmap"; then
        log_info "Mapping ASN to CIDRs..."
        
        local silent_flag=""
        [[ "${VERBOSE:-0}" != "1" ]] && silent_flag="-silent"
        
        # From domain
        echo "$target" | asnmap $silent_flag > "$base/intel/cidrs_domain.txt"
        
        # From org file if exists
        if [[ -s "$base/intel/org_ranges.txt" ]]; then
            cat "$base/intel/org_ranges.txt" | asnmap $silent_flag >> "$base/intel/cidrs_org.txt"
        fi
    fi
    
    # ─────────────────────────────────────────────────────────────────────────
    # Merge all CIDRs
    # ─────────────────────────────────────────────────────────────────────────
    cat "$base/intel/"cidrs_*.txt 2>/dev/null | sort -u > "$base/intel/all_cidrs.txt"
    
    # ─────────────────────────────────────────────────────────────────────────
    # Expand CIDRs to IPs (optional, for small ranges)
    # ─────────────────────────────────────────────────────────────────────────
    if require_tool "mapcidr"; then
        log_info "Expanding CIDRs to IP list..."
        
        local silent_flag=""
        [[ "${VERBOSE:-0}" != "1" ]] && silent_flag="-silent"
        
        # Only expand if total IPs < 100000
        local cidr_count=$(wc -l < "$base/intel/all_cidrs.txt" 2>/dev/null || echo 0)
        
        if [[ $cidr_count -lt 50 ]]; then
            mapcidr -l "$base/intel/all_cidrs.txt" $silent_flag > "$base/intel/all_ips.txt"
            log_success "Expanded to $(wc -l < "$base/intel/all_ips.txt") IPs"
        else
            log_warn "Too many CIDRs ($cidr_count), skipping IP expansion"
        fi
    fi
    
    # ─────────────────────────────────────────────────────────────────────────
    # Reverse DNS on IP ranges
    # ─────────────────────────────────────────────────────────────────────────
    if [[ -s "$base/intel/all_ips.txt" ]] && require_tool "dnsx"; then
        log_info "Running reverse DNS lookup..."
        
        local silent_flag=""
        [[ "${VERBOSE:-0}" != "1" ]] && silent_flag="-silent"
        
        # Limit to first 10000 IPs
        head -10000 "$base/intel/all_ips.txt" | \
            dnsx -ptr -resp-only $silent_flag > "$base/intel/ptr_records.txt"
        
        # Extract domains that match target
        grep -i "$target" "$base/intel/ptr_records.txt" > "$base/intel/ptr_inscope.txt" 2>/dev/null
    fi
    
    # ─────────────────────────────────────────────────────────────────────────
    # WHOIS Information
    # ─────────────────────────────────────────────────────────────────────────
    log_info "Gathering WHOIS data..."
    whois "$target" > "$base/intel/whois.txt" 2>/dev/null
    
    # Extract emails from WHOIS
    grep -oE "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}" "$base/intel/whois.txt" | \
        sort -u > "$base/intel/whois_emails.txt" 2>/dev/null
    
    # ─────────────────────────────────────────────────────────────────────────
    # Certificate Transparency
    # ─────────────────────────────────────────────────────────────────────────
    log_info "Checking Certificate Transparency logs..."
    
    curl -s "https://crt.sh/?q=%25.$target&output=json" 2>/dev/null | \
        jq -r '.[].name_value' 2>/dev/null | \
        sed 's/\*\.//g' | \
        sort -u > "$base/intel/crtsh.txt"
    
    # ─────────────────────────────────────────────────────────────────────────
    # Stats
    # ─────────────────────────────────────────────────────────────────────────
    separator
    log_success "Intel gathering complete!"
    show_stats "CIDRs found" "$base/intel/all_cidrs.txt"
    show_stats "IPs expanded" "$base/intel/all_ips.txt"
    show_stats "PTR records" "$base/intel/ptr_records.txt"
    show_stats "CT domains" "$base/intel/crtsh.txt"
    
    # Save to global subs file for next modules
    cat "$base/intel/crtsh.txt" "$base/intel/ptr_inscope.txt" 2>/dev/null | \
        sort -u > "$base/subs_intel.txt"
        
    save_stat "intel_cidrs" "$(wc -l < "$base/intel/all_cidrs.txt" 2>/dev/null)" "$base"
    
    return 0
}
