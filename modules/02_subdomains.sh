#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# SHADOW v5 - Module 02: Subdomain Enumeration
# ═══════════════════════════════════════════════════════════════════════════════
# Aggressive subdomain discovery using multiple sources
# ═══════════════════════════════════════════════════════════════════════════════

MODULE="02_SUBDOMAINS"

run() {
    local target="$1"
    local base="$2"
    
    banner "🌐 SUBDOMAIN ENUMERATION → $target"
    
    mkdir -p "$base/subs"
    local temp_dir=$(mktemp -d)
    
    # ─────────────────────────────────────────────────────────────────────────
    # Passive Sources (Parallel)
    # ─────────────────────────────────────────────────────────────────────────
    log_info "Starting passive enumeration..."
    
    local silent_flag=$(get_silent_flag)
    local stderr_redir=$(get_stderr)
    
    # Subfinder
    if require_tool "subfinder"; then
        log_info "Running Subfinder..."
        if [[ "${VERBOSE:-0}" == "1" ]]; then
            subfinder -d "$target" -all -o "$temp_dir/subfinder.txt" &
        else
            subfinder -d "$target" -all -silent > "$temp_dir/subfinder.txt" 2>/dev/null &
        fi
    fi
    
    # Assetfinder
    if require_tool "assetfinder"; then
        log_info "Running Assetfinder..."
        if [[ "${VERBOSE:-0}" == "1" ]]; then
            assetfinder --subs-only "$target" 2>&1 | tee "$temp_dir/assetfinder.txt" &
        else
            assetfinder --subs-only "$target" > "$temp_dir/assetfinder.txt" 2>/dev/null &
        fi
    fi
    
    # Findomain
    if check_tool "findomain"; then
        log_info "Running Findomain..."
        if [[ "${VERBOSE:-0}" == "1" ]]; then
            findomain -t "$target" 2>&1 | tee "$temp_dir/findomain.txt" &
        else
            findomain -t "$target" -q > "$temp_dir/findomain.txt" 2>/dev/null &
        fi
    fi
    
    # Amass passive
    if require_tool "amass"; then
        log_info "Running Amass (passive)..."
        if [[ "${VERBOSE:-0}" == "1" ]]; then
            timeout 600 amass enum -passive -d "$target" -o "$temp_dir/amass.txt" &
        else
            timeout 600 amass enum -passive -d "$target" -o "$temp_dir/amass.txt" 2>/dev/null &
        fi
    fi
    
    # Github-subdomains (if configured)
    if check_tool "github-subdomains" && [[ -n "$GITHUB_TOKEN" ]]; then
        log_info "Running Github-subdomains..."
        if [[ "${VERBOSE:-0}" == "1" ]]; then
            github-subdomains -d "$target" -t "$GITHUB_TOKEN" 2>&1 | tee "$temp_dir/github.txt" &
        else
            github-subdomains -d "$target" -t "$GITHUB_TOKEN" > "$temp_dir/github.txt" 2>/dev/null &
        fi
    fi
    
    # Wait for all passive sources
    log_info "Waiting for passive enumeration to complete..."
    wait
    
    # ─────────────────────────────────────────────────────────────────────────
    # API Sources
    # ─────────────────────────────────────────────────────────────────────────
    log_info "Querying API sources..."
    
    # Chaos (if API key available)
    if check_tool "chaos" && [[ -n "$CHAOS_KEY" ]]; then
        if [[ "${VERBOSE:-0}" == "1" ]]; then
            chaos -d "$target" 2>&1 | tee "$temp_dir/chaos.txt"
        else
            chaos -d "$target" -silent > "$temp_dir/chaos.txt" 2>/dev/null
        fi
    fi
    
    # SecurityTrails
    if [[ -n "$SECURITYTRAILS_KEY" ]]; then
        curl -s "https://api.securitytrails.com/v1/domain/$target/subdomains" \
            -H "APIKEY: $SECURITYTRAILS_KEY" 2>/dev/null | \
            jq -r '.subdomains[]' 2>/dev/null | \
            sed "s/$/.${target}/" > "$temp_dir/securitytrails.txt"
    fi
    
    # Shodan
    if [[ -n "$SHODAN_KEY" ]]; then
        curl -s "https://api.shodan.io/dns/domain/$target?key=$SHODAN_KEY" 2>/dev/null | \
            jq -r '.subdomains[]' 2>/dev/null | \
            sed "s/$/.${target}/" > "$temp_dir/shodan.txt"
    fi
    
    # ─────────────────────────────────────────────────────────────────────────
    # Web Archives
    # ─────────────────────────────────────────────────────────────────────────
    log_info "Querying web archives..."
    
    # Wayback Machine
    curl -s "http://web.archive.org/cdx/search/cdx?url=*.$target/*&output=text&fl=original&collapse=urlkey" 2>/dev/null | \
        sed 's|https\?://||' | cut -d/ -f1 | sort -u > "$temp_dir/wayback.txt" &
    
    # AlienVault OTX
    curl -s "https://otx.alienvault.com/api/v1/indicators/domain/$target/passive_dns" 2>/dev/null | \
        jq -r '.passive_dns[].hostname' 2>/dev/null | sort -u > "$temp_dir/otx.txt" &
    
    # URLScan
    curl -s "https://urlscan.io/api/v1/search/?q=domain:$target" 2>/dev/null | \
        jq -r '.results[].page.domain' 2>/dev/null | sort -u > "$temp_dir/urlscan.txt" &
    
    wait
    
    # ─────────────────────────────────────────────────────────────────────────
    # Merge All Results
    # ─────────────────────────────────────────────────────────────────────────
    log_info "Merging all subdomain sources..."
    
    # Merge from intel module if exists
    if [[ -f "$base/subs_intel.txt" ]]; then
        cat "$base/subs_intel.txt" >> "$temp_dir/intel.txt"
    fi
    
    # Merge all
    cat "$temp_dir"/*.txt 2>/dev/null | \
        tr '[:upper:]' '[:lower:]' | \
        sed 's/^\*\.//g' | \
        grep -E "\.${target}$" | \
        sort -u > "$base/subs/all_subs.txt"
    
    # ─────────────────────────────────────────────────────────────────────────
    # Permutation & Brute
    # ─────────────────────────────────────────────────────────────────────────
    if check_tool "gotator"; then
        log_info "Running permutations with Gotator..."
        gotator -sub "$base/subs/all_subs.txt" \
                -perm "${SCRIPT_DIR}/wordlists/permutations.txt" \
                -depth 1 -numbers 3 -silent > "$base/subs/permutations.txt" 2>/dev/null
        
        cat "$base/subs/permutations.txt" >> "$base/subs/all_subs.txt"
    fi
    
    if check_tool "alterx"; then
        log_info "Running AlterX for smart permutations..."
        cat "$base/subs/all_subs.txt" | alterx -silent > "$base/subs/alterx.txt" 2>/dev/null
        cat "$base/subs/alterx.txt" >> "$base/subs/all_subs.txt"
    fi
    
    # Final deduplication
    dedupe "$base/subs/all_subs.txt"

    # Apply scope filtering
    if [[ "${ENABLE_SCOPE_FILTERING:-true}" == "true" ]]; then
        filter_scope_arrays "$base/subs/all_subs.txt"
    fi
    
    # ─────────────────────────────────────────────────────────────────────────
    # APPLY LIMITS (Prevent runaway scans)
    # ─────────────────────────────────────────────────────────────────────────
    if [[ "${ENABLE_LIMITS:-true}" == "true" ]]; then
        local max_subs="${MAX_SUBDOMAINS:-5000}"
        local current_subs=$(wc -l < "$base/subs/all_subs.txt" 2>/dev/null || echo 0)
        
        if [[ $current_subs -gt $max_subs ]]; then
            log_warn "Limiting subdomains from $current_subs to $max_subs"
            mv "$base/subs/all_subs.txt" "$base/subs/all_subs_full.txt"
            head -n "$max_subs" "$base/subs/all_subs_full.txt" > "$base/subs/all_subs.txt"
            log_info "Full list saved to: all_subs_full.txt"
        fi
    fi
    
    # ─────────────────────────────────────────────────────────────────────────
    # Per-source stats
    # ─────────────────────────────────────────────────────────────────────────
    separator
    log_success "Subdomain enumeration complete!"
    
    for src in "$temp_dir"/*.txt; do
        if [[ -f "$src" ]]; then
            local name=$(basename "$src" .txt)
            local count=$(wc -l < "$src" 2>/dev/null || echo 0)
            if [[ $count -gt 0 ]]; then
                echo -e "  ${CYAN}→${NC} $name: ${GREEN}$count${NC}"
            fi
        fi
    done
    
    separator
    show_stats "Total unique subdomains" "$base/subs/all_subs.txt"
    
    # Cleanup
    rm -rf "$temp_dir"
    
    save_stat "total_subs" "$(wc -l < "$base/subs/all_subs.txt" 2>/dev/null)" "$base"
    
    return 0
}
