#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# SHADOW v5 - Module 03: DNS Resolution & Analysis
# ═══════════════════════════════════════════════════════════════════════════════
# Resolves subdomains and extracts DNS information
# ═══════════════════════════════════════════════════════════════════════════════

MODULE="03_DNS"

run() {
    local target="$1"
    local base="$2"
    
    banner "🔗 DNS RESOLUTION → $target"
    
    mkdir -p "$base/dns"
    
    local subs_file="$base/subs/all_subs.txt"
    
    # Single domain mode - create input file with just the target
    if [[ "${SINGLE_MODE:-0}" == "1" ]] || [[ ! -s "$subs_file" ]]; then
        if [[ "${SINGLE_MODE:-0}" == "1" ]]; then
            log_info "Single domain mode - scanning $target only"
            mkdir -p "$base/subs"
            echo "$target" > "$subs_file"
        elif [[ ! -s "$subs_file" ]]; then
            log_warn "No subdomains found. Using target domain directly."
            mkdir -p "$base/subs"
            echo "$target" > "$subs_file"
        fi
    fi
    
    local total_subs=$(wc -l < "$subs_file")
    log_info "Resolving $total_subs target(s)..."
    
    # ─────────────────────────────────────────────────────────────────────────
    # DNS Resolution with DNSX
    # ─────────────────────────────────────────────────────────────────────────
    if require_tool "dnsx"; then
        log_info "Running DNSX resolution..."
        
        # Full resolution with records
        dnsx -l "$subs_file" \
             -a -aaaa -cname -ns -mx -txt \
             -resp \
             -silent \
             -t 100 \
             -o "$base/dns/dnsx_full.txt" 2>/dev/null
        
        # Extract just alive hosts
        dnsx -l "$subs_file" \
             -a -resp-only \
             -silent \
             -t 100 \
             -o "$base/dns/resolved_ips.txt" 2>/dev/null
        
        # Get alive domains
        dnsx -l "$subs_file" \
             -silent \
             -t 100 \
             -o "$base/dns/alive.txt" 2>/dev/null
    fi
    
    # ─────────────────────────────────────────────────────────────────────────
    # Extract CNAME Records (potential takeovers)
    # ─────────────────────────────────────────────────────────────────────────
    log_info "Extracting CNAME records..."
    
    grep "CNAME" "$base/dns/dnsx_full.txt" 2>/dev/null | \
        awk '{print $1, $3}' > "$base/dns/cnames.txt"
    
    # Check for potential takeovers
    local takeover_patterns=(
        "\.s3\.amazonaws\.com"
        "\.cloudfront\.net"
        "\.herokuapp\.com"
        "\.herokudns\.com"
        "\.wordpress\.com"
        "\.pantheonsite\.io"
        "\.zendesk\.com"
        "\.github\.io"
        "\.fastly\.net"
        "\.azurewebsites\.net"
        "\.cloudapp\.azure\.com"
        "\.trafficmanager\.net"
        "\.blob\.core\.windows\.net"
        "\.ghost\.io"
        "\.myshopify\.com"
        "\.statuspage\.io"
        "\.uservoice\.com"
        "\.surge\.sh"
        "\.bitbucket\.io"
        "\.ghost\.org"
        "\.helpjuice\.com"
        "\.helpscoutdocs\.com"
        "\.feedpress\.me"
        "\.freshdesk\.com"
        "\.readme\.io"
        "\.cargo\.site"
        "\.strikingly\.com"
        "\.webflow\.io"
        "\.tictail\.com"
        "\.creatorlink\.net"
    )
    
    for pattern in "${takeover_patterns[@]}"; do
        grep -E "$pattern" "$base/dns/cnames.txt" >> "$base/dns/potential_takeovers.txt" 2>/dev/null
    done
    
    if [[ -s "$base/dns/potential_takeovers.txt" ]]; then
        log_found "Potential subdomain takeovers found!"
        cat "$base/dns/potential_takeovers.txt"
    fi
    
    # ─────────────────────────────────────────────────────────────────────────
    # Wildcard Detection
    # ─────────────────────────────────────────────────────────────────────────
    log_info "Checking for wildcard DNS..."
    
    local random_sub="shadowtest$(date +%s).$target"
    local wildcard_check=$(dig +short "$random_sub" A 2>/dev/null)
    
    if [[ -n "$wildcard_check" ]]; then
        log_warn "Wildcard DNS detected: $wildcard_check"
        echo "$wildcard_check" > "$base/dns/wildcard_ip.txt"
        
        # Filter out wildcard IPs from resolved
        if [[ -s "$base/dns/resolved_ips.txt" ]]; then
            grep -v "$wildcard_check" "$base/dns/resolved_ips.txt" > "$base/dns/resolved_ips_filtered.txt"
            mv "$base/dns/resolved_ips_filtered.txt" "$base/dns/resolved_ips.txt"
        fi
    fi
    
    # ─────────────────────────────────────────────────────────────────────────
    # IP Extraction & Grouping
    # ─────────────────────────────────────────────────────────────────────────
    log_info "Grouping by IP..."
    
    # Create IP to domain mapping
    while IFS= read -r line; do
        local domain=$(echo "$line" | awk '{print $1}')
        local ip=$(echo "$line" | awk '{print $2}')
        echo "$ip $domain"
    done < <(dnsx -l "$subs_file" -a -resp -silent 2>/dev/null) | \
        sort -t. -k1,1n -k2,2n -k3,3n -k4,4n > "$base/dns/ip_domain_map.txt" 2>/dev/null
    
    # Unique IPs
    cut -d' ' -f1 "$base/dns/ip_domain_map.txt" 2>/dev/null | \
        sort -u > "$base/dns/unique_ips.txt"
    
    # ─────────────────────────────────────────────────────────────────────────
    # TLS/SSL Certificate Info
    # ─────────────────────────────────────────────────────────────────────────
    if check_tool "tlsx"; then
        log_info "Extracting TLS certificate info..."
        
        tlsx -l "$base/dns/alive.txt" \
             -san -cn -silent \
             -o "$base/dns/tls_sans.txt" 2>/dev/null
        
        # Extract new domains from SANs
        cut -d',' -f2- "$base/dns/tls_sans.txt" 2>/dev/null | \
            tr ',' '\n' | \
            grep -E "\.${target}$" | \
            sort -u > "$base/dns/san_domains.txt"
        
        # Add new domains to subs
        if [[ -s "$base/dns/san_domains.txt" ]]; then
            local new_from_san=$(comm -23 <(sort "$base/dns/san_domains.txt") <(sort "$subs_file") | wc -l)
            if [[ $new_from_san -gt 0 ]]; then
                log_found "$new_from_san new domains from TLS SANs"
                cat "$base/dns/san_domains.txt" >> "$subs_file"
                dedupe "$subs_file"
            fi
        fi
    fi
    
    # ─────────────────────────────────────────────────────────────────────────
    # Zone Transfer Attempt (legal only if authorized)
    # ─────────────────────────────────────────────────────────────────────────
    log_info "Attempting zone transfer..."
    
    # Get nameservers
    dig NS "$target" +short > "$base/dns/nameservers.txt" 2>/dev/null
    
    while IFS= read -r ns; do
        local zt_result=$(dig @"$ns" "$target" AXFR +noall +answer 2>/dev/null)
        if [[ -n "$zt_result" ]]; then
            log_critical "Zone transfer successful on $ns!"
            echo "$zt_result" > "$base/dns/zone_transfer_$ns.txt"
        fi
    done < "$base/dns/nameservers.txt"
    
    # ─────────────────────────────────────────────────────────────────────────
    # Stats
    # ─────────────────────────────────────────────────────────────────────────
    separator
    log_success "DNS resolution complete!"
    show_stats "Alive subdomains" "$base/dns/alive.txt"
    show_stats "Unique IPs" "$base/dns/unique_ips.txt"
    show_stats "CNAME records" "$base/dns/cnames.txt"
    show_stats "Potential takeovers" "$base/dns/potential_takeovers.txt"
    
    # Copy alive for next module
    cp "$base/dns/alive.txt" "$base/dns_live.txt" 2>/dev/null
    
    save_stat "alive_subs" "$(wc -l < "$base/dns/alive.txt" 2>/dev/null)" "$base"
    save_stat "unique_ips" "$(wc -l < "$base/dns/unique_ips.txt" 2>/dev/null)" "$base"
    
    return 0
}
