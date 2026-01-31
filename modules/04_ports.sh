#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# SHADOW v5 - Module 04: Port Scanning
# ═══════════════════════════════════════════════════════════════════════════════
# Fast and comprehensive port scanning
# ═══════════════════════════════════════════════════════════════════════════════

MODULE="04_PORTS"

run() {
    local target="$1"
    local base="$2"
    
    banner "🔌 PORT SCANNING → $target"
    
    mkdir -p "$base/ports"
    
    local hosts_file="$base/dns/alive.txt"
    local ips_file="$base/dns/unique_ips.txt"
    
    # Prefer IPs for port scanning (faster)
    local scan_file="$ips_file"
    if [[ ! -s "$ips_file" ]]; then
        scan_file="$hosts_file"
    fi
    
    # Single domain mode - create input file with just the target
    if [[ ! -s "$scan_file" ]]; then
        if [[ "${SINGLE_MODE:-0}" == "1" ]]; then
            log_info "Single domain mode - scanning $target only"
            mkdir -p "$base/dns"
            echo "$target" > "$base/dns/alive.txt"
            scan_file="$base/dns/alive.txt"
        else
            log_error "No hosts to scan. Run DNS resolution first."
            return 1
        fi
    fi
    
    local total_hosts=$(wc -l < "$scan_file")
    log_info "Scanning $total_hosts hosts..."
    
    # ─────────────────────────────────────────────────────────────────────────
    # Naabu - Fast Port Scan
    # ─────────────────────────────────────────────────────────────────────────
    if require_tool "naabu"; then
        log_info "Running Naabu (top 1000 ports)..."
        
        naabu -list "$scan_file" \
              -top-ports 1000 \
              -c 50 \
              -rate 1000 \
              -silent \
              -o "$base/ports/naabu_top1000.txt" 2>/dev/null
        
        # Extract unique ports found
        cut -d: -f2 "$base/ports/naabu_top1000.txt" 2>/dev/null | \
            sort -n -u > "$base/ports/open_ports.txt"
        
        log_success "Found $(wc -l < "$base/ports/open_ports.txt" 2>/dev/null || echo 0) unique ports"
    fi
    
    # ─────────────────────────────────────────────────────────────────────────
    # Full Port Scan (optional, slower)
    # ─────────────────────────────────────────────────────────────────────────
    if [[ "${FULL_SCAN:-0}" == "1" ]]; then
        log_info "Running full port scan (1-65535)..."
        
        if check_tool "masscan" && [[ $EUID -eq 0 ]]; then
            # Use masscan if root
            masscan -iL "$scan_file" \
                    -p1-65535 \
                    --rate=10000 \
                    -oL "$base/ports/masscan_full.txt" 2>/dev/null
                    
            # Convert masscan output
            grep "^open" "$base/ports/masscan_full.txt" 2>/dev/null | \
                awk '{print $4":"$3}' > "$base/ports/full_ports.txt"
        else
            # Use naabu for full scan
            naabu -list "$scan_file" \
                  -p 1-65535 \
                  -c 25 \
                  -rate 500 \
                  -silent \
                  -o "$base/ports/naabu_full.txt" 2>/dev/null
        fi
    fi
    
    # ─────────────────────────────────────────────────────────────────────────
    # Common Ports Scan
    # ─────────────────────────────────────────────────────────────────────────
    log_info "Scanning common web ports..."
    
    local web_ports="80,443,8080,8443,8000,8888,3000,5000,9000,9443,4443,8081,8082"
    
    naabu -list "$scan_file" \
          -p "$web_ports" \
          -c 50 \
          -silent \
          -o "$base/ports/web_ports.txt" 2>/dev/null
    
    # ─────────────────────────────────────────────────────────────────────────
    # Service Detection
    # ─────────────────────────────────────────────────────────────────────────
    if [[ -s "$base/ports/naabu_top1000.txt" ]]; then
        log_info "Detecting services..."
        
        # Group by service type
        while IFS= read -r line; do
            local host=$(echo "$line" | cut -d: -f1)
            local port=$(echo "$line" | cut -d: -f2)
            
            case "$port" in
                21) echo "$line" >> "$base/ports/ftp.txt" ;;
                22) echo "$line" >> "$base/ports/ssh.txt" ;;
                23) echo "$line" >> "$base/ports/telnet.txt" ;;
                25|465|587) echo "$line" >> "$base/ports/smtp.txt" ;;
                53) echo "$line" >> "$base/ports/dns.txt" ;;
                80|8080|8000|3000|5000) echo "$line" >> "$base/ports/http.txt" ;;
                443|8443|9443|4443) echo "$line" >> "$base/ports/https.txt" ;;
                110|995) echo "$line" >> "$base/ports/pop3.txt" ;;
                143|993) echo "$line" >> "$base/ports/imap.txt" ;;
                389|636) echo "$line" >> "$base/ports/ldap.txt" ;;
                445) echo "$line" >> "$base/ports/smb.txt" ;;
                1433) echo "$line" >> "$base/ports/mssql.txt" ;;
                1521) echo "$line" >> "$base/ports/oracle.txt" ;;
                3306) echo "$line" >> "$base/ports/mysql.txt" ;;
                3389) echo "$line" >> "$base/ports/rdp.txt" ;;
                5432) echo "$line" >> "$base/ports/postgres.txt" ;;
                5900) echo "$line" >> "$base/ports/vnc.txt" ;;
                6379) echo "$line" >> "$base/ports/redis.txt" ;;
                27017) echo "$line" >> "$base/ports/mongodb.txt" ;;
                9200) echo "$line" >> "$base/ports/elasticsearch.txt" ;;
            esac
        done < "$base/ports/naabu_top1000.txt"
    fi
    
    # ─────────────────────────────────────────────────────────────────────────
    # Prepare HTTP targets for next module
    # ─────────────────────────────────────────────────────────────────────────
    log_info "Preparing HTTP targets..."
    
    # Combine HTTP and HTTPS ports
    cat "$base/ports/http.txt" "$base/ports/https.txt" 2>/dev/null | \
        sort -u > "$base/ports/all_web.txt"
    
    # Create URL format for httpx
    while IFS= read -r line; do
        local host=$(echo "$line" | cut -d: -f1)
        local port=$(echo "$line" | cut -d: -f2)
        
        if [[ "$port" == "443" || "$port" == "8443" || "$port" == "9443" ]]; then
            echo "https://${host}:${port}"
        else
            echo "http://${host}:${port}"
        fi
    done < "$base/ports/all_web.txt" > "$base/ports/http_targets.txt" 2>/dev/null
    
    # ─────────────────────────────────────────────────────────────────────────
    # Stats
    # ─────────────────────────────────────────────────────────────────────────
    separator
    log_success "Port scanning complete!"
    
    show_stats "Total open ports" "$base/ports/naabu_top1000.txt"
    show_stats "HTTP services" "$base/ports/http.txt"
    show_stats "HTTPS services" "$base/ports/https.txt"
    show_stats "SSH services" "$base/ports/ssh.txt"
    show_stats "Database services" "$base/ports/mysql.txt"
    
    # High-value targets
    separator
    log_info "High-value services found:"
    
    for service in rdp smb ssh telnet redis mongodb elasticsearch; do
        if [[ -s "$base/ports/${service}.txt" ]]; then
            local count=$(wc -l < "$base/ports/${service}.txt")
            log_found "$service: $count hosts"
        fi
    done
    
    save_stat "open_ports" "$(wc -l < "$base/ports/naabu_top1000.txt" 2>/dev/null)" "$base"
    save_stat "web_services" "$(wc -l < "$base/ports/all_web.txt" 2>/dev/null)" "$base"
    
    return 0
}
