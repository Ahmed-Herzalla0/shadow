#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# SHADOW v5 - Module 06: Content Discovery
# ═══════════════════════════════════════════════════════════════════════════════
# Directory brute-forcing and content discovery
# ═══════════════════════════════════════════════════════════════════════════════

MODULE="06_CONTENT"

run() {
    local target="$1"
    local base="$2"
    
    banner "📂 CONTENT DISCOVERY → $target"
    
    mkdir -p "$base/content"
    
    local http_file="$base/http/alive.txt"
    
    # Single domain mode - create http input file if missing
    if [[ ! -s "$http_file" ]] && [[ "${SINGLE_MODE:-0}" == "1" ]]; then
        log_info "Single domain mode - running content discovery on $target"
        mkdir -p "$base/http"
        echo "https://$target" > "$http_file"
        echo "http://$target" >> "$http_file"
    fi
    
    if [[ ! -s "$http_file" ]]; then
        log_error "No HTTP hosts found. Run HTTP probing first."
        return 1
    fi
    
    local total_hosts=$(wc -l < "$http_file")
    log_info "Running content discovery on $total_hosts hosts..."
    
    # Wordlist selection
    local wordlist="${SCRIPT_DIR}/wordlists/dirs.txt"
    if [[ ! -f "$wordlist" ]]; then
        wordlist="/usr/share/wordlists/dirb/common.txt"
    fi
    if [[ ! -f "$wordlist" ]]; then
        wordlist="/usr/share/seclists/Discovery/Web-Content/common.txt"
    fi
    
    if [[ ! -f "$wordlist" ]]; then
        log_error "No wordlist found. Please install SecLists or create wordlists/dirs.txt"
        return 1
    fi
    
    log_info "Using wordlist: $wordlist"
    
    # ─────────────────────────────────────────────────────────────────────────
    # FFUF Directory Brute-force
    # ─────────────────────────────────────────────────────────────────────────
    if require_tool "ffuf"; then
        log_info "Running FFUF..."
        
        # Proxy support for Burp Suite
        local proxy_opt=""
        [[ "${ENABLE_PROXY:-false}" == "true" ]] && proxy_opt="-x ${PROXY_URL:-http://127.0.0.1:8080}"
        
        local count=0
        while IFS= read -r host; do
            ((count++))
            local safe_host=$(echo "$host" | sed 's|https\?://||' | sed 's|[/:.]|_|g')
            
            progress $count $total_hosts "FFUF"
            
            ffuf -u "${host}/FUZZ" \
                 -w "$wordlist" \
                 -mc 200,201,204,301,302,307,401,403,405,500 \
                 -ac \
                 -t 40 \
                 -timeout 10 \
                 $proxy_opt \
                 -o "$base/content/ffuf_${safe_host}.json" \
                 -of json \
                 -s 2>/dev/null
                 
        done < "$http_file"
        
        echo ""  # New line after progress
        
        # Merge all FFUF results
        log_info "Merging FFUF results..."
        for f in "$base/content"/ffuf_*.json; do
            if [[ -f "$f" ]]; then
                jq -r '.results[]? | "\(.url) [\(.status)] [\(.length)]"' "$f" 2>/dev/null
            fi
        done | sort -u > "$base/content/all_ffuf.txt"
    fi
    
    # ─────────────────────────────────────────────────────────────────────────
    # Feroxbuster (if available, more aggressive)
    # ─────────────────────────────────────────────────────────────────────────
    if check_tool "feroxbuster" && [[ "${USE_FEROX:-0}" == "1" ]]; then
        log_info "Running Feroxbuster..."
        
        # Proxy support for Burp Suite
        local proxy_opt=""
        [[ "${ENABLE_PROXY:-false}" == "true" ]] && proxy_opt="--proxy ${PROXY_URL:-http://127.0.0.1:8080}"
        
        feroxbuster --stdin \
                    -w "$wordlist" \
                    --status-codes 200,204,301,302,307,401,403,405,500 \
                    --threads 50 \
                    --depth 2 \
                    --no-recursion \
                    $proxy_opt \
                    -o "$base/content/feroxbuster.txt" < "$http_file" 2>/dev/null
    fi
    
    # ─────────────────────────────────────────────────────────────────────────
    # Common Files Check
    # ─────────────────────────────────────────────────────────────────────────
    log_info "Checking for common sensitive files..."
    
    local sensitive_files=(
        ".git/config"
        ".git/HEAD"
        ".env"
        ".env.local"
        ".env.production"
        "config.php"
        "wp-config.php"
        "configuration.php"
        ".htaccess"
        ".htpasswd"
        "web.config"
        "crossdomain.xml"
        "clientaccesspolicy.xml"
        "phpinfo.php"
        "info.php"
        "server-status"
        "server-info"
        ".svn/entries"
        ".DS_Store"
        "backup.zip"
        "backup.sql"
        "dump.sql"
        "database.sql"
        ".backup"
        "robots.txt"
        "sitemap.xml"
        "security.txt"
        ".well-known/security.txt"
        "swagger.json"
        "swagger.yaml"
        "api-docs"
        "graphql"
        "graphiql"
        "actuator"
        "actuator/health"
        "actuator/env"
        "debug"
        "trace"
        "elmah.axd"
        "error_log"
        "errors.log"
        "access.log"
    )
    
    while IFS= read -r host; do
        for file in "${sensitive_files[@]}"; do
            local status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "${host}/${file}" 2>/dev/null)
            if [[ "$status" == "200" || "$status" == "403" ]]; then
                echo "${host}/${file} [$status]" >> "$base/content/sensitive_files.txt"
            fi
        done
    done < <(head -50 "$http_file") 2>/dev/null &
    
    # ─────────────────────────────────────────────────────────────────────────
    # Backup Files Check
    # ─────────────────────────────────────────────────────────────────────────
    log_info "Checking for backup files..."
    
    local backup_extensions=("~" ".bak" ".backup" ".old" ".orig" ".save" ".swp" ".tmp")
    
    # Get paths from FFUF results
    if [[ -f "$base/content/all_ffuf.txt" ]]; then
        while IFS= read -r line; do
            local url=$(echo "$line" | awk '{print $1}')
            for ext in "${backup_extensions[@]}"; do
                local backup_url="${url}${ext}"
                local status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 "$backup_url" 2>/dev/null)
                if [[ "$status" == "200" ]]; then
                    echo "$backup_url [$status]" >> "$base/content/backup_files.txt"
                fi
            done
        done < <(head -100 "$base/content/all_ffuf.txt") 2>/dev/null
    fi
    
    # ─────────────────────────────────────────────────────────────────────────
    # Extract interesting paths
    # ─────────────────────────────────────────────────────────────────────────
    log_info "Extracting interesting paths..."
    
    local interesting_patterns=(
        "admin"
        "api"
        "config"
        "upload"
        "backup"
        "debug"
        "test"
        "dev"
        "staging"
        "internal"
        "private"
        "secret"
        "hidden"
        "console"
        "dashboard"
        "panel"
        "manage"
        "cgi-bin"
        "scripts"
    )
    
    for pattern in "${interesting_patterns[@]}"; do
        grep -i "$pattern" "$base/content/all_ffuf.txt" >> "$base/content/interesting_paths.txt" 2>/dev/null
    done
    
    sort -u "$base/content/interesting_paths.txt" -o "$base/content/interesting_paths.txt" 2>/dev/null
    
    # Wait for background jobs
    wait
    
    # ─────────────────────────────────────────────────────────────────────────
    # Stats
    # ─────────────────────────────────────────────────────────────────────────
    separator
    log_success "Content discovery complete!"
    
    show_stats "Total paths found" "$base/content/all_ffuf.txt"
    show_stats "Sensitive files" "$base/content/sensitive_files.txt"
    show_stats "Backup files" "$base/content/backup_files.txt"
    show_stats "Interesting paths" "$base/content/interesting_paths.txt"
    
    # Critical findings
    if [[ -s "$base/content/sensitive_files.txt" ]]; then
        separator
        log_critical "Sensitive files found:"
        head -20 "$base/content/sensitive_files.txt"
    fi
    
    save_stat "content_paths" "$(wc -l < "$base/content/all_ffuf.txt" 2>/dev/null)" "$base"
    
    return 0
}
