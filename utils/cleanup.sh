#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# SHADOW v5 - Cleanup Utility
# ═══════════════════════════════════════════════════════════════════════════════
# Removes temporary and unnecessary files after scan
# ═══════════════════════════════════════════════════════════════════════════════

# Files to always remove (temp/intermediate)
TEMP_PATTERNS=(
    "*.tmp"
    "*.temp"
    "*_temp.txt"
    "*.bak"
)

# Files to remove if cleanup is aggressive
INTERMEDIATE_FILES=(
    "no_static.txt"
    "with_params.txt"
    "dead_urls.txt"
    "diff_sample.txt"
    "no_auth_response.txt"
    "with_auth_response.txt"
    "alive_params.txt"
)

# Directories to clean
CLEAN_DIRS=(
    "gospider"
)

# ─────────────────────────────────────────────────────────────────────────────
# Module-specific required files
# Only these files are needed after each module completes
# ─────────────────────────────────────────────────────────────────────────────
declare -A MODULE_REQUIRED_FILES=(
    # After subdomain discovery - only need alive subs
    ["02_subdomains"]="subs/alive.txt subs/all.txt"
    
    # After DNS - only need resolved
    ["03_dns"]="dns/resolved.txt dns/ips.txt"
    
    # After ports - only need open ports
    ["04_ports"]="ports/open.txt"
    
    # After HTTP - only need alive hosts
    ["05_http"]="http/alive.txt http/tech.txt"
    
    # After content - only need discovered paths
    ["06_content"]="content/all_ffuf.txt content/interesting.txt"
    
    # After JS - only need extracted data
    ["07_js"]="js/endpoints.txt js/secrets.txt js/domains.txt"
    
    # After params - only need params file
    ["08_params"]="params/all.txt params/gf_xss.txt params/gf_sqli.txt params/gf_ssrf.txt"
    
    # After vuln - keep all findings
    ["09_vuln"]="vulns/"
)

# ─────────────────────────────────────────────────────────────────────────────
# Smart cleanup after module completes
# Keeps only required files for next stages
# ─────────────────────────────────────────────────────────────────────────────
cleanup_after_module() {
    local base="$1"
    local module="$2"
    local keep_temp="${3:-false}"
    
    if [[ "$keep_temp" == "true" ]]; then
        log_debug "Keeping temp files (keep_temp=true)"
        return 0
    fi
    
    local required="${MODULE_REQUIRED_FILES[$module]:-}"
    
    if [[ -z "$required" ]]; then
        log_debug "No cleanup rules for module: $module"
        return 0
    fi
    
    log_info "🧹 Cleaning up after $module..."
    
    local removed=0
    
    # Get module directory (e.g., "subs" from "02_subdomains")
    case "$module" in
        "02_subdomains") local mod_dir="subs" ;;
        "03_dns") local mod_dir="dns" ;;
        "04_ports") local mod_dir="ports" ;;
        "05_http") local mod_dir="http" ;;
        "06_content") local mod_dir="content" ;;
        "07_js") local mod_dir="js" ;;
        "08_params") local mod_dir="params" ;;
        "09_vuln") local mod_dir="vulns" ;;
        *) return 0 ;;
    esac
    
    # Skip if directory doesn't exist
    [[ ! -d "$base/$mod_dir" ]] && return 0
    
    # Create temp file with required files list
    local required_list=$(mktemp)
    echo "$required" | tr ' ' '\n' | while read -r f; do
        echo "$base/$f"
    done > "$required_list"
    
    # Find and remove files not in required list (only in module dir)
    find "$base/$mod_dir" -type f | while read -r file; do
        local keep=false
        
        # Check if file is in required list
        while IFS= read -r req; do
            if [[ "$file" == "$req" ]] || [[ "$file" == "$base/$req"* ]]; then
                keep=true
                break
            fi
        done < "$required_list"
        
        # Remove if not required
        if [[ "$keep" == "false" ]]; then
            rm -f "$file" 2>/dev/null && ((removed++))
        fi
    done
    
    rm -f "$required_list"
    
    # Remove empty directories
    find "$base/$mod_dir" -type d -empty -delete 2>/dev/null
    
    [[ $removed -gt 0 ]] && log_info "  Removed $removed unnecessary files"
    
    return 0
}

cleanup_scan() {
    local base="$1"
    local aggressive="${2:-false}"
    
    if [[ ! -d "$base" ]]; then
        echo "Directory not found: $base"
        return 1
    fi
    
    echo "🧹 Cleaning up: $base"
    
    local removed=0
    
    # Remove temp patterns
    for pattern in "${TEMP_PATTERNS[@]}"; do
        local count=$(find "$base" -name "$pattern" -type f 2>/dev/null | wc -l)
        if [[ $count -gt 0 ]]; then
            find "$base" -name "$pattern" -type f -delete 2>/dev/null
            removed=$((removed + count))
        fi
    done
    
    # Remove intermediate files
    for file in "${INTERMEDIATE_FILES[@]}"; do
        if [[ -f "$base/$file" ]]; then
            rm -f "$base/$file"
            removed=$((removed + 1))
        fi
        # Also check subdirs
        find "$base" -name "$file" -type f -delete 2>/dev/null
    done
    
    # Remove empty files
    local empty_count=$(find "$base" -type f -empty 2>/dev/null | wc -l)
    if [[ $empty_count -gt 0 ]]; then
        find "$base" -type f -empty -delete 2>/dev/null
        removed=$((removed + empty_count))
    fi
    
    # Remove empty directories
    find "$base" -type d -empty -delete 2>/dev/null
    
    # Aggressive cleanup
    if [[ "$aggressive" == "true" ]]; then
        echo "  Running aggressive cleanup..."
        
        # Remove downloaded JS files (keep just the analysis)
        if [[ -d "$base/js/files" ]]; then
            local js_count=$(find "$base/js/files" -type f | wc -l)
            rm -rf "$base/js/files"
            removed=$((removed + js_count))
            echo "  Removed $js_count JS files"
        fi
        
        # Remove gospider raw output
        if [[ -d "$base/params/gospider" ]]; then
            rm -rf "$base/params/gospider"
            echo "  Removed gospider directory"
        fi
        
        # Compress large files
        for large_file in "$base/params/all_urls_full.txt" "$base/subs/all_subs_full.txt"; do
            if [[ -f "$large_file" ]]; then
                gzip -f "$large_file" 2>/dev/null
                echo "  Compressed: $(basename "$large_file")"
            fi
        done
    fi
    
    echo "✅ Cleanup complete: removed $removed files"
    
    # Show final size
    local final_size=$(du -sh "$base" 2>/dev/null | cut -f1)
    echo "📁 Final size: $final_size"
}

# Calculate space savings
show_cleanup_stats() {
    local base="$1"
    
    echo ""
    echo "📊 Cleanup Statistics:"
    echo "━━━━━━━━━━━━━━━━━━━━━━"
    
    # Count files by type
    echo "Files by type:"
    echo "  .txt:  $(find "$base" -name "*.txt" -type f 2>/dev/null | wc -l)"
    echo "  .json: $(find "$base" -name "*.json" -type f 2>/dev/null | wc -l)"
    echo "  .js:   $(find "$base" -name "*.js" -type f 2>/dev/null | wc -l)"
    echo "  .gz:   $(find "$base" -name "*.gz" -type f 2>/dev/null | wc -l)"
    
    # Empty files
    local empty=$(find "$base" -type f -empty 2>/dev/null | wc -l)
    echo ""
    echo "Empty files: $empty"
    
    # Total size
    echo ""
    echo "Total size: $(du -sh "$base" 2>/dev/null | cut -f1)"
}

# Main cleanup for all scans
cleanup_all() {
    local logs_dir="${1:-./logs}"
    local aggressive="${2:-false}"
    
    echo "🧹 Cleaning all scans in: $logs_dir"
    echo ""
    
    for scan_dir in "$logs_dir"/*/; do
        if [[ -d "$scan_dir" ]]; then
            cleanup_scan "$scan_dir" "$aggressive"
            echo ""
        fi
    done
}

# If run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    case "${1:-}" in
        --all)
            cleanup_all "${2:-./logs}" "${3:-false}"
            ;;
        --aggressive)
            cleanup_scan "${2:-.}" "true"
            ;;
        --stats)
            show_cleanup_stats "${2:-.}"
            ;;
        *)
            if [[ -n "$1" ]]; then
                cleanup_scan "$1" "false"
            else
                echo "Usage: cleanup.sh [--all|--aggressive|--stats] [path]"
                echo ""
                echo "Options:"
                echo "  --all        Clean all scans in logs directory"
                echo "  --aggressive Remove JS files and compress large files"
                echo "  --stats      Show cleanup statistics"
                echo ""
                echo "Examples:"
                echo "  ./cleanup.sh logs/target_20260130/"
                echo "  ./cleanup.sh --aggressive logs/target_20260130/"
                echo "  ./cleanup.sh --all logs/"
            fi
            ;;
    esac
fi
