#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
#
#   ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗    ██╗   ██╗███████╗
#   ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║    ██║   ██║██╔════╝
#   ███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║    ██║   ██║███████╗
#   ╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║    ╚██╗ ██╔╝╚════██║
#   ███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝     ╚████╔╝ ███████║
#   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝       ╚═══╝  ╚══════╝
#
#   SHADOW RECON v5 - Modular Bug Bounty Framework
#   Author: Shadow Team
#   
# ═══════════════════════════════════════════════════════════════════════════════

set -u

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────
VERSION="5.0.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export SCRIPT_DIR

# Load environment variables from .env (if present)
ENV_FILE="${SCRIPT_DIR}/.env"
if [[ -f "$ENV_FILE" ]]; then
    set -a
    # shellcheck disable=SC1090
    source "$ENV_FILE"
    set +a
fi

# Source utilities
source "${SCRIPT_DIR}/utils/log.sh"
source "${SCRIPT_DIR}/utils/state.sh"
source "${SCRIPT_DIR}/utils/check.sh"
source "${SCRIPT_DIR}/utils/dedupe.sh"

# Source configs
[[ -f "${SCRIPT_DIR}/config/tools.conf" ]] && source "${SCRIPT_DIR}/config/tools.conf"
[[ -f "${SCRIPT_DIR}/config/rate.conf" ]] && source "${SCRIPT_DIR}/config/rate.conf"
[[ -f "${SCRIPT_DIR}/config/scope.conf" ]] && source "${SCRIPT_DIR}/config/scope.conf"

# ─────────────────────────────────────────────────────────────────────────────
# USAGE
# ─────────────────────────────────────────────────────────────────────────────
usage() {
    cat << EOF

${PURPLE}
   ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗
   ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║
   ███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║
   ╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║
   ███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝
   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝
${NC}
   ${CYAN}SHADOW RECON v${VERSION} - Modular Bug Bounty Framework${NC}

${GREEN}USAGE:${NC}
    ./shadow.sh [OPTIONS] <target>

${GREEN}OPTIONS:${NC}
    -h, --help          Show this help
    -v, --version       Show version
    -c, --check         Check tool dependencies
    -m, --module NUM    Run specific module (1-10)
    -s, --skip NUM      Skip module(s) (comma-separated)
    -r, --resume        Resume previous scan
    -f, --full          Full port scan (1-65535)
    -q, --quick         Quick scan (skip content discovery)
    -o, --output DIR    Custom output directory
    -V, --verbose       Show live output from all tools
    -1, --single        Single domain mode (no subdomain enum)
    --debug             Enable debug mode
    --no-color          Disable colored output

${GREEN}MODULES:${NC}
    01 - Intel          ASN, CIDR, Organization discovery
    02 - Subdomains     Subdomain enumeration
    03 - DNS            DNS resolution & analysis
    04 - Ports          Port scanning
    05 - HTTP           HTTP probing & tech detection
    06 - Content        Directory brute-forcing
    07 - JS             JavaScript analysis
    08 - Params         URL & parameter discovery
    09 - Vuln           Vulnerability scanning
    10 - Visual         Screenshots
    11 - Intelligence   Smart analysis & prioritization
    12 - Delta          Change detection (vs previous scans)
    13 - Brain          Auto-pruning, scoring, pattern detection
    14 - Stateful       Authenticated testing with sessions
    15 - Assume         Assumption breaker (headers, methods, etc.)
    16 - Logic          Business logic testing (IDOR, race, privesc)
    17 - Report         Obsidian markdown report generator

${GREEN}EXAMPLES:${NC}
    ./shadow.sh example.com                    # Full scan
    ./shadow.sh -1 www.example.com            # Single domain (no subs enum)
    ./shadow.sh -m 1,2,3 example.com          # Run modules 1,2,3 only
    ./shadow.sh -s 6,10 example.com           # Skip content & visual
    ./shadow.sh -r example.com                # Resume previous scan
    ./shadow.sh -q example.com                # Quick scan

${GREEN}API KEYS (optional):${NC}
    Export these for better results:
    GITHUB_TOKEN, CHAOS_KEY, SHODAN_KEY, SECURITYTRAILS_KEY

EOF
}

# ─────────────────────────────────────────────────────────────────────────────
# ARGUMENT PARSING
# ─────────────────────────────────────────────────────────────────────────────
TARGET=""
OUTPUT_DIR=""
RUN_MODULES=""
SKIP_MODULES=""
RESUME=0
FULL_SCAN=0
QUICK_SCAN=0
SINGLE_MODE=0
DEBUG=0
VERBOSE=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            usage
            exit 0
            ;;
        -v|--version)
            echo "SHADOW RECON v${VERSION}"
            exit 0
            ;;
        -c|--check)
            check_all_tools
            exit $?
            ;;
        -m|--module)
            RUN_MODULES="$2"
            shift 2
            ;;
        -s|--skip)
            SKIP_MODULES="$2"
            shift 2
            ;;
        -r|--resume)
            RESUME=1
            shift
            ;;
        -f|--full)
            FULL_SCAN=1
            export FULL_SCAN
            shift
            ;;
        -q|--quick)
            QUICK_SCAN=1
            shift
            ;;
        -1|--single)
            SINGLE_MODE=1
            export SINGLE_MODE
            shift
            ;;
        -o|--output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -V|--verbose)
            VERBOSE=1
            export VERBOSE
            shift
            ;;
        --debug)
            DEBUG=1
            export DEBUG
            shift
            ;;
        --no-color)
            RED="" GREEN="" YELLOW="" BLUE="" PURPLE="" CYAN="" WHITE="" NC=""
            shift
            ;;
        -*)
            log_error "Unknown option: $1"
            usage
            exit 1
            ;;
        *)
            TARGET="$1"
            shift
            ;;
    esac
done

# ─────────────────────────────────────────────────────────────────────────────
# VALIDATION
# ─────────────────────────────────────────────────────────────────────────────
if [[ -z "$TARGET" ]]; then
    usage
    exit 1
fi

if ! validate_target "$TARGET"; then
    exit 1
fi

# ─────────────────────────────────────────────────────────────────────────────
# SETUP
# ─────────────────────────────────────────────────────────────────────────────
BASE="${OUTPUT_DIR:-${SCRIPT_DIR}/logs/${TARGET}_$(date +%Y%m%d_%H%M%S)}"
LOG_FILE="${BASE}/shadow.log"
export LOG_FILE

# Resume support
if [[ $RESUME -eq 1 ]]; then
    # Find latest scan for this target
    LATEST=$(ls -dt "${SCRIPT_DIR}/logs/${TARGET}"_* 2>/dev/null | head -1)
    if [[ -n "$LATEST" ]] && can_resume "$LATEST"; then
        BASE="$LATEST"
        LOG_FILE="${BASE}/shadow.log"
        log_info "Resuming scan: $BASE"
    else
        log_warn "No previous scan found, starting fresh"
    fi
fi

mkdir -p "$BASE"
touch "$LOG_FILE"

# Initialize state
init_state "$BASE"

# ─────────────────────────────────────────────────────────────────────────────
# BANNER
# ─────────────────────────────────────────────────────────────────────────────
clear
echo -e "${PURPLE}"
cat << 'EOF'
   ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗
   ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║
   ███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║
   ╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║
   ███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝
   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝
EOF
echo -e "${NC}"
echo -e "${CYAN}   SHADOW RECON v${VERSION} - Modular Bug Bounty Framework${NC}"
echo ""

separator
echo -e "${GREEN}${TARGET}${NC} Target: ${WHITE}$TARGET${NC}"
echo -e "${GREEN}${ARROW}${NC} Output: ${WHITE}$BASE${NC}"
echo -e "${GREEN}${ARROW}${NC} Started: ${WHITE}$(date)${NC}"
separator

# Check dependencies
log_info "Checking dependencies..."
if ! check_all_tools; then
    log_warn "Some tools are missing. Scan may be incomplete."
    echo ""
    read -p "Continue anyway? [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# ─────────────────────────────────────────────────────────────────────────────
# MODULE EXECUTION
# ─────────────────────────────────────────────────────────────────────────────
TOTAL_START=$(date +%s)

# Determine which modules to run
declare -a MODULES_TO_RUN

if [[ -n "$RUN_MODULES" ]]; then
    # Run specific modules
    IFS=',' read -ra MODULES_TO_RUN <<< "$RUN_MODULES"
else
    # Run all modules (including new brain modules)
    MODULES_TO_RUN=(01 02 03 04 05 06 07 08 09 10 11 12 13)
    
    # Quick mode - skip heavy modules
    if [[ $QUICK_SCAN -eq 1 ]]; then
        MODULES_TO_RUN=(01 02 03 04 05 08 13)
        log_info "Quick mode: skipping content discovery, visual, and vuln scanning"
    fi
fi

# Remove skipped modules
if [[ -n "$SKIP_MODULES" ]]; then
    IFS=',' read -ra SKIP_ARRAY <<< "$SKIP_MODULES"
    for skip in "${SKIP_ARRAY[@]}"; do
        MODULES_TO_RUN=("${MODULES_TO_RUN[@]/$skip}")
    done
fi

# Execute modules
FAILED_MODULES=()
for mod_num in "${MODULES_TO_RUN[@]}"; do
    # Skip empty entries
    [[ -z "$mod_num" ]] && continue
    
    # Pad module number (remove leading zeros first to avoid octal interpretation)
    mod_num=$(printf "%02d" "$((10#$mod_num))")
    
    module_path="${SCRIPT_DIR}/modules/${mod_num}_*.sh"
    module_file=$(ls $module_path 2>/dev/null | head -1)
    
    if [[ -f "$module_file" ]]; then
        if ! run_module "$module_file" "$TARGET" "$BASE"; then
            FAILED_MODULES+=("$mod_num")
            log_error "Module $mod_num failed"
        fi
        
        # Cleanup after each module (if enabled)
        if [[ "${ENABLE_CLEANUP:-true}" == "true" ]]; then
            source "${SCRIPT_DIR}/utils/cleanup.sh"
            cleanup_temp_files "$BASE" 2>/dev/null
        fi
        
        # Delay between modules
        sleep "${MODULE_DELAY:-2}"
    else
        log_warn "Module $mod_num not found"
    fi
done

# ─────────────────────────────────────────────────────────────────────────────
# FINAL CLEANUP
# ─────────────────────────────────────────────────────────────────────────────
if [[ "${ENABLE_CLEANUP:-true}" == "true" ]]; then
    log_info "Final cleanup..."
    source "${SCRIPT_DIR}/utils/cleanup.sh"
    cleanup_scan "$BASE" "${CLEANUP_AGGRESSIVE:-false}"
fi

# ─────────────────────────────────────────────────────────────────────────────
# FINAL REPORT
# ─────────────────────────────────────────────────────────────────────────────
TOTAL_END=$(date +%s)
TOTAL_DURATION=$((TOTAL_END - TOTAL_START))
TOTAL_MINS=$((TOTAL_DURATION / 60))
TOTAL_SECS=$((TOTAL_DURATION % 60))

echo ""
banner "SHADOW v5 COMPLETE"

separator
echo -e "${CYAN}📊 FINAL STATISTICS${NC}"
separator

# Show all stats
if [[ -f "$BASE/.stats" ]]; then
    while IFS='=' read -r key value; do
        echo -e "  ${GREEN}→${NC} $key: ${WHITE}$value${NC}"
    done < "$BASE/.stats"
fi

separator
echo -e "${CYAN}⏱ Total Duration:${NC} ${TOTAL_MINS}m ${TOTAL_SECS}s"
echo -e "${CYAN}📁 Output:${NC} $BASE"

if [[ ${#FAILED_MODULES[@]} -gt 0 ]]; then
    echo -e "${RED}❌ Failed Modules:${NC} ${FAILED_MODULES[*]}"
fi

separator

# Check for critical findings
if [[ -s "$BASE/vulns/nuclei_critical.txt" ]] || \
   [[ -s "$BASE/vulns/ssrf_confirmed.txt" ]] || \
   [[ -s "$BASE/vulns/lfi_confirmed.txt" ]]; then
    echo ""
    echo -e "${RED}${SKULL}${SKULL}${SKULL} CRITICAL VULNERABILITIES FOUND! ${SKULL}${SKULL}${SKULL}${NC}"
    echo -e "${RED}Check: $BASE/vulns/${NC}"
    echo ""
fi

# Create final summary
{
    echo "═══════════════════════════════════════════════════════════════════"
    echo "SHADOW RECON v${VERSION} - SCAN COMPLETE"
    echo "═══════════════════════════════════════════════════════════════════"
    echo "Target: $TARGET"
    echo "Date: $(date)"
    echo "Duration: ${TOTAL_MINS}m ${TOTAL_SECS}s"
    echo ""
    echo "STATISTICS:"
    cat "$BASE/.stats" 2>/dev/null
    echo ""
    echo "OUTPUT STRUCTURE:"
    find "$BASE" -type d | head -20
    echo ""
    echo "═══════════════════════════════════════════════════════════════════"
} > "$BASE/SCAN_SUMMARY.txt"

log_success "Summary saved to $BASE/SCAN_SUMMARY.txt"

exit 0
