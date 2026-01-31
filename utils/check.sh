#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# SHADOW v5 - Tool & Dependency Checker
# ═══════════════════════════════════════════════════════════════════════════════

# ─────────────────────────────────────────────────────────────────────────────
# CHECK IF TOOL IS ENABLED IN CONFIG
# ─────────────────────────────────────────────────────────────────────────────
is_tool_enabled() {
    local tool="$1"
    # Convert to uppercase and replace hyphens with underscores
    local tool_upper="${tool^^}"
    local var_name="ENABLE_${tool_upper//-/_}"
    local value="${!var_name:-true}"   # Default to true if not set
    
    [[ "$value" == "true" || "$value" == "1" || "$value" == "yes" ]]
}

# ─────────────────────────────────────────────────────────────────────────────
# CHECK SINGLE TOOL (installed + enabled)
# ─────────────────────────────────────────────────────────────────────────────
check_tool() {
    local tool="$1"
    
    # First check if enabled in config
    if ! is_tool_enabled "$tool"; then
        return 1
    fi
    
    # Then check if installed
    if command -v "$tool" &>/dev/null; then
        return 0
    else
        return 1
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# REQUIRE TOOL (check + warn if missing)
# ─────────────────────────────────────────────────────────────────────────────
require_tool() {
    local tool="$1"
    
    # Check if disabled in config
    if ! is_tool_enabled "$tool"; then
        log_debug "$tool is disabled in config"
        return 1
    fi
    
    # Check if installed
    if command -v "$tool" &>/dev/null; then
        return 0
    else
        log_warn "$tool not found, skipping..."
        return 1
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# REQUIRED TOOLS
# ─────────────────────────────────────────────────────────────────────────────
CORE_TOOLS=(
    "subfinder"
    "amass"
    "assetfinder"
    "dnsx"
    "httpx"
    "naabu"
    "nuclei"
    "ffuf"
    "gau"
    "waybackurls"
)

OPTIONAL_TOOLS=(
    "gowitness"
    "aquatone"
    "dalfox"
    "gf"
    "qsreplace"
    "anew"
    "unfurl"
    "hakrawler"
    "katana"
    "subjs"
    "linkfinder"
    "secretfinder"
    "metabigor"
    "asnmap"
    "mapcidr"
    "tlsx"
)

# ─────────────────────────────────────────────────────────────────────────────
# CHECK ALL TOOLS
# ─────────────────────────────────────────────────────────────────────────────
check_all_tools() {
    local missing_core=()
    local missing_optional=()
    local disabled_tools=()
    local found_count=0
    local total_count=${#CORE_TOOLS[@]}
    
    echo ""
    log_info "Checking required tools..."
    separator
    
    for tool in "${CORE_TOOLS[@]}"; do
        if ! is_tool_enabled "$tool"; then
            echo -e "  ${YELLOW}⊘${NC} $tool ${YELLOW}(DISABLED)${NC}"
            disabled_tools+=("$tool")
        elif command -v "$tool" &>/dev/null; then
            echo -e "  ${GREEN}${CHECK}${NC} $tool"
            ((found_count++))
        else
            echo -e "  ${RED}${CROSS}${NC} $tool ${RED}(REQUIRED)${NC}"
            missing_core+=("$tool")
        fi
    done
    
    separator
    echo ""
    log_info "Checking optional tools..."
    separator
    
    for tool in "${OPTIONAL_TOOLS[@]}"; do
        if ! is_tool_enabled "$tool"; then
            echo -e "  ${YELLOW}⊘${NC} $tool ${YELLOW}(disabled)${NC}"
            disabled_tools+=("$tool")
        elif command -v "$tool" &>/dev/null; then
            echo -e "  ${GREEN}${CHECK}${NC} $tool"
        else
            echo -e "  ${YELLOW}○${NC} $tool ${YELLOW}(optional)${NC}"
            missing_optional+=("$tool")
        fi
    done
    
    separator
    echo ""
    
    if [[ ${#disabled_tools[@]} -gt 0 ]]; then
        log_info "${#disabled_tools[@]} tools disabled in config"
    fi
    
    if [[ ${#missing_core[@]} -gt 0 ]]; then
        log_error "Missing ${#missing_core[@]} required tools: ${missing_core[*]}"
        log_info "Run: ./install_tools.sh to install missing tools"
        return 1
    else
        log_success "All required tools are installed!"
        if [[ ${#missing_optional[@]} -gt 0 ]]; then
            log_warn "${#missing_optional[@]} optional tools missing"
        fi
        return 0
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# VERSION CHECK
# ─────────────────────────────────────────────────────────────────────────────
get_tool_version() {
    local tool="$1"
    
    case "$tool" in
        subfinder|httpx|nuclei|naabu|dnsx|katana)
            $tool -version 2>&1 | head -1
            ;;
        amass)
            $tool -version 2>&1 | head -1
            ;;
        ffuf)
            $tool -V 2>&1 | head -1
            ;;
        *)
            echo "unknown"
            ;;
    esac
}

# ─────────────────────────────────────────────────────────────────────────────
# SYSTEM CHECKS
# ─────────────────────────────────────────────────────────────────────────────
check_system() {
    log_info "System Check"
    separator
    
    # Check Go
    if check_tool "go"; then
        echo -e "  ${GREEN}${CHECK}${NC} Go: $(go version | awk '{print $3}')"
    else
        echo -e "  ${YELLOW}○${NC} Go: not installed (needed for tool installation)"
    fi
    
    # Check Python
    if check_tool "python3"; then
        echo -e "  ${GREEN}${CHECK}${NC} Python: $(python3 --version 2>&1)"
    else
        echo -e "  ${YELLOW}○${NC} Python3: not installed"
    fi
    
    # Check disk space
    local free_space=$(df -h . | awk 'NR==2 {print $4}')
    echo -e "  ${CYAN}→${NC} Free disk space: $free_space"
    
    # Check RAM
    local total_ram=$(free -h | awk '/^Mem:/ {print $2}')
    local free_ram=$(free -h | awk '/^Mem:/ {print $4}')
    echo -e "  ${CYAN}→${NC} RAM: $free_ram free / $total_ram total"
    
    # Check internet
    if ping -c 1 google.com &>/dev/null; then
        echo -e "  ${GREEN}${CHECK}${NC} Internet: Connected"
    else
        echo -e "  ${RED}${CROSS}${NC} Internet: Not connected"
    fi
    
    separator
}

# ─────────────────────────────────────────────────────────────────────────────
# NUCLEI TEMPLATES CHECK
# ─────────────────────────────────────────────────────────────────────────────
check_nuclei_templates() {
    local templates_path="${HOME}/nuclei-templates"
    
    if [[ -d "$templates_path" ]]; then
        local count=$(find "$templates_path" -name "*.yaml" | wc -l)
        log_success "Nuclei templates: $count templates found"
        return 0
    else
        log_warn "Nuclei templates not found. Run: nuclei -update-templates"
        return 1
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# WORDLISTS CHECK
# ─────────────────────────────────────────────────────────────────────────────
check_wordlists() {
    local wordlist_dir="${SCRIPT_DIR}/wordlists"
    
    if [[ -d "$wordlist_dir" ]]; then
        local count=$(find "$wordlist_dir" -type f | wc -l)
        log_success "Wordlists: $count files found"
        return 0
    else
        log_warn "Wordlists directory not found"
        return 1
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# VALIDATE INPUT
# ─────────────────────────────────────────────────────────────────────────────
validate_target() {
    local target="$1"
    
    # Check if empty
    if [[ -z "$target" ]]; then
        log_error "Target cannot be empty"
        return 1
    fi
    
    # Check if it's a valid domain
    if [[ "$target" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$ ]]; then
        return 0
    fi
    
    # Check if it's an IP
    if [[ "$target" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        return 0
    fi
    
    # Check if it's a CIDR
    if [[ "$target" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$ ]]; then
        return 0
    fi
    
    log_error "Invalid target format: $target"
    return 1
}

# ─────────────────────────────────────────────────────────────────────────────
# ROOT CHECK
# ─────────────────────────────────────────────────────────────────────────────
check_root() {
    if [[ $EUID -eq 0 ]]; then
        log_warn "Running as root (some tools may not work correctly)"
        return 0
    fi
    return 1
}

# ─────────────────────────────────────────────────────────────────────────────
# QUICK CHECK (for module use)
# ─────────────────────────────────────────────────────────────────────────────
require_tool() {
    local tool="$1"
    if ! check_tool "$tool"; then
        log_error "Required tool not found: $tool"
        return 1
    fi
    return 0
}

require_file() {
    local file="$1"
    if [[ ! -f "$file" ]]; then
        log_error "Required file not found: $file"
        return 1
    fi
    return 0
}
