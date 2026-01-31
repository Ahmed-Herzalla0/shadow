#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# SHADOW v5 - Logging Utilities
# ═══════════════════════════════════════════════════════════════════════════════

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

# Symbols
CHECK="✓"
CROSS="✗"
ARROW="→"
STAR="★"
FIRE="🔥"
SKULL="💀"
TARGET="🎯"

# ─────────────────────────────────────────────────────────────────────────────
# BANNER
# ─────────────────────────────────────────────────────────────────────────────
banner() {
    local msg="$1"
    echo ""
    echo -e "${PURPLE}╔══════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${PURPLE}║${NC} ${CYAN}${STAR} ${msg}${NC}"
    echo -e "${PURPLE}╚══════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# ─────────────────────────────────────────────────────────────────────────────
# LOG FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────
log_info() {
    echo -e "${BLUE}[INFO]${NC} ${1}"
    [[ -n "${LOG_FILE:-}" ]] && echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] ${1}" >> "$LOG_FILE" 2>/dev/null
}

log_success() {
    echo -e "${GREEN}[${CHECK}]${NC} ${1}"
    [[ -n "${LOG_FILE:-}" ]] && echo "[$(date '+%Y-%m-%d %H:%M:%S')] [SUCCESS] ${1}" >> "$LOG_FILE" 2>/dev/null
}

log_warn() {
    echo -e "${YELLOW}[!]${NC} ${1}"
    [[ -n "${LOG_FILE:-}" ]] && echo "[$(date '+%Y-%m-%d %H:%M:%S')] [WARN] ${1}" >> "$LOG_FILE" 2>/dev/null
}

log_error() {
    echo -e "${RED}[${CROSS}]${NC} ${1}"
    [[ -n "${LOG_FILE:-}" ]] && echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] ${1}" >> "$LOG_FILE" 2>/dev/null
}

log_debug() {
    if [[ "${DEBUG:-0}" == "1" ]]; then
        echo -e "${WHITE}[DEBUG]${NC} ${1}"
        [[ -n "${LOG_FILE:-}" ]] && echo "[$(date '+%Y-%m-%d %H:%M:%S')] [DEBUG] ${1}" >> "$LOG_FILE" 2>/dev/null
    fi
}

log_critical() {
    echo -e "${RED}${SKULL} [CRITICAL]${NC} ${1}"
    [[ -n "${LOG_FILE:-}" ]] && echo "[$(date '+%Y-%m-%d %H:%M:%S')] [CRITICAL] ${1}" >> "$LOG_FILE" 2>/dev/null
}

log_found() {
    echo -e "${GREEN}${FIRE} [FOUND]${NC} ${1}"
    [[ -n "${LOG_FILE:-}" ]] && echo "[$(date '+%Y-%m-%d %H:%M:%S')] [FOUND] ${1}" >> "$LOG_FILE" 2>/dev/null
}

# ─────────────────────────────────────────────────────────────────────────────
# PROGRESS
# ─────────────────────────────────────────────────────────────────────────────
progress() {
    local current=$1
    local total=$2
    local label="${3:-Progress}"
    local percent=$((current * 100 / total))
    local filled=$((percent / 2))
    local empty=$((50 - filled))
    
    printf "\r${CYAN}[${label}]${NC} ["
    printf "%${filled}s" | tr ' ' '█'
    printf "%${empty}s" | tr ' ' '░'
    printf "] ${percent}%% (${current}/${total})"
    
    if [[ $current -eq $total ]]; then
        echo ""
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# STATS
# ─────────────────────────────────────────────────────────────────────────────
show_stats() {
    local label="$1"
    local file="$2"
    local count=0
    
    if [[ -f "$file" ]]; then
        count=$(wc -l < "$file" 2>/dev/null || echo "0")
    fi
    
    echo -e "${CYAN}${ARROW}${NC} ${label}: ${GREEN}${count}${NC}"
}

# ─────────────────────────────────────────────────────────────────────────────
# SEPARATOR
# ─────────────────────────────────────────────────────────────────────────────
separator() {
    echo -e "${PURPLE}──────────────────────────────────────────────────────────────────────${NC}"
}

# ─────────────────────────────────────────────────────────────────────────────
# TIMER
# ─────────────────────────────────────────────────────────────────────────────
timer_start() {
    TIMER_START=$(date +%s)
}

timer_end() {
    local end=$(date +%s)
    local duration=$((end - TIMER_START))
    local mins=$((duration / 60))
    local secs=$((duration % 60))
    echo -e "${CYAN}⏱ Duration:${NC} ${mins}m ${secs}s"
}

# ─────────────────────────────────────────────────────────────────────────────
# RUN TOOL (with verbose support)
# ─────────────────────────────────────────────────────────────────────────────
# Usage: run_tool "command with args" "output_file"
# If VERBOSE=1, shows live output. Otherwise, suppresses errors.
run_tool() {
    local cmd="$1"
    local output_file="${2:-}"
    
    if [[ "${VERBOSE:-0}" == "1" ]]; then
        # Show live output
        if [[ -n "$output_file" ]]; then
            eval "$cmd" 2>&1 | tee "$output_file"
        else
            eval "$cmd" 2>&1
        fi
    else
        # Silent mode
        if [[ -n "$output_file" ]]; then
            eval "$cmd" > "$output_file" 2>/dev/null
        else
            eval "$cmd" 2>/dev/null
        fi
    fi
}

# Usage: run_tool_bg "command" "output_file"
# For background jobs with verbose support
run_tool_bg() {
    local cmd="$1"
    local output_file="${2:-}"
    
    if [[ "${VERBOSE:-0}" == "1" ]]; then
        if [[ -n "$output_file" ]]; then
            eval "$cmd" 2>&1 | tee "$output_file" &
        else
            eval "$cmd" 2>&1 &
        fi
    else
        if [[ -n "$output_file" ]]; then
            eval "$cmd" > "$output_file" 2>/dev/null &
        else
            eval "$cmd" 2>/dev/null &
        fi
    fi
}

# Get stderr redirect based on verbose mode
get_stderr() {
    if [[ "${VERBOSE:-0}" == "1" ]]; then
        echo ""
    else
        echo "2>/dev/null"
    fi
}

# Get silent flag based on verbose mode
get_silent_flag() {
    if [[ "${VERBOSE:-0}" == "1" ]]; then
        echo ""
    else
        echo "-silent"
    fi
}
