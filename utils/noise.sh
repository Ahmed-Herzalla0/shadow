#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# SHADOW v5 - Noise Detection & Auto-Pause System
# ═══════════════════════════════════════════════════════════════════════════════
# Detects when server is blocking/rate-limiting and auto-pauses
# ═══════════════════════════════════════════════════════════════════════════════

# Configuration
NOISE_PAUSE_TIME="${NOISE_PAUSE_TIME:-60}"          # Seconds to pause when noise detected
NOISE_MAX_403="${NOISE_MAX_403:-10}"                # Max 403s before pause
NOISE_MAX_429="${NOISE_MAX_429:-3}"                 # Max 429s before pause (rate limit)
NOISE_MAX_TIMEOUT="${NOISE_MAX_TIMEOUT:-5}"         # Max timeouts before pause
NOISE_CHECK_INTERVAL="${NOISE_CHECK_INTERVAL:-20}"  # Check every N requests

# Counters
declare -g NOISE_403_COUNT=0
declare -g NOISE_429_COUNT=0
declare -g NOISE_TIMEOUT_COUNT=0
declare -g NOISE_REQUEST_COUNT=0
declare -g NOISE_PAUSED=0

# ─────────────────────────────────────────────────────────────────────────────
# Initialize noise detection
# ─────────────────────────────────────────────────────────────────────────────
noise_init() {
    NOISE_403_COUNT=0
    NOISE_429_COUNT=0
    NOISE_TIMEOUT_COUNT=0
    NOISE_REQUEST_COUNT=0
    NOISE_PAUSED=0
    
    log_debug "Noise detection initialized (pause: ${NOISE_PAUSE_TIME}s)"
}

# ─────────────────────────────────────────────────────────────────────────────
# Check HTTP response for noise indicators
# Usage: noise_check_response <http_code> <url>
# ─────────────────────────────────────────────────────────────────────────────
noise_check_response() {
    local http_code="$1"
    local url="${2:-unknown}"
    
    ((NOISE_REQUEST_COUNT++))
    
    case "$http_code" in
        403)
            ((NOISE_403_COUNT++))
            log_debug "403 Forbidden detected ($NOISE_403_COUNT/$NOISE_MAX_403): $url"
            ;;
        429)
            ((NOISE_429_COUNT++))
            log_warn "⚠️  Rate limit (429) detected ($NOISE_429_COUNT/$NOISE_MAX_429): $url"
            ;;
        0|000)
            ((NOISE_TIMEOUT_COUNT++))
            log_debug "Timeout detected ($NOISE_TIMEOUT_COUNT/$NOISE_MAX_TIMEOUT): $url"
            ;;
        503)
            # Service unavailable - likely WAF blocking
            ((NOISE_403_COUNT++))
            log_warn "⚠️  Service unavailable (503) - possible WAF: $url"
            ;;
    esac
    
    # Check if we need to pause
    noise_should_pause && noise_auto_pause
}

# ─────────────────────────────────────────────────────────────────────────────
# Check if we should pause
# ─────────────────────────────────────────────────────────────────────────────
noise_should_pause() {
    if [[ $NOISE_429_COUNT -ge $NOISE_MAX_429 ]]; then
        return 0
    fi
    
    if [[ $NOISE_403_COUNT -ge $NOISE_MAX_403 ]]; then
        return 0
    fi
    
    if [[ $NOISE_TIMEOUT_COUNT -ge $NOISE_MAX_TIMEOUT ]]; then
        return 0
    fi
    
    return 1
}

# ─────────────────────────────────────────────────────────────────────────────
# Auto pause when noise detected
# ─────────────────────────────────────────────────────────────────────────────
noise_auto_pause() {
    local reason=""
    
    if [[ $NOISE_429_COUNT -ge $NOISE_MAX_429 ]]; then
        reason="Rate Limit (429)"
    elif [[ $NOISE_403_COUNT -ge $NOISE_MAX_403 ]]; then
        reason="Blocked (403)"
    elif [[ $NOISE_TIMEOUT_COUNT -ge $NOISE_MAX_TIMEOUT ]]; then
        reason="Timeouts"
    fi
    
    NOISE_PAUSED=1
    
    echo ""
    log_warn "╔═══════════════════════════════════════════════════════════════╗"
    log_warn "║  🛑 NOISE DETECTED - AUTO PAUSE                               ║"
    log_warn "╠═══════════════════════════════════════════════════════════════╣"
    log_warn "║  Reason: $reason"
    log_warn "║  Pausing for: ${NOISE_PAUSE_TIME} seconds..."
    log_warn "║  Stats: 403s=$NOISE_403_COUNT | 429s=$NOISE_429_COUNT | Timeouts=$NOISE_TIMEOUT_COUNT"
    log_warn "╚═══════════════════════════════════════════════════════════════╝"
    echo ""
    
    # Visual countdown
    for ((i=NOISE_PAUSE_TIME; i>0; i--)); do
        printf "\r  ⏳ Resuming in %3d seconds..." "$i"
        sleep 1
    done
    printf "\r  ✅ Resuming scan...                    \n"
    echo ""
    
    # Reset counters after pause
    noise_reset_counters
    
    NOISE_PAUSED=0
}

# ─────────────────────────────────────────────────────────────────────────────
# Reset counters
# ─────────────────────────────────────────────────────────────────────────────
noise_reset_counters() {
    NOISE_403_COUNT=0
    NOISE_429_COUNT=0
    NOISE_TIMEOUT_COUNT=0
    NOISE_REQUEST_COUNT=0
}

# ─────────────────────────────────────────────────────────────────────────────
# Smart request wrapper with noise detection
# Usage: noise_curl <url> [curl_options...]
# Returns: response body, sets NOISE_LAST_CODE
# ─────────────────────────────────────────────────────────────────────────────
noise_curl() {
    local url="$1"
    shift
    local extra_opts="$@"
    
    local response
    local http_code
    
    # Make request and capture both body and status code
    response=$(curl -s -w "\n%{http_code}" --max-time 10 $extra_opts "$url" 2>/dev/null)
    http_code=$(echo "$response" | tail -1)
    response=$(echo "$response" | sed '$d')
    
    # Store for external use
    export NOISE_LAST_CODE="$http_code"
    
    # Check for noise
    noise_check_response "$http_code" "$url"
    
    echo "$response"
}

# ─────────────────────────────────────────────────────────────────────────────
# Wrapper for running tools with noise detection
# Usage: noise_run_tool <tool_command> <output_file>
# Monitors output for rate limiting signs
# ─────────────────────────────────────────────────────────────────────────────
noise_run_tool() {
    local cmd="$1"
    local output_file="${2:-/dev/null}"
    local temp_file=$(mktemp)
    
    noise_reset_counters
    
    # Run command and monitor output
    eval "$cmd" 2>&1 | while IFS= read -r line; do
        echo "$line" >> "$temp_file"
        
        # Check for common rate limit indicators in output
        if echo "$line" | grep -qiE "429|rate.?limit|too.?many|blocked|forbidden|banned"; then
            ((NOISE_429_COUNT++))
            if noise_should_pause; then
                noise_auto_pause
            fi
        fi
        
        # Check for WAF indicators
        if echo "$line" | grep -qiE "cloudflare|akamai|imperva|waf|captcha|challenge"; then
            log_warn "⚠️  WAF detected in response"
            ((NOISE_403_COUNT++))
        fi
    done
    
    # Move temp output to final destination
    [[ -f "$temp_file" ]] && mv "$temp_file" "$output_file"
}

# ─────────────────────────────────────────────────────────────────────────────
# Get current noise status
# ─────────────────────────────────────────────────────────────────────────────
noise_status() {
    echo "Noise Status: 403s=$NOISE_403_COUNT | 429s=$NOISE_429_COUNT | Timeouts=$NOISE_TIMEOUT_COUNT | Requests=$NOISE_REQUEST_COUNT"
}

# ─────────────────────────────────────────────────────────────────────────────
# Manual pause (for user interruption)
# ─────────────────────────────────────────────────────────────────────────────
noise_manual_pause() {
    local pause_time="${1:-$NOISE_PAUSE_TIME}"
    
    log_info "Manual pause for ${pause_time} seconds..."
    sleep "$pause_time"
    log_info "Resuming..."
}
