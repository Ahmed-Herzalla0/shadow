#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# SHADOW v5 - State Management
# ═══════════════════════════════════════════════════════════════════════════════

STATE_FILE=""
LOCK_DIR=""

# ─────────────────────────────────────────────────────────────────────────────
# INITIALIZE STATE
# ─────────────────────────────────────────────────────────────────────────────
init_state() {
    local base="$1"
    STATE_FILE="${base}/.shadow_state"
    LOCK_DIR="${base}/.locks"
    
    mkdir -p "$LOCK_DIR"
    
    if [[ ! -f "$STATE_FILE" ]]; then
        cat > "$STATE_FILE" << EOF
{
    "started": "$(date -Iseconds)",
    "status": "running",
    "current_module": "",
    "completed_modules": [],
    "failed_modules": [],
    "stats": {}
}
EOF
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# MODULE STATE
# ─────────────────────────────────────────────────────────────────────────────
mark_module_start() {
    local module="$1"
    local lock_file="${LOCK_DIR}/${module}.lock"
    
    echo "$(date -Iseconds)" > "$lock_file"
    log_info "Starting module: $module"
}

mark_module_done() {
    local module="$1"
    local lock_file="${LOCK_DIR}/${module}.lock"
    local done_file="${LOCK_DIR}/${module}.done"
    
    mv "$lock_file" "$done_file" 2>/dev/null
    log_success "Completed module: $module"
}

mark_module_failed() {
    local module="$1"
    local error="$2"
    local lock_file="${LOCK_DIR}/${module}.lock"
    local fail_file="${LOCK_DIR}/${module}.failed"
    
    echo "$error" > "$fail_file"
    rm -f "$lock_file" 2>/dev/null
    log_error "Failed module: $module - $error"
}

is_module_done() {
    local module="$1"
    local done_file="${LOCK_DIR}/${module}.done"
    
    [[ -f "$done_file" ]]
}

is_module_failed() {
    local module="$1"
    local fail_file="${LOCK_DIR}/${module}.failed"
    
    [[ -f "$fail_file" ]]
}

# ─────────────────────────────────────────────────────────────────────────────
# RUN MODULE WITH STATE
# ─────────────────────────────────────────────────────────────────────────────
run_module() {
    local module_path="$1"
    local target="$2"
    local base="$3"
    
    local module_name=$(basename "$module_path" .sh)
    
    # Check if already completed (for resume)
    if is_module_done "$module_name"; then
        log_info "Skipping $module_name (already completed)"
        return 0
    fi
    
    # Check if previously failed
    if is_module_failed "$module_name"; then
        log_warn "Retrying previously failed module: $module_name"
    fi
    
    # Source and run the module
    source "$module_path"
    
    mark_module_start "$module_name"
    timer_start
    
    if run "$target" "$base"; then
        mark_module_done "$module_name"
        timer_end
        return 0
    else
        mark_module_failed "$module_name" "Execution failed"
        timer_end
        return 1
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# RESUME
# ─────────────────────────────────────────────────────────────────────────────
can_resume() {
    local base="$1"
    [[ -f "${base}/.shadow_state" ]]
}

get_last_module() {
    local base="$1"
    
    for done_file in "${base}/.locks"/*.done; do
        if [[ -f "$done_file" ]]; then
            basename "$done_file" .done
        fi
    done | sort | tail -1
}

# ─────────────────────────────────────────────────────────────────────────────
# CLEANUP
# ─────────────────────────────────────────────────────────────────────────────
cleanup_state() {
    local base="$1"
    rm -rf "${base}/.locks"
    rm -f "${base}/.shadow_state"
}

# ─────────────────────────────────────────────────────────────────────────────
# STATS TRACKING
# ─────────────────────────────────────────────────────────────────────────────
save_stat() {
    local key="$1"
    local value="$2"
    local base="$3"
    
    echo "${key}=${value}" >> "${base}/.stats"
}

get_stat() {
    local key="$1"
    local base="$2"
    
    grep "^${key}=" "${base}/.stats" 2>/dev/null | cut -d= -f2
}

# ─────────────────────────────────────────────────────────────────────────────
# CHECKPOINT
# ─────────────────────────────────────────────────────────────────────────────
create_checkpoint() {
    local base="$1"
    local name="$2"
    local checkpoint_dir="${base}/checkpoints"
    
    mkdir -p "$checkpoint_dir"
    
    tar -czf "${checkpoint_dir}/${name}_$(date +%Y%m%d_%H%M%S).tar.gz" \
        -C "$base" \
        --exclude="checkpoints" \
        . 2>/dev/null
        
    log_info "Checkpoint created: $name"
}

restore_checkpoint() {
    local base="$1"
    local checkpoint="$2"
    
    if [[ -f "$checkpoint" ]]; then
        tar -xzf "$checkpoint" -C "$base"
        log_success "Restored checkpoint: $checkpoint"
        return 0
    else
        log_error "Checkpoint not found: $checkpoint"
        return 1
    fi
}
