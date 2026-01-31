#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# SHADOW v5 - Deduplication Utilities
# ═══════════════════════════════════════════════════════════════════════════════

# ─────────────────────────────────────────────────────────────────────────────
# BASIC DEDUPLICATION
# ─────────────────────────────────────────────────────────────────────────────
dedupe() {
    local file="$1"
    
    if [[ ! -f "$file" ]]; then
        return 1
    fi
    
    local before=$(wc -l < "$file")
    sort -u "$file" -o "$file"
    local after=$(wc -l < "$file")
    local removed=$((before - after))
    
    if [[ $removed -gt 0 ]]; then
        log_debug "Deduped $file: removed $removed duplicates"
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# MERGE AND DEDUPE
# ─────────────────────────────────────────────────────────────────────────────
merge_dedupe() {
    local output="$1"
    shift
    local inputs=("$@")
    
    cat "${inputs[@]}" 2>/dev/null | sort -u > "$output"
    
    local count=$(wc -l < "$output")
    log_info "Merged ${#inputs[@]} files → $count unique lines"
}

# ─────────────────────────────────────────────────────────────────────────────
# ANEW-LIKE FUNCTION
# ─────────────────────────────────────────────────────────────────────────────
add_new() {
    local file="$1"
    
    if [[ ! -f "$file" ]]; then
        cat > "$file"
        return
    fi
    
    local temp=$(mktemp)
    cat > "$temp"
    
    while IFS= read -r line; do
        if ! grep -Fxq "$line" "$file"; then
            echo "$line" >> "$file"
            echo "$line"  # Output new items
        fi
    done < "$temp"
    
    rm -f "$temp"
}

# ─────────────────────────────────────────────────────────────────────────────
# DEDUPE URLS (normalize first)
# ─────────────────────────────────────────────────────────────────────────────
dedupe_urls() {
    local file="$1"
    
    if [[ ! -f "$file" ]]; then
        return 1
    fi
    
    local temp=$(mktemp)
    
    # Normalize URLs: remove trailing slashes, lowercase, sort
    cat "$file" | \
        sed 's:/*$::' | \
        tr '[:upper:]' '[:lower:]' | \
        sort -u > "$temp"
    
    mv "$temp" "$file"
}

# ─────────────────────────────────────────────────────────────────────────────
# DEDUPE DOMAINS
# ─────────────────────────────────────────────────────────────────────────────
dedupe_domains() {
    local file="$1"
    
    if [[ ! -f "$file" ]]; then
        return 1
    fi
    
    # Remove wildcards, lowercase, sort unique
    sed 's/^\*\.//' "$file" | \
        tr '[:upper:]' '[:lower:]' | \
        sort -u -o "$file"
}

# ─────────────────────────────────────────────────────────────────────────────
# FILTER OUT-OF-SCOPE
# ─────────────────────────────────────────────────────────────────────────────
filter_scope() {
    local file="$1"
    local scope_file="$2"
    
    if [[ ! -f "$scope_file" ]]; then
        log_warn "No scope file provided, skipping filter"
        return
    fi
    
    local temp=$(mktemp)
    
    while IFS= read -r domain; do
        if grep -qE "$(cat "$scope_file")" <<< "$domain"; then
            echo "$domain"
        fi
    done < "$file" > "$temp"
    
    mv "$temp" "$file"
}

# ─────────────────────────────────────────────────────────────────────────────
# FILTER SCOPE USING CONFIG ARRAYS (INSCOPE/OUTSCOPE)
# ─────────────────────────────────────────────────────────────────────────────
filter_scope_arrays() {
    local file="$1"

    if [[ ! -f "$file" ]]; then
        return 1
    fi

    local temp
    temp=$(mktemp)

    # If no inscope patterns are defined, allow all by default
    local has_inscope=0
    if [[ ${#INSCOPE_PATTERNS[@]} -gt 0 ]]; then
        has_inscope=1
    fi

    while IFS= read -r line; do
        [[ -z "$line" ]] && continue

        local in_scope=0
        local out_scope=0

        if [[ $has_inscope -eq 0 ]]; then
            in_scope=1
        else
            for pattern in "${INSCOPE_PATTERNS[@]}"; do
                [[ -z "$pattern" ]] && continue
                if [[ "$line" =~ $pattern ]]; then
                    in_scope=1
                    break
                fi
            done
        fi

        for pattern in "${OUTSCOPE_PATTERNS[@]}"; do
            [[ -z "$pattern" ]] && continue
            if [[ "$line" =~ $pattern ]]; then
                out_scope=1
                break
            fi
        done

        if [[ $in_scope -eq 1 && $out_scope -eq 0 ]]; then
            echo "$line" >> "$temp"
        fi
    done < "$file"

    mv "$temp" "$file"
}

# ─────────────────────────────────────────────────────────────────────────────
# FILTER URLs BY HOST USING SCOPE ARRAYS
# ─────────────────────────────────────────────────────────────────────────────
filter_scope_urls() {
    local file="$1"

    if [[ ! -f "$file" ]]; then
        return 1
    fi

    local temp
    temp=$(mktemp)

    local has_inscope=0
    if [[ ${#INSCOPE_PATTERNS[@]} -gt 0 ]]; then
        has_inscope=1
    fi

    while IFS= read -r url; do
        [[ -z "$url" ]] && continue

        local host
        host=$(echo "$url" | awk -F/ '{print $3}')
        [[ -z "$host" ]] && continue

        local in_scope=0
        local out_scope=0

        if [[ $has_inscope -eq 0 ]]; then
            in_scope=1
        else
            for pattern in "${INSCOPE_PATTERNS[@]}"; do
                [[ -z "$pattern" ]] && continue
                if [[ "$host" =~ $pattern ]]; then
                    in_scope=1
                    break
                fi
            done
        fi

        for pattern in "${OUTSCOPE_PATTERNS[@]}"; do
            [[ -z "$pattern" ]] && continue
            if [[ "$host" =~ $pattern ]]; then
                out_scope=1
                break
            fi
        done

        if [[ $in_scope -eq 1 && $out_scope -eq 0 ]]; then
            echo "$url" >> "$temp"
        fi
    done < "$file"

    mv "$temp" "$file"
}

# ─────────────────────────────────────────────────────────────────────────────
# REMOVE KNOWN BAD
# ─────────────────────────────────────────────────────────────────────────────
remove_known_bad() {
    local file="$1"
    
    # Common bad patterns to remove
    local bad_patterns=(
        "cloudflare.com"
        "cloudfront.net"
        "googleapis.com"
        "amazonaws.com"
        "azurewebsites.net"
        "github.com"
        "github.io"
        "facebook.com"
        "google.com"
        "twitter.com"
    )
    
    local temp=$(mktemp)
    
    cp "$file" "$temp"
    
    for pattern in "${bad_patterns[@]}"; do
        grep -v "$pattern" "$temp" > "${temp}.new"
        mv "${temp}.new" "$temp"
    done
    
    mv "$temp" "$file"
}

# ─────────────────────────────────────────────────────────────────────────────
# SMART MERGE (with priority)
# ─────────────────────────────────────────────────────────────────────────────
smart_merge() {
    local output="$1"
    shift
    
    local temp=$(mktemp)
    
    for input in "$@"; do
        if [[ -f "$input" ]]; then
            cat "$input" >> "$temp"
        fi
    done
    
    sort -u "$temp" -o "$output"
    rm -f "$temp"
    
    log_info "Smart merged → $(wc -l < "$output") unique entries"
}

# ─────────────────────────────────────────────────────────────────────────────
# DIFF FILES
# ─────────────────────────────────────────────────────────────────────────────
diff_files() {
    local file1="$1"
    local file2="$2"
    local output="$3"
    
    # Get lines in file1 not in file2
    comm -23 <(sort "$file1") <(sort "$file2") > "$output"
    
    log_info "Diff: $(wc -l < "$output") unique to first file"
}

# ─────────────────────────────────────────────────────────────────────────────
# COUNT UNIQUE
# ─────────────────────────────────────────────────────────────────────────────
count_unique() {
    local file="$1"
    
    if [[ -f "$file" ]]; then
        sort -u "$file" | wc -l
    else
        echo "0"
    fi
}
