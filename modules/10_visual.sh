#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# SHADOW v5 - Module 10: Visual Reconnaissance
# ═══════════════════════════════════════════════════════════════════════════════
# Screenshots and visual analysis of targets
# ═══════════════════════════════════════════════════════════════════════════════

MODULE="10_VISUAL"

run() {
    local target="$1"
    local base="$2"
    
    banner "📸 VISUAL RECON → $target"
    
    mkdir -p "$base/screenshots"
    
    local http_file="$base/http/alive.txt"
    
    # Single domain mode - create http input file if missing
    if [[ ! -s "$http_file" ]] && [[ "${SINGLE_MODE:-0}" == "1" ]]; then
        log_info "Single domain mode - taking screenshots of $target"
        mkdir -p "$base/http"
        echo "https://$target" > "$http_file"
        echo "http://$target" >> "$http_file"
    fi
    
    if [[ ! -s "$http_file" ]]; then
        log_error "No HTTP hosts found"
        return 1
    fi
    
    local total_hosts=$(wc -l < "$http_file")
    log_info "Taking screenshots of $total_hosts hosts..."
    
    # ─────────────────────────────────────────────────────────────────────────
    # Gowitness
    # ─────────────────────────────────────────────────────────────────────────
    if check_tool "gowitness"; then
        log_info "Running Gowitness..."
        
        gowitness file -f "$http_file" \
                  --screenshot-path "$base/screenshots/gowitness" \
                  --threads 10 \
                  --timeout 20 \
                  --delay 2 2>/dev/null
        
        # Generate report
        if [[ -d "$base/screenshots/gowitness" ]]; then
            gowitness report generate \
                      --screenshot-path "$base/screenshots/gowitness" \
                      -n "$base/screenshots/gowitness_report.html" 2>/dev/null
        fi
        
        log_success "Gowitness complete"
    fi
    
    # ─────────────────────────────────────────────────────────────────────────
    # Aquatone (alternative)
    # ─────────────────────────────────────────────────────────────────────────
    if check_tool "aquatone" && [[ ! -d "$base/screenshots/gowitness" ]]; then
        log_info "Running Aquatone..."
        
        cat "$http_file" | aquatone \
            -out "$base/screenshots/aquatone" \
            -threads 10 \
            -timeout 20000 \
            -screenshot-timeout 30000 2>/dev/null
        
        log_success "Aquatone complete"
    fi
    
    # ─────────────────────────────────────────────────────────────────────────
    # Eyeballer (ML-based analysis)
    # ─────────────────────────────────────────────────────────────────────────
    if check_tool "eyeballer"; then
        log_info "Running Eyeballer for ML analysis..."
        
        local screenshot_dir="$base/screenshots/gowitness"
        [[ ! -d "$screenshot_dir" ]] && screenshot_dir="$base/screenshots/aquatone/screenshots"
        
        if [[ -d "$screenshot_dir" ]]; then
            eyeballer --screenshot-dir "$screenshot_dir" \
                      --output "$base/screenshots/eyeballer_results.csv" 2>/dev/null
        fi
    fi
    
    # ─────────────────────────────────────────────────────────────────────────
    # Interesting Screenshots Analysis
    # ─────────────────────────────────────────────────────────────────────────
    log_info "Analyzing screenshots..."
    
    # Get interesting hosts from httpx for prioritization
    if [[ -s "$base/http/interesting_titles.txt" ]]; then
        log_info "Interesting hosts based on titles:"
        head -20 "$base/http/interesting_titles.txt"
    fi
    
    # ─────────────────────────────────────────────────────────────────────────
    # Create HTML Gallery
    # ─────────────────────────────────────────────────────────────────────────
    log_info "Creating screenshot gallery..."
    
    local gallery_file="$base/screenshots/gallery.html"
    
    cat > "$gallery_file" << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>SHADOW v5 - Screenshot Gallery</title>
    <style>
        body { 
            background: #1a1a2e; 
            color: #eee; 
            font-family: 'Courier New', monospace;
            padding: 20px;
        }
        h1 { color: #00ff88; text-align: center; }
        .gallery { 
            display: grid; 
            grid-template-columns: repeat(auto-fill, minmax(400px, 1fr));
            gap: 20px;
            padding: 20px;
        }
        .item { 
            background: #16213e; 
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 4px 15px rgba(0,0,0,0.3);
        }
        .item img { 
            width: 100%; 
            height: 250px;
            object-fit: cover;
            cursor: pointer;
            transition: transform 0.3s;
        }
        .item img:hover { transform: scale(1.05); }
        .item .url { 
            padding: 10px;
            font-size: 12px;
            word-break: break-all;
            color: #00ff88;
        }
        .filter { 
            text-align: center; 
            margin: 20px;
        }
        .filter input {
            padding: 10px;
            width: 50%;
            background: #16213e;
            border: 1px solid #00ff88;
            color: #fff;
            border-radius: 5px;
        }
        .stats { text-align: center; color: #888; }
    </style>
</head>
<body>
    <h1>🔍 SHADOW v5 - Visual Recon</h1>
    <div class="filter">
        <input type="text" id="search" placeholder="Filter URLs..." onkeyup="filterGallery()">
    </div>
    <div class="stats" id="stats"></div>
    <div class="gallery" id="gallery">
EOF
    
    # Add screenshots
    local screenshot_count=0
    for dir in "$base/screenshots/gowitness" "$base/screenshots/aquatone/screenshots"; do
        if [[ -d "$dir" ]]; then
            for img in "$dir"/*.png; do
                if [[ -f "$img" ]]; then
                    local img_name=$(basename "$img")
                    local img_path=$(realpath "$img")
                    ((screenshot_count++))
                    
                    cat >> "$gallery_file" << EOF
        <div class="item">
            <img src="file://$img_path" onclick="window.open(this.src)" alt="$img_name">
            <div class="url">$img_name</div>
        </div>
EOF
                fi
            done
        fi
    done
    
    cat >> "$gallery_file" << 'EOF'
    </div>
    <script>
        document.getElementById('stats').innerHTML = 'Total Screenshots: ' + document.querySelectorAll('.item').length;
        function filterGallery() {
            var filter = document.getElementById('search').value.toLowerCase();
            var items = document.querySelectorAll('.item');
            items.forEach(function(item) {
                var url = item.querySelector('.url').textContent.toLowerCase();
                item.style.display = url.includes(filter) ? 'block' : 'none';
            });
        }
    </script>
</body>
</html>
EOF
    
    log_success "Created gallery with $screenshot_count screenshots"
    
    # ─────────────────────────────────────────────────────────────────────────
    # Stats
    # ─────────────────────────────────────────────────────────────────────────
    separator
    log_success "Visual recon complete!"
    
    show_stats "Screenshots taken" "$base/screenshots"
    
    log_info "View gallery: file://$gallery_file"
    
    if [[ -f "$base/screenshots/gowitness_report.html" ]]; then
        log_info "Gowitness report: file://$base/screenshots/gowitness_report.html"
    fi
    
    save_stat "screenshots" "$screenshot_count" "$base"
    
    return 0
}
