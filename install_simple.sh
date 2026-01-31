#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# SHADOW v5 - Simple Tool Installer (No Sudo Required)
# Run this script in a regular terminal, not VS Code terminal
# ═══════════════════════════════════════════════════════════════════════════════

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[✓]${NC} $1"; }
log_error() { echo -e "${RED}[✗]${NC} $1"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -e "${BLUE}"
echo "╔═══════════════════════════════════════════════════════════════════╗"
echo "║              SHADOW v5 - Tool Installer                          ║"
echo "╚═══════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# ─────────────────────────────────────────────────────────────────────────────
# STEP 1: Install Go
# ─────────────────────────────────────────────────────────────────────────────
install_go() {
    if command -v go &>/dev/null; then
        log_success "Go already installed: $(go version)"
        return 0
    fi
    
    log_info "Installing Go..."
    GO_VERSION="1.21.5"
    GO_TAR="go${GO_VERSION}.linux-amd64.tar.gz"
    
    cd /tmp
    wget -q "https://go.dev/dl/${GO_TAR}"
    
    mkdir -p "$HOME/.local"
    rm -rf "$HOME/.local/go"
    tar -C "$HOME/.local" -xzf "$GO_TAR"
    
    # Setup PATH
    export PATH="$HOME/.local/go/bin:$PATH"
    export GOPATH="$HOME/go"
    export PATH="$PATH:$GOPATH/bin"
    
    # Add to bashrc
    if ! grep -q '.local/go/bin' ~/.bashrc 2>/dev/null; then
        echo '' >> ~/.bashrc
        echo '# Go' >> ~/.bashrc
        echo 'export PATH="$HOME/.local/go/bin:$PATH"' >> ~/.bashrc
        echo 'export GOPATH="$HOME/go"' >> ~/.bashrc
        echo 'export PATH="$PATH:$GOPATH/bin"' >> ~/.bashrc
    fi
    
    rm -f "/tmp/$GO_TAR"
    log_success "Go installed to ~/.local/go"
}

# ─────────────────────────────────────────────────────────────────────────────
# STEP 2: Install Go Tools
# ─────────────────────────────────────────────────────────────────────────────
go_install() {
    local tool="$1"
    local url="$2"
    
    if command -v "$tool" &>/dev/null; then
        log_success "$tool ✓"
        return 0
    fi
    
    log_info "Installing $tool..."
    if go install "$url" 2>/dev/null; then
        log_success "$tool installed"
    else
        log_error "$tool failed"
    fi
}

install_go_tools() {
    log_info "Installing Go security tools..."
    echo ""
    
    # ProjectDiscovery suite
    go_install "subfinder" "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    go_install "httpx" "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    go_install "nuclei" "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    go_install "naabu" "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    go_install "dnsx" "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    go_install "katana" "github.com/projectdiscovery/katana/cmd/katana@latest"
    go_install "tlsx" "github.com/projectdiscovery/tlsx/cmd/tlsx@latest"
    go_install "asnmap" "github.com/projectdiscovery/asnmap/cmd/asnmap@latest"
    go_install "mapcidr" "github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest"
    go_install "alterx" "github.com/projectdiscovery/alterx/cmd/alterx@latest"
    
    # Other tools
    go_install "amass" "github.com/owasp-amass/amass/v4/...@master"
    go_install "assetfinder" "github.com/tomnomnom/assetfinder@latest"
    go_install "ffuf" "github.com/ffuf/ffuf/v2@latest"
    go_install "gau" "github.com/lc/gau/v2/cmd/gau@latest"
    go_install "waybackurls" "github.com/tomnomnom/waybackurls@latest"
    go_install "gf" "github.com/tomnomnom/gf@latest"
    go_install "anew" "github.com/tomnomnom/anew@latest"
    go_install "unfurl" "github.com/tomnomnom/unfurl@latest"
    go_install "hakrawler" "github.com/hakluke/hakrawler@latest"
    go_install "gospider" "github.com/jaeles-project/gospider@latest"
    go_install "gowitness" "github.com/sensepost/gowitness@latest"
    go_install "dalfox" "github.com/hahwul/dalfox/v2@latest"
    go_install "subjs" "github.com/lc/subjs@latest"
}

# ─────────────────────────────────────────────────────────────────────────────
# STEP 3: Install Python Tools
# ─────────────────────────────────────────────────────────────────────────────
install_python_tools() {
    if ! command -v pip3 &>/dev/null; then
        log_error "pip3 not found. Install Python3 first."
        return 1
    fi
    
    log_info "Installing Python tools..."
    pip3 install --user arjun waymore uro 2>/dev/null || true
}

# ─────────────────────────────────────────────────────────────────────────────
# STEP 4: Setup GF Patterns
# ─────────────────────────────────────────────────────────────────────────────
setup_gf_patterns() {
    log_info "Setting up GF patterns..."
    mkdir -p ~/.gf
    
    if [[ ! -d "$HOME/tools/Gf-Patterns" ]]; then
        mkdir -p "$HOME/tools"
        git clone https://github.com/1ndianl33t/Gf-Patterns.git "$HOME/tools/Gf-Patterns" 2>/dev/null || true
        cp "$HOME/tools/Gf-Patterns"/*.json ~/.gf/ 2>/dev/null || true
    fi
    log_success "GF patterns ready"
}

# ─────────────────────────────────────────────────────────────────────────────
# STEP 5: Update Nuclei Templates
# ─────────────────────────────────────────────────────────────────────────────
update_nuclei() {
    if command -v nuclei &>/dev/null; then
        log_info "Updating Nuclei templates..."
        nuclei -update-templates 2>/dev/null || true
        log_success "Nuclei templates updated"
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

# Check if running in VS Code terminal (limited environment)
if [[ "$TERM_PROGRAM" == "vscode" ]] || [[ -n "$VSCODE_GIT_IPC_HANDLE" ]]; then
    log_error "Please run this script in a regular terminal, not VS Code terminal!"
    echo ""
    echo "Open a terminal and run:"
    echo "  cd $SCRIPT_DIR"
    echo "  ./install_simple.sh"
    exit 1
fi

# Run installation steps
install_go
echo ""
install_go_tools
echo ""
install_python_tools
echo ""
setup_gf_patterns
echo ""
update_nuclei

# Make scripts executable
chmod +x "$SCRIPT_DIR/shadow.sh" 2>/dev/null
chmod +x "$SCRIPT_DIR/modules/"*.sh 2>/dev/null

echo ""
echo "═══════════════════════════════════════════════════════════════════"
log_success "Installation complete!"
echo "═══════════════════════════════════════════════════════════════════"
echo ""
echo "Next steps:"
echo "  1. Reload shell: source ~/.bashrc"
echo "  2. Check tools: ./shadow.sh -c"
echo "  3. Run scan: ./shadow.sh target.com"
echo ""
