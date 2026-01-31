#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# SHADOW v5 - Tool Installer
# Installs all required and optional tools for SHADOW RECON
# ═══════════════════════════════════════════════════════════════════════════════

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}"
cat << 'EOF'
   ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗
   ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║
   ███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║
   ╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║
   ███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝
   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝
   
   TOOL INSTALLER
EOF
echo -e "${NC}"

# ─────────────────────────────────────────────────────────────────────────────
# HELPER FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[✓]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[✗]${NC} $1"; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_warn "Some tools may require root. Run with sudo for full installation."
    fi
}

check_go() {
    if ! command -v go &>/dev/null; then
        log_error "Go is not installed. Installing Go..."
        install_go
    else
        log_success "Go found: $(go version)"
    fi
}

install_go() {
    local GO_VERSION="1.21.5"
    local GO_TAR="go${GO_VERSION}.linux-amd64.tar.gz"
    
    log_info "Downloading Go ${GO_VERSION}..."
    wget -q "https://go.dev/dl/${GO_TAR}" -O "/tmp/${GO_TAR}"
    
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf "/tmp/${GO_TAR}"
    
    # Add to PATH
    export PATH=$PATH:/usr/local/go/bin
    export GOPATH=$HOME/go
    export PATH=$PATH:$GOPATH/bin
    
    # Add to shell rc
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
    echo 'export GOPATH=$HOME/go' >> ~/.bashrc
    echo 'export PATH=$PATH:$GOPATH/bin' >> ~/.bashrc
    
    rm -f "/tmp/${GO_TAR}"
    log_success "Go installed successfully"
}

go_install() {
    local tool="$1"
    local url="$2"
    
    if command -v "$tool" &>/dev/null; then
        log_success "$tool already installed"
        return 0
    fi
    
    log_info "Installing $tool..."
    if go install "$url"; then
        log_success "$tool installed"
    else
        log_error "Failed to install $tool"
    fi
}

pip_install() {
    local tool="$1"
    
    if command -v "$tool" &>/dev/null || pip3 show "$tool" &>/dev/null; then
        log_success "$tool already installed"
        return 0
    fi
    
    log_info "Installing $tool..."
    if pip3 install "$tool"; then
        log_success "$tool installed"
    else
        log_error "Failed to install $tool"
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# CHECK PREREQUISITES
# ─────────────────────────────────────────────────────────────────────────────
log_info "Checking prerequisites..."

# Update package lists
log_info "Updating package lists..."
sudo apt-get update

# Install basic dependencies
log_info "Installing basic dependencies..."
sudo apt-get install -y \
    git \
    curl \
    wget \
    jq \
    python3 \
    python3-pip \
    chromium-browser \
    libpcap-dev \
    dnsutils \
    whois \
    nmap \
    masscan

check_go

# ─────────────────────────────────────────────────────────────────────────────
# INSTALL GO TOOLS (ProjectDiscovery & Others)
# ─────────────────────────────────────────────────────────────────────────────
echo ""
log_info "Installing Go tools..."
echo ""

# ProjectDiscovery Tools
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
go_install "chaos" "github.com/projectdiscovery/chaos-client/cmd/chaos@latest"

# Other Go Tools
go_install "amass" "github.com/owasp-amass/amass/v4/...@master"
go_install "assetfinder" "github.com/tomnomnom/assetfinder@latest"
go_install "ffuf" "github.com/ffuf/ffuf/v2@latest"
go_install "gau" "github.com/lc/gau/v2/cmd/gau@latest"
go_install "waybackurls" "github.com/tomnomnom/waybackurls@latest"
go_install "gf" "github.com/tomnomnom/gf@latest"
go_install "qsreplace" "github.com/tomnomnom/qsreplace@latest"
go_install "anew" "github.com/tomnomnom/anew@latest"
go_install "unfurl" "github.com/tomnomnom/unfurl@latest"
go_install "hakrawler" "github.com/hakluke/hakrawler@latest"
go_install "gospider" "github.com/jaeles-project/gospider@latest"
go_install "gowitness" "github.com/sensepost/gowitness@latest"
go_install "dalfox" "github.com/hahwul/dalfox/v2@latest"
go_install "kxss" "github.com/Emoe/kxss@latest"
go_install "subjs" "github.com/lc/subjs@latest"
go_install "getJS" "github.com/003random/getJS@latest"
go_install "gauplus" "github.com/bp0lr/gauplus@latest"
go_install "gotator" "github.com/Josue87/gotator@latest"
go_install "crlfuzz" "github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest"
go_install "subjack" "github.com/haccer/subjack@latest"

# ─────────────────────────────────────────────────────────────────────────────
# INSTALL PYTHON TOOLS
# ─────────────────────────────────────────────────────────────────────────────
echo ""
log_info "Installing Python tools..."
echo ""

pip_install "arjun"
pip_install "waymore"
pip_install "ghauri"
pip_install "uro"
pip_install "dirsearch"

# LinkFinder
if [[ ! -d "$HOME/tools/LinkFinder" ]]; then
    log_info "Installing LinkFinder..."
    mkdir -p "$HOME/tools"
    git clone https://github.com/GerbenJavado/LinkFinder.git "$HOME/tools/LinkFinder" 2>/dev/null
    pip3 install -r "$HOME/tools/LinkFinder/requirements.txt" 2>/dev/null
    ln -sf "$HOME/tools/LinkFinder/linkfinder.py" "$HOME/.local/bin/linkfinder" 2>/dev/null
    log_success "LinkFinder installed"
fi

# SecretFinder
if [[ ! -d "$HOME/tools/SecretFinder" ]]; then
    log_info "Installing SecretFinder..."
    git clone https://github.com/m4ll0k/SecretFinder.git "$HOME/tools/SecretFinder" 2>/dev/null
    pip3 install -r "$HOME/tools/SecretFinder/requirements.txt" 2>/dev/null
    ln -sf "$HOME/tools/SecretFinder/SecretFinder.py" "$HOME/.local/bin/secretfinder" 2>/dev/null
    log_success "SecretFinder installed"
fi

# Findomain
if ! command -v findomain &>/dev/null; then
    log_info "Installing Findomain..."
    curl -LO https://github.com/findomain/findomain/releases/latest/download/findomain-linux.zip 2>/dev/null
    unzip -q findomain-linux.zip
    chmod +x findomain
    sudo mv findomain /usr/local/bin/
    rm -f findomain-linux.zip
    log_success "Findomain installed"
fi

# ─────────────────────────────────────────────────────────────────────────────
# INSTALL GF PATTERNS
# ─────────────────────────────────────────────────────────────────────────────
echo ""
log_info "Installing GF patterns..."

mkdir -p ~/.gf
if [[ ! -d "$HOME/tools/Gf-Patterns" ]]; then
    git clone https://github.com/1ndianl33t/Gf-Patterns.git "$HOME/tools/Gf-Patterns" 2>/dev/null
    cp "$HOME/tools/Gf-Patterns"/*.json ~/.gf/ 2>/dev/null
    log_success "GF patterns installed"
fi

# ─────────────────────────────────────────────────────────────────────────────
# UPDATE NUCLEI TEMPLATES
# ─────────────────────────────────────────────────────────────────────────────
echo ""
log_info "Updating Nuclei templates..."

if command -v nuclei &>/dev/null; then
    nuclei -update-templates 2>/dev/null
    log_success "Nuclei templates updated"
fi

# ─────────────────────────────────────────────────────────────────────────────
# INSTALL FEROXBUSTER (Rust)
# ─────────────────────────────────────────────────────────────────────────────
if ! command -v feroxbuster &>/dev/null; then
    log_info "Installing Feroxbuster..."
    sudo apt-get install -y feroxbuster 2>/dev/null || {
        curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash
        sudo mv feroxbuster /usr/local/bin/
    }
    log_success "Feroxbuster installed"
fi

# ─────────────────────────────────────────────────────────────────────────────
# INSTALL ADDITIONAL TOOLS
# ─────────────────────────────────────────────────────────────────────────────
echo ""
log_info "Installing additional tools..."

# SQLMap
if ! command -v sqlmap &>/dev/null; then
    log_info "Installing SQLMap..."
    sudo apt-get install -y sqlmap 2>/dev/null
    log_success "SQLMap installed"
fi

# Metabigor
go_install "metabigor" "github.com/j3ssie/metabigor@latest"

# x8
if ! command -v x8 &>/dev/null; then
    log_info "Installing x8..."
    cargo install x8 2>/dev/null || log_warn "x8 requires Rust/Cargo"
fi

# ─────────────────────────────────────────────────────────────────────────────
# SETUP WORDLISTS
# ─────────────────────────────────────────────────────────────────────────────
echo ""
log_info "Setting up wordlists..."

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORDLIST_DIR="${SCRIPT_DIR}/wordlists"
mkdir -p "$WORDLIST_DIR"

# Download essential wordlists
if [[ ! -f "$WORDLIST_DIR/dirs.txt" ]]; then
    log_info "Downloading directory wordlist..."
    curl -sL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories.txt" \
        -o "$WORDLIST_DIR/dirs.txt"
fi

if [[ ! -f "$WORDLIST_DIR/params.txt" ]]; then
    log_info "Downloading parameters wordlist..."
    curl -sL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/burp-parameter-names.txt" \
        -o "$WORDLIST_DIR/params.txt"
fi

if [[ ! -f "$WORDLIST_DIR/subdomains.txt" ]]; then
    log_info "Downloading subdomain wordlist..."
    curl -sL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt" \
        -o "$WORDLIST_DIR/subdomains.txt"
fi

if [[ ! -f "$WORDLIST_DIR/permutations.txt" ]]; then
    log_info "Creating permutations wordlist..."
    cat > "$WORDLIST_DIR/permutations.txt" << 'EOF'
dev
stage
staging
prod
production
test
testing
uat
qa
api
admin
internal
private
secure
old
new
beta
alpha
demo
backup
temp
tmp
cdn
static
assets
media
upload
downloads
EOF
fi

log_success "Wordlists ready"

# ─────────────────────────────────────────────────────────────────────────────
# MAKE SCRIPTS EXECUTABLE
# ─────────────────────────────────────────────────────────────────────────────
chmod +x "${SCRIPT_DIR}/shadow.sh" 2>/dev/null
chmod +x "${SCRIPT_DIR}/modules/"*.sh 2>/dev/null
chmod +x "${SCRIPT_DIR}/utils/"*.sh 2>/dev/null

# ─────────────────────────────────────────────────────────────────────────────
# FINAL CHECK
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════════════════"
log_success "Installation complete!"
echo "═══════════════════════════════════════════════════════════════════"
echo ""

log_info "Run tool check with: ./shadow.sh -c"
log_info "Start scanning with: ./shadow.sh <target>"
echo ""

# Show PATH reminder
if [[ ":$PATH:" != *":$HOME/go/bin:"* ]]; then
    log_warn "Add Go bin to PATH:"
    echo "    export PATH=\$PATH:\$HOME/go/bin"
    echo "    (add to ~/.bashrc for persistence)"
fi

echo ""
