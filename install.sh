#!/bin/bash
# ============================================================
# AUTONOMOUS PENTEST AGENT — INSTALLER
# For authorized security research only
# ============================================================

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

banner() {
cat << 'EOF'
        /\
       /  \
      /    \
     /  👁  \     AUTONOMOUS PENTEST AGENT
    /________\    INSTALLER v1.0
  ══════════════
  For authorized security research only.
EOF
}

log_info()  { echo -e "${GREEN}[+]${RESET} $1"; }
log_warn()  { echo -e "${YELLOW}[!]${RESET} $1"; }
log_error() { echo -e "${RED}[-]${RESET} $1"; }
log_step()  { echo -e "\n${CYAN}${BOLD}[STEP]${RESET} $1"; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "Run as root: sudo bash install.sh"
        exit 1
    fi
}

detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        OS_VER=$VERSION_ID
    else
        OS=$(uname -s)
    fi
    log_info "Detected OS: $OS $OS_VER"
}

install_system_deps() {
    log_step "Installing system dependencies"
    apt-get update -qq 2>/dev/null || true
    DEPS="curl wget git python3 python3-pip python3-venv nmap nikto tor proxychains4 \
          chromium-browser chromium jq unzip build-essential libssl-dev \
          libffi-dev python3-dev ruby ruby-dev libpq-dev"
    for dep in $DEPS; do
        if dpkg -l "$dep" &>/dev/null 2>&1; then
            log_info "$dep already installed ✓"
        else
            apt-get install -y "$dep" -qq 2>/dev/null && log_info "Installed $dep ✓" || log_warn "Could not install $dep (skipping)"
        fi
    done
}

check_tool_version() {
    local tool=$1
    local min_ver=$2
    if command -v "$tool" &>/dev/null; then
        local cur_ver=$("$tool" --version 2>&1 | grep -oP '\d+\.\d+' | head -1)
        log_info "$tool found: v$cur_ver"
        echo "found"
    else
        echo "missing"
    fi
}

install_go() {
    log_step "Checking Go installation"
    if command -v go &>/dev/null; then
        GO_VER=$(go version | grep -oP 'go\K[\d.]+')
        log_info "Go $GO_VER already installed ✓"
        # Upgrade if < 1.21
        if [[ "$(echo "$GO_VER 1.21" | tr ' ' '\n' | sort -V | head -1)" != "1.21" ]]; then
            log_warn "Go version < 1.21, upgrading..."
            install_go_fresh
        fi
    else
        install_go_fresh
    fi
}

install_go_fresh() {
    GO_VER="1.22.0"
    ARCH=$(dpkg --print-architecture)
    [[ "$ARCH" == "amd64" ]] && GOARCH="amd64" || GOARCH="arm64"
    wget -q "https://go.dev/dl/go${GO_VER}.linux-${GOARCH}.tar.gz" -O /tmp/go.tar.gz
    rm -rf /usr/local/go
    tar -C /usr/local -xzf /tmp/go.tar.gz
    echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> /etc/profile
    export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
    log_info "Go $GO_VER installed ✓"
}

install_go_tools() {
    log_step "Installing Go security tools"
    export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
    export GOPATH=$HOME/go

    GO_TOOLS=(
        "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        "github.com/projectdiscovery/httpx/cmd/httpx@latest"
        "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
        "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        "github.com/ffuf/ffuf/v2@latest"
        "github.com/tomnomnom/gf@latest"
        "github.com/tomnomnom/anew@latest"
        "github.com/tomnomnom/qsreplace@latest"
        "github.com/lc/gau/v2/cmd/gau@latest"
        "github.com/hakluke/hakrawler@latest"
    )

    for tool in "${GO_TOOLS[@]}"; do
        name=$(basename "${tool%@*}")
        if command -v "$name" &>/dev/null; then
            log_info "$name already installed, checking update..."
            go install "$tool" 2>/dev/null && log_info "$name updated ✓" || log_info "$name kept as-is ✓"
        else
            go install "$tool" 2>/dev/null && log_info "$name installed ✓" || log_warn "$name install failed (skipping)"
        fi
    done

    # Copy to /usr/local/bin for global access
    cp $HOME/go/bin/* /usr/local/bin/ 2>/dev/null || true
}

install_python_deps() {
    log_step "Installing Python dependencies"
    # Use --break-system-packages for Kali/Debian 12+
    PY_PKGS="httpx[asyncio] aiohttp playwright mitmproxy networkx sqlalchemy \
              pyyaml rich colorama groq requests beautifulsoup4 lxml \
              websockets python-jose cryptography paramiko dnspython \
              tldextract fake-useragent stem aiofiles asyncio-throttle \
              python-nmap tabulate jinja2"

    for pkg in $PY_PKGS; do
        pkg_name=$(echo "$pkg" | cut -d'[' -f1 | cut -d'=' -f1)
        if python3 -c "import $pkg_name" 2>/dev/null; then
            log_info "$pkg_name already installed ✓"
        else
            pip3 install "$pkg" --break-system-packages -q 2>/dev/null && \
                log_info "$pkg installed ✓" || \
                log_warn "$pkg install failed (skipping)"
        fi
    done

    # Install Playwright browsers
    playwright install chromium 2>/dev/null && log_info "Playwright Chromium installed ✓" || log_warn "Playwright browser install failed"
}

install_sqlmap() {
    log_step "Checking sqlmap"
    if command -v sqlmap &>/dev/null; then
        log_info "sqlmap found, updating..."
        cd /opt/sqlmap 2>/dev/null && git pull -q && log_info "sqlmap updated ✓" || true
    else
        git clone --depth 1 https://github.com/sqlmapproject/sqlmap /opt/sqlmap -q
        ln -sf /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap
        chmod +x /opt/sqlmap/sqlmap.py
        log_info "sqlmap installed ✓"
    fi
}

install_dalfox() {
    log_step "Checking dalfox (XSS scanner)"
    if command -v dalfox &>/dev/null; then
        log_info "dalfox already installed ✓"
    else
        export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
        go install github.com/hahwul/dalfox/v2@latest 2>/dev/null && \
            cp $HOME/go/bin/dalfox /usr/local/bin/ && \
            log_info "dalfox installed ✓" || log_warn "dalfox install failed"
    fi
}

install_arjun() {
    log_step "Checking arjun (parameter discovery)"
    if command -v arjun &>/dev/null; then
        log_info "arjun already installed ✓"
    else
        pip3 install arjun --break-system-packages -q && log_info "arjun installed ✓" || log_warn "arjun failed"
    fi
}

install_wpscan() {
    log_step "Checking WPScan"
    if command -v wpscan &>/dev/null; then
        log_info "wpscan found, updating..."
        gem update wpscan -q 2>/dev/null && log_info "wpscan updated ✓" || true
    else
        gem install wpscan -q 2>/dev/null && log_info "wpscan installed ✓" || log_warn "wpscan failed"
    fi
}

install_gf_patterns() {
    log_step "Installing gf patterns"
    mkdir -p ~/.gf
    if [ -d /opt/gf-patterns ]; then
        cd /opt/gf-patterns && git pull -q
    else
        git clone --depth 1 https://github.com/1ndianl33t/Gf-Patterns /opt/gf-patterns -q
    fi
    cp /opt/gf-patterns/*.json ~/.gf/ 2>/dev/null || true
    log_info "gf patterns installed ✓"
}

install_seclists() {
    log_step "Checking SecLists"
    if [ -d /usr/share/seclists ] || [ -d /usr/share/SecLists ]; then
        log_info "SecLists already present ✓"
    else
        apt-get install -y seclists -qq 2>/dev/null && log_info "SecLists installed ✓" || \
            (git clone --depth 1 https://github.com/danielmiessler/SecLists /usr/share/seclists -q && log_info "SecLists cloned ✓") || \
            log_warn "SecLists not available (offline?)"
    fi
}

setup_tor() {
    log_step "Configuring Tor"
    if command -v tor &>/dev/null; then
        # Configure tor control port
        grep -q "ControlPort 9051" /etc/tor/torrc 2>/dev/null || echo "ControlPort 9051" >> /etc/tor/torrc
        grep -q "CookieAuthentication 0" /etc/tor/torrc 2>/dev/null || echo "CookieAuthentication 0" >> /etc/tor/torrc
        log_info "Tor configured ✓"
    fi
}

setup_nuclei() {
    log_step "Updating Nuclei templates"
    if command -v nuclei &>/dev/null; then
        nuclei -update-templates -silent 2>/dev/null && log_info "Nuclei templates updated ✓" || log_warn "Nuclei template update failed"
    fi
}

install_ollama() {
    log_step "Checking Ollama (Local AI)"
    if command -v ollama &>/dev/null; then
        log_info "Ollama already installed ✓"
        # Pull model if not present
        ollama list 2>/dev/null | grep -q "llama3" || {
            log_warn "Pulling llama3:8b model (this may take time)..."
            ollama pull llama3:8b 2>/dev/null && log_info "llama3:8b pulled ✓" || log_warn "Ollama pull failed (ensure Ollama is running)"
        }
    else
        log_warn "Ollama not found. Install manually: curl -fsSL https://ollama.ai/install.sh | sh"
        log_warn "Then run: ollama pull llama3:8b"
    fi
}

create_global_command() {
    log_step "Creating global command"
    INSTALL_DIR="/opt/pentest-agent"

    # Copy project to /opt
    if [ -d "$INSTALL_DIR" ]; then
        log_info "Updating existing installation..."
        cp -r "$(pwd)"/* "$INSTALL_DIR/" 2>/dev/null || true
    else
        cp -r "$(pwd)" "$INSTALL_DIR" 2>/dev/null || mkdir -p "$INSTALL_DIR"
    fi

    # Create launcher
    cat > /usr/local/bin/pentest-agent << 'LAUNCHER'
#!/bin/bash
export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
cd /opt/pentest-agent
python3 agent.py "$@"
LAUNCHER
    chmod +x /usr/local/bin/pentest-agent
    log_info "Global command 'pentest-agent' created ✓"
}

print_summary() {
    echo -e "\n${GREEN}${BOLD}════════════════════════════════════════${RESET}"
    echo -e "${GREEN}${BOLD}  INSTALLATION COMPLETE!${RESET}"
    echo -e "${GREEN}${BOLD}════════════════════════════════════════${RESET}"
    echo -e "\n${BOLD}Usage:${RESET}"
    echo -e "  ${CYAN}pentest-agent -u https://target.com --creds user:pass${RESET}"
    echo -e "  ${CYAN}pentest-agent -f targets.txt --deep --tor${RESET}"
    echo -e "  ${CYAN}pentest-agent -u https://target.com --quick${RESET}"
    echo -e "\n${YELLOW}⚠️  Use only on systems you own or have written permission to test.${RESET}\n"
}

# MAIN
banner
check_root
detect_os
install_system_deps
install_go
install_go_tools
install_python_deps
install_sqlmap
install_dalfox
install_arjun
install_wpscan
install_gf_patterns
install_seclists
setup_tor
setup_nuclei
install_ollama
create_global_command
print_summary
