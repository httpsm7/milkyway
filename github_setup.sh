#!/bin/bash
# ============================================================
# GitHub Setup Script for Pentest Agent
# Run: bash github_setup.sh YOUR_GITHUB_USERNAME
# ============================================================

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

log_info()  { echo -e "${GREEN}[+]${RESET} $1"; }
log_warn()  { echo -e "${YELLOW}[!]${RESET} $1"; }
log_error() { echo -e "${RED}[-]${RESET} $1"; }

GITHUB_USER="${1:-YourUsername}"
REPO_NAME="pentest-agent"

echo -e "${CYAN}${BOLD}"
echo "  GitHub Setup for Pentest Agent"
echo "  User: $GITHUB_USER / Repo: $REPO_NAME"
echo -e "${RESET}"

# Check git installed
if ! command -v git &>/dev/null; then
    log_error "git not found. Install: sudo apt install git"
    exit 1
fi

# Init git if not already
if [ ! -d ".git" ]; then
    git init
    log_info "Git initialized"
fi

# Configure git (if not set)
if [ -z "$(git config user.email)" ]; then
    git config user.email "pentest-agent@security.research"
    git config user.name "$GITHUB_USER"
fi

# Add all files
git add .
git status

# First commit
git commit -m "🔰 Initial release: Autonomous Pentest Agent v1.0

Features:
- AI-driven autonomous penetration testing
- Ollama (local) + Groq (cloud) AI fallback
- Smart context management (no LLM overflow)
- 12+ attack engines: IDOR, Auth Bypass, JWT, SQLi, SSRF, CORS, Race Condition
- WAF detection + adaptive bypass
- 30+ attack chain detection
- 3-step finding verification
- Auto PoC generation
- Dark-theme HTML reports
- Timestamped output (no duplicate files)
- One-command install + run
- For authorized security research only" 2>/dev/null || \
git commit -m "Update: Autonomous Pentest Agent" --allow-empty

log_info "Code committed ✓"

echo ""
echo -e "${YELLOW}${BOLD}Next Steps:${RESET}"
echo ""
echo "1. Create repo on GitHub:"
echo "   https://github.com/new"
echo "   Name: $REPO_NAME"
echo "   Description: Autonomous AI-powered penetration testing agent"
echo "   Visibility: Public or Private"
echo ""
echo "2. Push to GitHub:"
echo -e "   ${CYAN}git remote add origin https://github.com/$GITHUB_USER/$REPO_NAME.git${RESET}"
echo -e "   ${CYAN}git branch -M main${RESET}"
echo -e "   ${CYAN}git push -u origin main${RESET}"
echo ""
echo "3. On Kali — clone and install:"
echo -e "   ${CYAN}git clone https://github.com/$GITHUB_USER/$REPO_NAME${RESET}"
echo -e "   ${CYAN}cd $REPO_NAME${RESET}"
echo -e "   ${CYAN}sudo bash install.sh${RESET}"
echo ""
echo "4. Run scan:"
echo -e "   ${CYAN}pentest-agent -u https://target.com --creds admin:pass${RESET}"
echo ""
