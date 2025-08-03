#!/bin/bash
set -euo pipefail

# MagicRune installer script

MAGICRUNE_VERSION="${MAGICRUNE_VERSION:-latest}"
MAGICRUNE_HOME="${MAGICRUNE_HOME:-$HOME/.magicrune}"
MAGICRUNE_BIN="$MAGICRUNE_HOME/bin"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

# Check OS
detect_os() {
    case "$(uname -s)" in
        Linux*)     OS="linux";;
        Darwin*)    OS="macos";;
        CYGWIN*|MINGW*|MSYS*) OS="windows";;
        *)          error "Unsupported operating system";;
    esac
    
    case "$(uname -m)" in
        x86_64|amd64) ARCH="x86_64";;
        aarch64|arm64) ARCH="aarch64";;
        *)            error "Unsupported architecture: $(uname -m)";;
    esac
}

# Download and install
install_magicrune() {
    info "Installing MagicRune $MAGICRUNE_VERSION for $OS-$ARCH..."
    
    # Create directories
    mkdir -p "$MAGICRUNE_BIN"
    mkdir -p "$MAGICRUNE_HOME/trusted_keys"
    mkdir -p "$MAGICRUNE_HOME/audit"
    mkdir -p "$MAGICRUNE_HOME/cache"
    
    # Download binary
    local download_url="https://github.com/magicrune/magicrune/releases/download/$MAGICRUNE_VERSION/magicrune-$OS-$ARCH"
    local temp_file="/tmp/magicrune-download"
    
    info "Downloading from $download_url..."
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$download_url" -o "$temp_file"
    elif command -v wget >/dev/null 2>&1; then
        wget -q "$download_url" -O "$temp_file"
    else
        error "Neither curl nor wget found. Please install one of them."
    fi
    
    # Verify checksum (if provided)
    if [ -n "${MAGICRUNE_CHECKSUM:-}" ]; then
        info "Verifying checksum..."
        echo "$MAGICRUNE_CHECKSUM  $temp_file" | sha256sum -c - || error "Checksum verification failed"
    fi
    
    # Install binary
    chmod +x "$temp_file"
    mv "$temp_file" "$MAGICRUNE_BIN/magicrune"
    
    success "MagicRune installed to $MAGICRUNE_BIN/magicrune"
}

# Setup shell integration
setup_shell() {
    info "Setting up shell integration..."
    
    local shell_config=""
    case "$SHELL" in
        */bash) shell_config="$HOME/.bashrc";;
        */zsh)  shell_config="$HOME/.zshrc";;
        */fish) shell_config="$HOME/.config/fish/config.fish";;
        *)      warning "Unknown shell: $SHELL. Please add $MAGICRUNE_BIN to your PATH manually."
               return;;
    esac
    
    # Add to PATH if not already present
    if ! grep -q "MAGICRUNE_HOME" "$shell_config" 2>/dev/null; then
        echo "" >> "$shell_config"
        echo "# MagicRune" >> "$shell_config"
        echo "export MAGICRUNE_HOME=\"$MAGICRUNE_HOME\"" >> "$shell_config"
        echo "export PATH=\"\$MAGICRUNE_HOME/bin:\$PATH\"" >> "$shell_config"
        success "Added MagicRune to $shell_config"
    else
        info "MagicRune already in $shell_config"
    fi
}

# Initialize configuration
init_config() {
    info "Initializing MagicRune configuration..."
    
    if [ ! -f "$MAGICRUNE_HOME/policy.yml" ]; then
        "$MAGICRUNE_BIN/magicrune" init --force
        success "Configuration initialized"
    else
        info "Configuration already exists"
    fi
}

# Main installation flow
main() {
    echo "╔═══════════════════════════════════════╗"
    echo "║       MagicRune Installer             ║"
    echo "║   Secure Code Execution Framework     ║"
    echo "╚═══════════════════════════════════════╝"
    echo
    
    detect_os
    install_magicrune
    setup_shell
    init_config
    
    echo
    success "Installation complete!"
    echo
    echo "To get started:"
    echo "  1. Restart your shell or run: source ~/.bashrc"
    echo "  2. Run: magicrune --help"
    echo
    echo "Documentation: https://github.com/magicrune/magicrune"
}

# Run main
main "$@"