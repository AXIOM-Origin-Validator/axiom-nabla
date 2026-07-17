#!/usr/bin/env bash
set -euo pipefail

# ═══════════════════════════════════════════════════════════════
# AXIOM Nabla — macOS Setup
#
# Two modes:
#   SOURCE tarball  — compiles from source, then installs
#   BINARY tarball  — pre-built binaries in bin/, skips compile
#
# After compiling, offers to package a binary tarball that can
# be delivered to other Macs without needing Rust or Xcode.
#
# Run from the tarball's nabla/ directory:
#   cd axiom/nabla && ./deploy/setup-macos.sh
# ═══════════════════════════════════════════════════════════════

# ── Verify macOS ──
if [ "$(uname)" != "Darwin" ]; then
    echo "ERROR: This script is for macOS only."
    echo "       For Linux, use deploy/setup-node.sh + deploy/install-service.sh"
    exit 1
fi

ARCH=$(uname -m)
echo "╔══════════════════════════════════════╗"
echo "║   AXIOM Nabla — macOS Setup          ║"
echo "╚══════════════════════════════════════╝"
echo ""
echo "  Architecture: $ARCH"

# ── Resolve paths ──
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NABLA_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

DATA_DIR="${DATA_DIR:-$HOME/.axiom}"
LOG_DIR="$DATA_DIR/logs"
BIN_DIR="$DATA_DIR/bin"

echo "  Data dir:     $DATA_DIR"

# ── Read port from node.toml ──
TEMPLATE_TOML="$NABLA_DIR/node.toml"
PORT=6225
if [ -f "$TEMPLATE_TOML" ]; then
    PORT=$(grep '^port' "$TEMPLATE_TOML" | sed 's/.*= *\([0-9]*\).*/\1/' | head -1)
    PORT="${PORT:-6225}"
fi

# ═══════════════════════════════════════════════════════════════
# Detect mode: pre-built binaries or compile from source
# ═══════════════════════════════════════════════════════════════
PREBUILT_DIR="$NABLA_DIR/bin"
COMPILED_FROM_SOURCE=false

if [ -f "$PREBUILT_DIR/nabla-node" ] && [ -f "$PREBUILT_DIR/nabla-ceremony" ]; then
    echo "  Mode:         Binary (pre-built)"
    echo ""
    RELEASE_DIR="$PREBUILT_DIR"
    echo "── Pre-built binaries found in bin/"
    echo "   nabla-node     $(du -h "$PREBUILT_DIR/nabla-node" | cut -f1)"
    echo "   nabla-ceremony $(du -h "$PREBUILT_DIR/nabla-ceremony" | cut -f1)"
    echo ""
else
    SRC_DIR="$(cd "$NABLA_DIR/../src" 2>/dev/null && pwd)" || {
        echo "ERROR: No pre-built binaries in bin/ and no source in ../src/"
        exit 1
    }
    echo "  Mode:         Source (compile)"
    echo "  Source dir:   $SRC_DIR"
    echo ""
    COMPILED_FROM_SOURCE=true

    # ═══════════════════════════════════════════════════════════
    # Step 1: Xcode Command Line Tools
    # ═══════════════════════════════════════════════════════════
    echo "── Step 1: Xcode Command Line Tools"
    if xcode-select -p &>/dev/null; then
        echo "   Already installed: $(xcode-select -p)"
    else
        echo "   Installing Xcode Command Line Tools..."
        echo "   A system dialog will appear — click 'Install' and wait."
        xcode-select --install 2>/dev/null || true
        echo ""
        echo "   Waiting for installation to complete..."
        until xcode-select -p &>/dev/null; do
            sleep 5
        done
        echo "   Installed: $(xcode-select -p)"
    fi
    echo ""

    # ═══════════════════════════════════════════════════════════
    # Step 2: Rust toolchain
    # ═══════════════════════════════════════════════════════════
    echo "── Step 2: Rust toolchain"
    if command -v rustc &>/dev/null; then
        echo "   Already installed: $(rustc --version)"
    else
        echo "   Installing Rust via rustup..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        # Source cargo env for this session
        source "$HOME/.cargo/env"
        echo "   Installed: $(rustc --version)"
    fi
    echo ""

    # ═══════════════════════════════════════════════════════════
    # Step 3: Build release binaries
    # ═══════════════════════════════════════════════════════════
    echo "── Step 3: Building release binaries (this may take a few minutes)..."
    echo "   Target: $ARCH-apple-darwin"
    echo ""
    (cd "$SRC_DIR" && cargo build --release -p axiom-nabla -p axiom-nabla-ceremony)
    echo ""
    echo "   Build complete."

    RELEASE_DIR="$SRC_DIR/target/release"
    for bin in nabla-node nabla-ceremony; do
        if [ ! -f "$RELEASE_DIR/$bin" ]; then
            echo "ERROR: $bin not found in $RELEASE_DIR/"
            exit 1
        fi
    done
    echo "   nabla-node     $(du -h "$RELEASE_DIR/nabla-node" | cut -f1)"
    echo "   nabla-ceremony $(du -h "$RELEASE_DIR/nabla-ceremony" | cut -f1)"
    echo ""
fi

# ═══════════════════════════════════════════════════════════════
# Step 4: Install binaries
# ═══════════════════════════════════════════════════════════════
echo "── Step 4: Installing binaries to $BIN_DIR/"
mkdir -p "$BIN_DIR"
cp "$RELEASE_DIR/nabla-node"     "$BIN_DIR/"
cp "$RELEASE_DIR/nabla-ceremony" "$BIN_DIR/"
chmod +x "$BIN_DIR/"*
echo "   Done."
echo ""

# ═══════════════════════════════════════════════════════════════
# Step 5: Copy node.toml (if not already present)
# ═══════════════════════════════════════════════════════════════
echo "── Step 5: Node configuration"
mkdir -p "$DATA_DIR"
NODE_TOML="$DATA_DIR/node.toml"
if [ ! -f "$NODE_TOML" ]; then
    cp "$TEMPLATE_TOML" "$NODE_TOML"
    echo "   Copied node.toml → $NODE_TOML"
else
    echo "   node.toml already exists at $NODE_TOML"
    echo "   To reset, remove it and re-run setup."
fi
echo ""

# ═══════════════════════════════════════════════════════════════
# Step 6: Run ceremony (generate node identity)
# ═══════════════════════════════════════════════════════════════
echo "── Step 6: Node identity"
TARBALL_CONFIG="$NABLA_DIR/config"
if [ -d "$DATA_DIR/config" ] && [ -f "$DATA_DIR/config/nbc.json" ]; then
    echo "   Node identity already exists at $DATA_DIR/config/"
    echo "   To regenerate, remove $DATA_DIR/config and run again."
elif [ -f "$TARBALL_CONFIG/nbc.json" ]; then
    echo "   Installing pre-signed identity from tarball..."
    mkdir -p "$DATA_DIR/config"
    cp "$TARBALL_CONFIG"/nbc.json "$DATA_DIR/config/"
    for f in nabla_sphincs.pub nabla_ed25519.pub nabla_dilithium.pub; do
        [ -f "$TARBALL_CONFIG/$f" ] && cp "$TARBALL_CONFIG/$f" "$DATA_DIR/config/"
    done
    TARBALL_PRIVATE="$NABLA_DIR/private"
    if [ -d "$TARBALL_PRIVATE" ]; then
        for f in nabla_sphincs.key nabla_ed25519.key nabla_dilithium.key; do
            [ -f "$TARBALL_PRIVATE/$f" ] && cp "$TARBALL_PRIVATE/$f" "$DATA_DIR/config/" && chmod 600 "$DATA_DIR/config/$f"
        done
    fi
    echo "   Identity installed from genesis package."
else
    echo "   No pre-signed identity found."
    echo "   Node will receive its NBC from a qualified peer on first connect."
fi
echo ""

# ═══════════════════════════════════════════════════════════════
# Step 7: Install zkVM artifacts (ELF + IMAGE_ID)
# ═══════════════════════════════════════════════════════════════
echo "── Step 7: zkVM artifacts"
TARBALL_ZKVM="$NABLA_DIR/zkvm"
ZKVM_DIR="$DATA_DIR/zkvm"
if [ -f "$TARBALL_ZKVM/axiom-core.elf" ]; then
    mkdir -p "$ZKVM_DIR"
    cp "$TARBALL_ZKVM/axiom-core.elf"  "$ZKVM_DIR/"
    cp "$TARBALL_ZKVM/image-id.hex"  "$ZKVM_DIR/" 2>/dev/null || true
    echo "   Installed to $ZKVM_DIR/"
else
    echo "   Not in package (skipped)"
fi
echo ""

# ═══════════════════════════════════════════════════════════════
# Step 8: Copy bootstrap.toml
# ═══════════════════════════════════════════════════════════════
echo "── Step 8: Bootstrap configuration"
BOOTSTRAP="$DATA_DIR/bootstrap.toml"
if [ ! -f "$BOOTSTRAP" ]; then
    if [ -f "$NABLA_DIR/bootstrap.toml" ]; then
        cp "$NABLA_DIR/bootstrap.toml" "$BOOTSTRAP"
        echo "   Copied bootstrap.toml → $BOOTSTRAP"
        echo "   IMPORTANT: Edit $BOOTSTRAP with your peer addresses."
    fi
else
    echo "   bootstrap.toml already exists at $BOOTSTRAP"
fi
echo ""

# ═══════════════════════════════════════════════════════════════
# Step 9: Install launchd service
# ═══════════════════════════════════════════════════════════════
echo "── Step 9: Installing launchd service"
PLIST_TEMPLATE="$SCRIPT_DIR/com.axiom.nabla.plist"
PLIST_DIR="$HOME/Library/LaunchAgents"
PLIST_DEST="$PLIST_DIR/com.axiom.nabla.plist"

mkdir -p "$PLIST_DIR"
mkdir -p "$LOG_DIR"

# Unload existing service if present
if launchctl list com.axiom.nabla &>/dev/null; then
    echo "   Stopping existing service..."
    launchctl stop com.axiom.nabla 2>/dev/null || true
    launchctl unload "$PLIST_DEST" 2>/dev/null || true
fi

sed \
    -e "s|%NABLA_BIN%|$BIN_DIR/nabla-node|g" \
    -e "s|%AVM_ELF%|$DATA_DIR/zkvm/axiom-core.elf|g" \
    -e "s|%DATA_DIR%|$DATA_DIR|g" \
    -e "s|%LOG_DIR%|$LOG_DIR|g" \
    -e "s|%PORT%|$PORT|g" \
    "$PLIST_TEMPLATE" > "$PLIST_DEST"

echo "   Installed: $PLIST_DEST"
echo ""

# ═══════════════════════════════════════════════════════════════
# Done
# ═══════════════════════════════════════════════════════════════
echo "╔══════════════════════════════════════════════════════════╗"
echo "║  Setup complete!                                        ║"
echo "╠══════════════════════════════════════════════════════════╣"
echo "║  Next steps:                                            ║"
echo "║                                                         ║"
echo "║  1. Edit bootstrap peers:                               ║"
echo "║     nano $BOOTSTRAP"
echo "║                                                         ║"
echo "║  2. Load and start the service:                         ║"
echo "║     launchctl load ~/Library/LaunchAgents/com.axiom.nabla.plist"
echo "║     launchctl start com.axiom.nabla                     ║"
echo "║                                                         ║"
echo "║  3. Dashboard:                                          ║"
echo "║     http://localhost:6226                                ║"
echo "║                                                         ║"
echo "║  Service commands:                                      ║"
echo "║     launchctl stop com.axiom.nabla      # Stop          ║"
echo "║     launchctl unload <plist>             # Disable       ║"
echo "║     tail -f $LOG_DIR/nabla.out.log  # Logs"
echo "╚══════════════════════════════════════════════════════════╝"

# ═══════════════════════════════════════════════════════════════
# Offer to create binary tarball (only after compiling from source)
# ═══════════════════════════════════════════════════════════════
if [ "$COMPILED_FROM_SOURCE" = true ]; then
    echo ""
    read -p "Create binary tarball for other Macs? (y/N): " pack_choice
    if [ "$pack_choice" = "y" ] || [ "$pack_choice" = "Y" ]; then
        NABLA_VERSION=$(grep '^version' "$SRC_DIR/Cargo.toml" | head -1 | sed 's/.*"\(.*\)".*/\1/')
        TARBALL_NAME="axiom-nabla-macos-${ARCH}-v${NABLA_VERSION}.tar.gz"
        TARBALL_PATH="$NABLA_DIR/$TARBALL_NAME"

        STAGE_DIR=$(mktemp -d)
        PKG="$STAGE_DIR/axiom/nabla"
        mkdir -p "$PKG/bin" "$PKG/deploy"

        # Binaries
        cp "$RELEASE_DIR/nabla-node"     "$PKG/bin/"
        cp "$RELEASE_DIR/nabla-ceremony" "$PKG/bin/"
        chmod +x "$PKG/bin/"*

        # Deploy scripts
        cp "$SCRIPT_DIR/setup-macos.sh"         "$PKG/deploy/"
        cp "$SCRIPT_DIR/uninstall-macos.sh"     "$PKG/deploy/"
        cp "$SCRIPT_DIR/repack-macos.sh"        "$PKG/deploy/"
        cp "$SCRIPT_DIR/com.axiom.nabla.plist"  "$PKG/deploy/"
        chmod +x "$PKG/deploy/"*.sh

        # Config templates
        cp "$NABLA_DIR/node.toml"      "$PKG/"
        cp "$NABLA_DIR/bootstrap.toml" "$PKG/"

        # No root-keys — new nodes get their NBC signed by a qualified peer on connect.
        # Root authority public keys are hardcoded in Core (genesis.rs).

        # zkVM artifacts
        ZKVM_DIR="$HOME/.axiom/zkvm"
        if [ -f "$ZKVM_DIR/axiom-core.elf" ] && [ -f "$ZKVM_DIR/image-id.hex" ]; then
            mkdir -p "$PKG/zkvm"
            cp "$ZKVM_DIR/axiom-core.elf"  "$PKG/zkvm/"
            cp "$ZKVM_DIR/image-id.hex"  "$PKG/zkvm/"
        fi

        tar czf "$TARBALL_PATH" -C "$STAGE_DIR" axiom/
        rm -rf "$STAGE_DIR"

        TARBALL_SIZE=$(du -h "$TARBALL_PATH" | cut -f1)
        echo ""
        echo "╔══════════════════════════════════════════════════════════╗"
        echo "║  Binary tarball ready                                   ║"
        echo "╚══════════════════════════════════════════════════════════╝"
        echo ""
        echo "  $TARBALL_PATH"
        echo "  Size: $TARBALL_SIZE"
        echo ""
        echo "  On another Mac:"
        echo "    tar xzf $TARBALL_NAME"
        echo "    cd axiom/nabla"
        echo "    nano node.toml"
        echo "    ./deploy/setup-macos.sh      # no compile needed"
    fi
fi
