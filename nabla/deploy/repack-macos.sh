#!/usr/bin/env bash
set -euo pipefail

# ═══════════════════════════════════════════════════════════════
# AXIOM Nabla — macOS Binary Repack
#
# Compiles Nabla binaries from source on THIS Mac, then packages
# everything into a binary tarball that can be sent to other Macs.
#
# Recipients just run:
#   tar xzf axiom-nabla-macos-arm64-vX.Y.Z.tar.gz
#   cd axiom/nabla
#   ./deploy/setup-macos.sh
#
# No Rust or Xcode needed on the receiving Mac.
#
# Run from the source tree:
#   ./nabla/deploy/repack-macos.sh
# Or from the nabla/ directory:
#   ./deploy/repack-macos.sh
# ═══════════════════════════════════════════════════════════════

ARCH=$(uname -m)
echo "╔══════════════════════════════════════════════════════════╗"
echo "║   AXIOM Nabla — macOS Binary Repack                     ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
echo "  Architecture: $ARCH"

# ── Resolve paths ──
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NABLA_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Find src/ — either sibling of nabla/ or parent
if [ -f "$NABLA_DIR/../src/Cargo.toml" ]; then
    SRC_DIR="$(cd "$NABLA_DIR/../src" && pwd)"
elif [ -f "$NABLA_DIR/../../Cargo.toml" ]; then
    SRC_DIR="$(cd "$NABLA_DIR/../.." && pwd)"
else
    echo "ERROR: Cannot find Cargo.toml (source tree)."
    echo "       Run this from the axiom source tree or extracted source tarball."
    exit 1
fi

echo "  Source dir:   $SRC_DIR"
echo "  Nabla dir:    $NABLA_DIR"
echo ""

# ═══════════════════════════════════════════════════════════════
# Step 1: Verify toolchain
# ═══════════════════════════════════════════════════════════════
echo "── Step 1: Checking build tools"
if ! command -v rustc &>/dev/null; then
    echo "   ERROR: Rust not installed. Run setup-macos.sh first (it installs Rust),"
    echo "          or install manually: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
    exit 1
fi
echo "   rustc: $(rustc --version)"

if ! xcode-select -p &>/dev/null; then
    echo "   WARNING: Xcode Command Line Tools not found."
    echo "   Installing... (a system dialog may appear)"
    xcode-select --install 2>/dev/null || true
    until xcode-select -p &>/dev/null; do sleep 5; done
fi
echo "   Xcode CLI: $(xcode-select -p)"
echo ""

# ═══════════════════════════════════════════════════════════════
# Step 2: Build release binaries
# ═══════════════════════════════════════════════════════════════
echo "── Step 2: Building release binaries..."
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

# ═══════════════════════════════════════════════════════════════
# Step 3: Package binary tarball
# ═══════════════════════════════════════════════════════════════
NABLA_VERSION=$(grep '^version' "$SRC_DIR/Cargo.toml" | head -1 | sed 's/.*"\(.*\)".*/\1/')
TARBALL_NAME="axiom-nabla-macos-${ARCH}-v${NABLA_VERSION}.tar.gz"
TARBALL_PATH="$SRC_DIR/target/$TARBALL_NAME"

echo "── Step 3: Packaging binary tarball"
echo "   Version: $NABLA_VERSION"
echo "   Output:  $TARBALL_PATH"
echo ""

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
cp "$SCRIPT_DIR/com.axiom.nabla.plist"  "$PKG/deploy/"
chmod +x "$PKG/deploy/"*.sh

# Config templates
cp "$NABLA_DIR/node.toml"      "$PKG/"
cp "$NABLA_DIR/bootstrap.toml" "$PKG/"

# No root-keys — new nodes get their NBC signed by a qualified peer on connect.
# Root authority public keys are hardcoded in Core (genesis.rs).

# zkVM artifacts (ELF + IMAGE_ID)
ZKVM_DIR="$HOME/.axiom/zkvm"
if [ -f "$ZKVM_DIR/axiom-core.elf" ] && [ -f "$ZKVM_DIR/image-id.hex" ]; then
    mkdir -p "$PKG/zkvm"
    cp "$ZKVM_DIR/axiom-core.elf"  "$PKG/zkvm/"
    cp "$ZKVM_DIR/image-id.hex"  "$PKG/zkvm/"
    echo "   zkVM:        axiom-core.elf $(du -h "$PKG/zkvm/axiom-core.elf" | cut -f1) + image-id.hex"
else
    echo "   zkVM:        NOT FOUND (skipped — ~/.axiom/zkvm/axiom-core.elf)"
fi

tar czf "$TARBALL_PATH" -C "$STAGE_DIR" axiom/
rm -rf "$STAGE_DIR"

TARBALL_SIZE=$(du -h "$TARBALL_PATH" | cut -f1)

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║  Binary tarball ready!                                   ║"
echo "╠══════════════════════════════════════════════════════════╣"
echo "║                                                          ║"
echo "║  $TARBALL_PATH"
echo "║  Size: $TARBALL_SIZE"
echo "║                                                          ║"
echo "║  On the receiving Mac:                                   ║"
echo "║    tar xzf $TARBALL_NAME"
echo "║    cd axiom/nabla                                        ║"
echo "║    nano node.toml          # set name + port             ║"
echo "║    ./deploy/setup-macos.sh # no compile needed           ║"
echo "║                                                          ║"
echo "╚══════════════════════════════════════════════════════════╝"
