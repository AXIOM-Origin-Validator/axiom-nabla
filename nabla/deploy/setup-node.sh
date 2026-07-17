#!/usr/bin/env bash
set -euo pipefail

# Resolve paths relative to tarball layout: deploy/ is inside axiom/nabla/
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NABLA_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN_DIR="$NABLA_DIR/bin"

DATA_DIR="${DATA_DIR:-$HOME/.axiom}"

# ── Read node.toml from tarball (user edits this before running setup) ──
TEMPLATE_TOML="$NABLA_DIR/node.toml"
if [ -f "$TEMPLATE_TOML" ]; then
    # Parse name and port from the template the user edited
    NODE_NAME=$(grep '^name' "$TEMPLATE_TOML" | sed 's/.*= *"\(.*\)"/\1/' | head -1)
    PORT=$(grep '^port' "$TEMPLATE_TOML" | sed 's/.*= *\([0-9]*\).*/\1/' | head -1)
fi
NODE_NAME="${NODE_NAME:-nabla-node}"
PORT="${PORT:-6225}"

echo "╔══════════════════════════════════════╗"
echo "║   AXIOM Nabla Node Setup             ║"
echo "╚══════════════════════════════════════╝"
echo ""
echo "  Data dir:  $DATA_DIR"
echo "  Name:      $NODE_NAME"
echo "  Port:      $PORT"
echo "  Source:    ${TEMPLATE_TOML}"
echo ""

# Step 1: Check binaries exist
if [ ! -f "$BIN_DIR/nabla-ceremony" ] || [ ! -f "$BIN_DIR/nabla-node" ]; then
    echo "ERROR: Binaries not found in $BIN_DIR/"
    echo "       Expected nabla-node and nabla-ceremony."
    exit 1
fi
echo "── Binaries OK: $BIN_DIR/"
echo ""

# Step 2: Copy node.toml to data dir (ceremony + binary read from here)
NODE_TOML="$DATA_DIR/node.toml"
mkdir -p "$DATA_DIR"
if [ ! -f "$NODE_TOML" ]; then
    echo "── Copying node.toml → $NODE_TOML"
    cp "$TEMPLATE_TOML" "$NODE_TOML"
    echo "   (from $TEMPLATE_TOML)"
else
    echo "── node.toml exists at $NODE_TOML"
    echo "   To update, edit $NODE_TOML directly or remove it and re-run setup."
fi
echo ""

# Step 3: Install pre-signed identity from genesis tarball (if present)
#   Genesis tarballs include config/nbc.json + private/ keys already signed.
#   Generic deployments get their NBC signed by a qualified peer on first connect.
TARBALL_CONFIG="$NABLA_DIR/config"
if [ -d "$DATA_DIR/config" ] && [ -f "$DATA_DIR/config/nbc.json" ]; then
    echo "── Node identity already exists at $DATA_DIR/config/"
    echo "   To regenerate, remove $DATA_DIR/config and run again."
elif [ -f "$TARBALL_CONFIG/nbc.json" ]; then
    echo "── Installing pre-signed identity from tarball..."
    mkdir -p "$DATA_DIR/config"
    cp "$TARBALL_CONFIG"/nbc.json "$DATA_DIR/config/"
    for f in nabla_sphincs.pub nabla_ed25519.pub nabla_dilithium.pub; do
        [ -f "$TARBALL_CONFIG/$f" ] && cp "$TARBALL_CONFIG/$f" "$DATA_DIR/config/"
    done
    # Private keys: tarball keeps them in private/
    TARBALL_PRIVATE="$NABLA_DIR/private"
    if [ -d "$TARBALL_PRIVATE" ]; then
        for f in nabla_sphincs.key nabla_ed25519.key nabla_dilithium.key; do
            [ -f "$TARBALL_PRIVATE/$f" ] && cp "$TARBALL_PRIVATE/$f" "$DATA_DIR/config/" && chmod 600 "$DATA_DIR/config/$f"
        done
    fi
    echo "   Identity installed from genesis package."
else
    echo "── No pre-signed identity found."
    echo "   Node will receive its NBC from a qualified peer on first connect."
fi

echo ""

# Step 4: Install zkVM artifacts (ELF + IMAGE_ID)
TARBALL_ZKVM="$NABLA_DIR/zkvm"
ZKVM_DIR="$DATA_DIR/zkvm"
if [ -f "$TARBALL_ZKVM/axiom-core.elf" ]; then
    mkdir -p "$ZKVM_DIR"
    cp "$TARBALL_ZKVM/axiom-core.elf"  "$ZKVM_DIR/"
    cp "$TARBALL_ZKVM/image-id.hex"  "$ZKVM_DIR/" 2>/dev/null || true
    echo "── zkVM artifacts installed to $ZKVM_DIR/"
else
    echo "── zkVM artifacts not in package (skipped)"
fi
echo ""

# Step 5: Remind about bootstrap.toml
BOOTSTRAP="$DATA_DIR/bootstrap.toml"
if [ ! -f "$BOOTSTRAP" ]; then
    if [ -f "$NABLA_DIR/bootstrap.toml" ]; then
        cp "$NABLA_DIR/bootstrap.toml" "$BOOTSTRAP"
    fi
    echo "── IMPORTANT: Edit $BOOTSTRAP with your peer addresses."
else
    echo "── bootstrap.toml exists at $BOOTSTRAP"
fi

echo ""
echo "Setup complete. Next steps:"
echo "  1. Edit $BOOTSTRAP with peer addresses"
echo "  2. Run:  $SCRIPT_DIR/install-service.sh"
echo "  3. Run:  sudo systemctl enable --now axiom-nabla"
echo ""
