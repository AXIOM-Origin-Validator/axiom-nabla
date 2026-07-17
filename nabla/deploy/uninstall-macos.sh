#!/usr/bin/env bash
set -euo pipefail

# ═══════════════════════════════════════════════════════════════
# AXIOM Nabla — macOS Uninstall
#
# Removes the launchd service and binaries.
# Preserves $DATA_DIR (node identity + state).
# ═══════════════════════════════════════════════════════════════

DATA_DIR="${DATA_DIR:-$HOME/.axiom}"
BIN_DIR="$DATA_DIR/bin"
PLIST="$HOME/Library/LaunchAgents/com.axiom.nabla.plist"

echo "Removing AXIOM Nabla from macOS..."

# ── Stop and unload service ──
if launchctl list com.axiom.nabla &>/dev/null; then
    echo "  Stopping service..."
    launchctl stop com.axiom.nabla 2>/dev/null || true
    launchctl unload "$PLIST" 2>/dev/null || true
    echo "  Service stopped."
else
    echo "  Service not running."
fi

# ── Remove plist ──
if [ -f "$PLIST" ]; then
    rm -f "$PLIST"
    echo "  Removed: $PLIST"
else
    echo "  Plist not found (already removed)."
fi

# ── Remove binaries ──
for bin in nabla-node nabla-ceremony; do
    if [ -f "$BIN_DIR/$bin" ]; then
        rm -f "$BIN_DIR/$bin"
        echo "  Removed: $BIN_DIR/$bin"
    fi
done

# Remove bin dir if empty
rmdir "$BIN_DIR" 2>/dev/null || true

echo ""
echo "Done. Binaries and service removed."
echo ""
echo "Node data is preserved at: $DATA_DIR"
echo "  (identity, config, state, logs)"
echo "  To remove everything:  rm -rf $DATA_DIR"
