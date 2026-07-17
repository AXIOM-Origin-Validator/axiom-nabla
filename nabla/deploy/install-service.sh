#!/usr/bin/env bash
set -euo pipefail

# Resolve paths relative to this script (works from tarball layout)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NABLA_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN_DIR="$NABLA_DIR/bin"
DATA_DIR="${DATA_DIR:-$HOME/.axiom}"
AVM_ELF="$DATA_DIR/zkvm/axiom-core.elf"

SERVICE_FILE="$SCRIPT_DIR/axiom-nabla.service"

if [ ! -f "$SERVICE_FILE" ]; then
    echo "ERROR: Service file not found: $SERVICE_FILE"
    exit 1
fi

if [ ! -f "$BIN_DIR/nabla-node" ]; then
    echo "ERROR: Binary not found at $BIN_DIR/nabla-node"
    exit 1
fi

if [ ! -f "$AVM_ELF" ]; then
    echo "WARNING: axiom-core.elf not found at $AVM_ELF"
    echo "         Node will look for it at runtime via AXIOM_ZKVM_ELF env var."
fi

if [ ! -f "$DATA_DIR/node.toml" ]; then
    echo "ERROR: node.toml not found at $DATA_DIR/node.toml"
    echo "       Run setup-node.sh first, or copy node.toml to $DATA_DIR/"
    exit 1
fi

echo "Installing AXIOM Nabla systemd service..."
echo "  Binary:   $BIN_DIR/nabla-node"
echo "  Data:     $DATA_DIR"
echo ""

# Generate service file with actual paths
sed \
    -e "s|%NABLA_BIN%|$BIN_DIR/nabla-node|g" \
    -e "s|%AVM_ELF%|$AVM_ELF|g" \
    -e "s|%DATA_DIR%|$DATA_DIR|g" \
    -e "s|%USER%|$(whoami)|g" \
    "$SERVICE_FILE" | sudo tee /etc/systemd/system/axiom-nabla.service > /dev/null

# Log rotation — don't fill the SD card
sudo mkdir -p /etc/systemd/journald.conf.d
cat <<'EOF' | sudo tee /etc/systemd/journald.conf.d/axiom-nabla.conf
[Journal]
SystemMaxUse=500M
SystemMaxFileSize=50M
MaxRetentionSec=7day
EOF

sudo systemctl daemon-reload
sudo systemctl restart systemd-journald

echo ""
echo "Service installed. Commands:"
echo "  sudo systemctl start axiom-nabla     # Start"
echo "  sudo systemctl stop axiom-nabla      # Stop"
echo "  sudo systemctl enable axiom-nabla    # Auto-start on boot"
echo "  sudo systemctl status axiom-nabla    # Status"
echo "  journalctl -u axiom-nabla -f         # Follow logs"
echo ""
echo "Dashboard: http://$(hostname -I | awk '{print $1}'):6226"
