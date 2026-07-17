#!/usr/bin/env bash
set -euo pipefail

echo "Removing AXIOM Nabla service..."
sudo systemctl stop axiom-nabla 2>/dev/null || true
sudo systemctl disable axiom-nabla 2>/dev/null || true
sudo rm -f /etc/systemd/system/axiom-nabla.service
sudo rm -f /etc/systemd/journald.conf.d/axiom-nabla.conf
sudo systemctl daemon-reload
echo "Done. Data in ~/.axiom is NOT removed."
