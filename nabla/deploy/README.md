# AXIOM Nabla Node Deployment

One machine = one node. Genesis nodes ship with a pre-signed NBC. Generic nodes
receive their NBC from a qualified peer on first connect (chain-of-trust).

## Quick Start (Generic Node)

    # 1. Extract archive
    tar xzf axiom-nabla-<arch>-<version>.tar.gz
    cd axiom/nabla

    # 2. Edit node name + port
    nano node.toml

    # 3. Edit bootstrap peers (add a qualified node's IP:port)
    nano bootstrap.toml

    # 4. Run setup (installs binaries + zkVM artifacts)
    ./deploy/setup-node.sh

    # 5. Install systemd service + start
    ./deploy/install-service.sh
    sudo systemctl enable --now axiom-nabla

On first connect, the node presents itself to a qualified Nabla peer.
The peer signs and issues an NBC via Core (k=1 SPHINCS+ signature).
The new node verifies the issuer's authority using root public keys
hardcoded in Core (`NABLA_ROOT_AUTHORITY_PKS` in genesis.rs).

## Quick Start (Genesis Node)

Genesis tarballs include a pre-signed NBC in `config/` and private keys
in `private/`. The setup script detects and installs these automatically.

    tar xzf axiom-nabla-alpha-linux-x86_64.tar.gz
    cd axiom-nabla-alpha
    nano node.toml
    nano bootstrap.toml
    ./deploy/setup-node.sh        # installs pre-signed NBC + keys
    ./deploy/install-service.sh
    sudo systemctl enable --now axiom-nabla

## macOS

    # Binary tarball (pre-built, no Xcode needed):
    tar xzf axiom-nabla-macos-arm64-vX.Y.Z.tar.gz
    cd axiom/nabla
    nano node.toml
    ./deploy/setup-macos.sh

    # To repack a binary tarball from source (for other Macs):
    ./deploy/repack-macos.sh

## Security

- **Root authority keys** are used only during the genesis ceremony and then
  moved to offline cold storage. They are NEVER shipped in deployment tarballs.
- **Root authority public keys** are hardcoded in Core (`genesis.rs`). Every
  node has them compiled in — no external key distribution needed.
- **NBC chain-of-trust:** Genesis nodes have NBCs signed directly by root keys
  (chain_depth=0). New nodes get NBCs signed by a qualified peer whose own NBC
  chains back to a root key. Core verifies the full chain on every connection.
- **Private keys** (in genesis tarballs) must be secured by the operator.
  After setup copies them to `~/.axiom/config/`, restrict permissions (chmod 600).

## Tarball Contents

**Generic tarball** (no identity — gets NBC from peer on connect):
```
axiom/nabla/
  bin/nabla-node, nabla-ceremony
  deploy/setup-node.sh, install-service.sh, ...
  zkvm/axiom-core.elf, image-id.hex
  node.toml, bootstrap.toml
```

**Genesis tarball** (pre-signed identity included):
```
axiom-nabla-alpha/
  bin/nabla-node, nabla-ceremony
  config/nbc.json, nabla_sphincs.pub, nabla_ed25519.pub, nabla_dilithium.pub
  private/nabla_sphincs.key, nabla_ed25519.key, nabla_dilithium.key
  deploy/setup-node.sh, install-service.sh, ...
  zkvm/axiom-core.elf, image-id.hex
  node.toml, bootstrap.toml
```

## Operations

    # Check health
    ./deploy/health-check.sh

    # Follow logs
    journalctl -u axiom-nabla -f

    # Restart (state recovers from WAL + snapshots)
    sudo systemctl restart axiom-nabla

    # Stop
    sudo systemctl stop axiom-nabla

    # Uninstall service
    ./deploy/uninstall-service.sh

    # Reset (destroy identity + state, start fresh)
    sudo systemctl stop axiom-nabla
    rm -rf ~/.axiom
    ./deploy/setup-node.sh

## Pi Notes

- 64-bit OS required (aarch64)
- 2GB RAM is enough
- 32GB SD card minimum
- Log rotation: 500MB max, 7 day retention
