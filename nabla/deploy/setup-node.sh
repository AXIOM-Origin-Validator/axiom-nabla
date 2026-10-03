#!/usr/bin/env bash
set -euo pipefail

# Resolve paths relative to tarball layout: deploy/ is inside axiom/nabla/
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NABLA_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN_DIR="$NABLA_DIR/bin"

DATA_DIR="${DATA_DIR:-$HOME/.axiom}"

# ── Args ────────────────────────────────────────────────────────────────────
#   --name NAME   your node's name on the network (prompted if omitted)
#   --yes         never prompt; use --name / $NODE_NAME / the template default
ASSUME_YES=0
CLI_NAME=""
while [ $# -gt 0 ]; do
    case "$1" in
        --name)      CLI_NAME="${2:-}"; shift 2 ;;
        --name=*)    CLI_NAME="${1#*=}"; shift ;;
        --data-dir)  DATA_DIR="${2:-}"; shift 2 ;;
        --data-dir=*) DATA_DIR="${1#*=}"; shift ;;
        -y|--yes)    ASSUME_YES=1; shift ;;
        -h|--help)
            echo "Usage: setup-node.sh [--name NAME] [--data-dir DIR] [--yes]"
            echo ""
            echo "  --name NAME   your node's name on the network (UTF-8, max 64 bytes)."
            echo "                Prompted for if omitted. Emoji and non-Latin scripts"
            echo "                are fine — 焼き鳥 is a perfectly good node name."
            echo "  --data-dir    where the node keeps its identity and state"
            echo "                (default: \$HOME/.axiom)"
            echo "  --yes         never prompt (for curl | bash and CI)"
            exit 0 ;;
        *) echo "Unknown option: $1 (try --help)"; exit 1 ;;
    esac
done

TEMPLATE_TOML="$NABLA_DIR/node.toml"
if [ -f "$TEMPLATE_TOML" ]; then
    TEMPLATE_NAME=$(grep '^name' "$TEMPLATE_TOML" | sed 's/.*= *"\(.*\)"/\1/' | head -1)
    PORT=$(grep '^port' "$TEMPLATE_TOML" | sed 's/.*= *\([0-9]*\).*/\1/' | head -1)
fi
PORT="${PORT:-6225}"

echo "╔══════════════════════════════════════╗"
echo "║   AXIOM Nabla Node Setup             ║"
echo "╚══════════════════════════════════════╝"
echo ""

# ── Name your node ──────────────────────────────────────────────────────────
#
# ⚠ THE NAME IS BAKED INTO THE NBC AT FIRST START AND CANNOT BE CHANGED LATER
# without re-issuing the node's identity. So it is settled HERE, before any key
# exists — not left in a file the operator is trusted to have edited.
#
# History (2026-08-25): this script only READ a name out of the template and
# never wrote one, so anyone who installed without hand-editing node.toml first
# came up as the fallback — every `curl | bash` citizen on the network shared
# one name, which makes peer lists, dashboards and logs useless exactly when
# they matter. Found on the Pi: node.toml said "nabla-pi-Orthanc", the NBC said
# ".axiom". Do not reduce this back to a silent default.
DEFAULT_NAME="${CLI_NAME:-${NODE_NAME:-}}"
if [ -z "$DEFAULT_NAME" ]; then
    # A hostname beats a generic placeholder, but it is only ever a SUGGESTION.
    DEFAULT_NAME="$(hostname -s 2>/dev/null || echo node)"
    case "$TEMPLATE_NAME" in
        ""|"nabla-node") : ;;               # placeholder — don't propose it
        *) DEFAULT_NAME="$TEMPLATE_NAME" ;; # operator already chose one
    esac
fi

NODE_NAME="${CLI_NAME:-${NODE_NAME:-}}"
if [ -z "$NODE_NAME" ]; then
    if [ "$ASSUME_YES" = "1" ] || [ ! -t 0 ]; then
        NODE_NAME="$DEFAULT_NAME"
    else
        echo "  Your node needs a name. It is how peers, dashboards and logs"
        echo "  will refer to you, and it is permanent once your identity is"
        echo "  issued. Any UTF-8 up to 64 bytes — 焼き鳥, tokyo-01, whatever."
        echo ""
        printf "  Node name [%s]: " "$DEFAULT_NAME"
        read -r REPLY_NAME || REPLY_NAME=""
        NODE_NAME="${REPLY_NAME:-$DEFAULT_NAME}"
    fi
fi

# Validate here, not at first start — a node that dies on its name after the
# operator walked away is worse than one that refuses to be set up.
NODE_NAME="$(printf '%s' "$NODE_NAME" | tr -d '\r\n')"
if [ -z "$NODE_NAME" ]; then
    echo "ERROR: node name cannot be empty."; exit 1
fi
NAME_BYTES=$(printf '%s' "$NODE_NAME" | LC_ALL=C wc -c | tr -d ' ')
if [ "$NAME_BYTES" -gt 64 ]; then
    echo "ERROR: node name is $NAME_BYTES bytes; the limit is 64."
    echo "       (Non-Latin characters use several bytes each.)"
    exit 1
fi
case "$NODE_NAME" in
    *'"'*) echo "ERROR: node name cannot contain a double quote."; exit 1 ;;
esac

# ── Greek names are reserved for genesis nodes ──────────────────────────────
#
# ⚠ THIS CHECK IS CONVENIENCE, NOT SECURITY (RULE 5(A)). An attacker edits this
# script. The enforcement that actually holds is in CORE:
#   core/logic/src/vbc.rs::enforce_nabla_name_reservation  (called from
#   vbc.rs:211 on the NBC bundle verify path) rejects a reserved name with
#   ValidationError::GenesisNameReserved unless the NBC's validator_id IS the
#   pinned NABLA_GENESIS_VALIDATORS key for that name.
#
# All 24 Greek letters are reserved, not only the 10 currently deployed, and
# both the short ("alpha") and formal ("axiom-first-penguin-alpha") forms
# collapse to the same slot. This check exists so an honest operator is told
# NOW, instead of watching their node get its NBC refused after install.
GREEK="alpha beta gamma delta epsilon zeta eta theta iota kappa lambda mu nu xi \
omicron pi rho sigma tau upsilon phi chi psi omega"

# The SYMBOLS impersonate just as well as the words — "α" reads as alpha in any
# peer list. Core's reserved_name_index only matches the Latin transliterations,
# so these pass Core today; see the CoreID note in GUIDE_Nabla §5.6a.
GREEK_SYMBOLS="α β γ δ ε ζ η θ ι κ λ μ ν ξ ο π ρ σ τ υ φ χ ψ ω ς \
Α Β Γ Δ Ε Ζ Η Θ Ι Κ Λ Μ Ν Ξ Ο Π Ρ Σ Τ Υ Φ Χ Ψ Ω"

_check_name="$(printf '%s' "$NODE_NAME" | tr '[:upper:]' '[:lower:]')"
_check_name="${_check_name#axiom-first-penguin-}"
for g in $GREEK_SYMBOLS; do
    if [ "$NODE_NAME" = "$g" ]; then
        echo "ERROR: \"$NODE_NAME\" is a Greek letter, reserved for genesis nodes."
        echo ""
        echo "  A single Greek symbol is indistinguishable from a genesis node"
        echo "  in peer lists, dashboards and logs. Pick a name of your own."
        exit 1
    fi
done
for g in $GREEK; do
    if [ "$_check_name" = "$g" ]; then
        echo "ERROR: \"$NODE_NAME\" is reserved."
        echo ""
        echo "  The 24 Greek letter names belong to the genesis nodes. Core"
        echo "  refuses an NBC carrying one unless it is signed to the pinned"
        echo "  genesis key for that name, so this node would be issued no"
        echo "  identity and could never join."
        echo ""
        echo "  Pick something of your own — a place, a handle, 焼き鳥."
        exit 1
    fi
done

echo "  Data dir:  $DATA_DIR"
echo "  Name:      $NODE_NAME  (${NAME_BYTES} bytes)"
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
    echo "── Writing node.toml → $NODE_TOML"
    cp "$TEMPLATE_TOML" "$NODE_TOML"
else
    echo "── node.toml exists at $NODE_TOML"
fi

# Stamp the chosen name in. The binary reads node.toml at first start and puts
# this string in its NBC request, so this write is what actually names the node
# (nabla_node.rs: node_name_for_keygen → subject.node_name → NbcIssuanceRequest).
if grep -qE '^name[[:space:]]*=' "$NODE_TOML"; then
    tmp="$(mktemp)"
    NN="$NODE_NAME" awk '
        BEGIN { done=0 }
        /^name[[:space:]]*=/ && !done { printf "name = \"%s\"\n", ENVIRON["NN"]; done=1; next }
        { print }
    ' "$NODE_TOML" > "$tmp" && mv "$tmp" "$NODE_TOML"
else
    printf 'name = "%s"\n' "$NODE_NAME" >> "$NODE_TOML"
fi
echo "   name = \"$NODE_NAME\""

# ⚠ An identity that already exists has the OLD name baked into its NBC —
# rewriting node.toml now changes nothing on the network. Say so plainly rather
# than letting the operator believe the rename took.
if [ -f "$DATA_DIR/config/nbc.json" ]; then
    echo ""
    echo "   ⚠ This node ALREADY HAS AN IDENTITY (config/nbc.json)."
    echo "     Its name was fixed when that identity was issued, and editing"
    echo "     node.toml now does NOT rename it on the network."
    echo "     To adopt \"$NODE_NAME\" you must re-issue: stop the service,"
    echo "     remove $DATA_DIR/config (and $DATA_DIR/private if present),"
    echo "     then run this script again to rejoin as a new node."
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
