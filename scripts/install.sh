#!/usr/bin/env bash
# Install git-gpg release binary to a configurable location.
# Usage: ./scripts/install.sh [DEST_DIR]
# Default: ~/.local/bin
set -euo pipefail

DEST_DIR="${1:-${INSTALL_DIR:-$HOME/.local/bin}}"
mkdir -p "$DEST_DIR"

echo "Building release binary..."
cargo build --release

echo "Installing to $DEST_DIR/git-gpg..."
install -m 755 "target/release/git-gpg" "$DEST_DIR/git-gpg"

echo "✓ Installed to $DEST_DIR/git-gpg"
echo "  Ensure $DEST_DIR is on your PATH."
