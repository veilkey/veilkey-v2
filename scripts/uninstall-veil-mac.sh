#!/bin/bash
set -euo pipefail

# VeilKey uninstaller for macOS
# Usage: curl -sL .../uninstall-veil-mac.sh | bash
#
# ⚠️  이 스크립트의 실행으로 발생하는 모든 결과에 대한
#     귀책사유는 실행자 본인에게 있습니다.

BIN_DIR="/usr/local/bin"
INSTALL_DIR="${VEILKEY_INSTALL_DIR:-$HOME/.veilkey}"

echo "=== VeilKey uninstaller (macOS) ==="
echo ""

# 1. Remove binaries
echo "[1/3] Removing binaries..."
for bin in veil veilkey veilkey-cli veilkey-session-config; do
    if [ -f "$BIN_DIR/$bin" ]; then
        sudo rm "$BIN_DIR/$bin"
        echo "  Removed $bin"
    fi
done

# 2. Stop docker
if [ -f "$INSTALL_DIR/docker-compose.yml" ]; then
    echo "[2/3] Docker services..."
    echo "  To stop:  cd $INSTALL_DIR && docker compose down"
    echo "  To purge: cd $INSTALL_DIR && docker compose down && rm -rf data/"
else
    echo "[2/3] No docker-compose.yml found (skip)"
fi

# 3. Remove install dir
echo "[3/3] Install directory: $INSTALL_DIR"
echo "  To remove: rm -rf $INSTALL_DIR"
echo "  (not removed automatically — may contain your vault data)"

echo ""
echo "=== Uninstall complete ==="
