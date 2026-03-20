#!/bin/bash
set -euo pipefail

# VeilKey installer for macOS
# Run from the cloned repo directory:
#   git clone https://github.com/veilkey/veilkey-selfhosted.git
#   cd veilkey-selfhosted
#   bash install/macos/install.sh
#
# ⚠️  이 스크립트의 실행으로 발생하는 모든 결과에 대한
#     귀책사유는 실행자 본인에게 있습니다.

# Must run from repo root
if [ ! -f "docker-compose.yml" ] || [ ! -d "services" ]; then
    echo "ERROR: veilkey-selfhosted repo root에서 실행하세요."
    echo "  git clone https://github.com/veilkey/veilkey-selfhosted.git"
    echo "  cd veilkey-selfhosted"
    echo "  bash scripts/install-veil-mac.sh"
    exit 1
fi

REPO_ROOT="$(pwd)"
VEILKEY_URL="${VEILKEY_URL:-https://localhost:11181}"

echo "=== VeilKey installer (macOS) ==="
echo ""
echo "  Project: $REPO_ROOT"
echo "  URL:     $VEILKEY_URL"
echo ""

# Check prerequisites
for cmd in npm cargo docker; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "ERROR: $cmd not found."
        case $cmd in
            npm)    echo "  Install: brew install node" ;;
            cargo)  echo "  Install: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh" ;;
            docker) echo "  Install: https://docs.docker.com/desktop/install/mac-install/" ;;
        esac
        exit 1
    fi
done
echo "[1/5] Prerequisites OK"

# Build CLI
echo "[2/5] Building CLI..."
cargo build --release --quiet 2>&1 | tail -3
echo "  Built"

# Install via npm (Gatekeeper-safe)
echo "[3/5] Installing via npm..."
mkdir -p "$REPO_ROOT/packages/veil-cli/native"
for bin in veil veilkey veilkey-cli veilkey-session-config; do
    if [ -f "$REPO_ROOT/target/release/$bin" ]; then
        cp "$REPO_ROOT/target/release/$bin" "$REPO_ROOT/packages/veil-cli/native/$bin"
    fi
done
npm install -g "$REPO_ROOT/packages/veil-cli" 2>&1 | tail -2

# Codesign native binaries (macOS Sequoia requirement)
NPM_NATIVE="$(npm prefix -g)/lib/node_modules/veilkey-cli/native"
echo "  Signing binaries (sudo required)..."
for bin in veil veilkey veilkey-cli veilkey-session-config; do
    if [ -f "$NPM_NATIVE/$bin" ]; then
        sudo codesign --force --sign - "$NPM_NATIVE/$bin" 2>/dev/null || true
    fi
done
echo "  Installed + signed"

# Create .veilkey/env (project-local)
echo "[4/5] Creating .veilkey/env..."
mkdir -p "$REPO_ROOT/.veilkey/config"
cat > "$REPO_ROOT/.veilkey/env" << EOF
#!/bin/sh
export VEILKEY_LOCALVAULT_URL="$VEILKEY_URL"
export VEILKEY_TLS_INSECURE=1
export VEILKEY_CONFIG="$REPO_ROOT/.veilkey/config/veilkey.yml"
export VEILKEY_CLI_BIN=$(npm prefix -g)/lib/node_modules/veilkey-cli/native/veilkey-cli
EOF

if [ ! -f "$REPO_ROOT/.veilkey/config/veilkey.yml" ]; then
    echo "threshold: 0.7" > "$REPO_ROOT/.veilkey/config/veilkey.yml"
fi

# Docker
echo "[5/5] Starting services..."
# Check port conflict
OWN_DOCKER=false
if docker compose ps --quiet 2>/dev/null | grep -q .; then
    OWN_DOCKER=true
fi
PORT="${VEILKEY_URL##*:}"
PORT="${PORT%%/*}"
if [ "$OWN_DOCKER" = false ] && lsof -i ":$PORT" -sTCP:LISTEN >/dev/null 2>&1; then
    echo ""
    echo "⚠️  포트 $PORT 가 이미 사용 중입니다."
    echo "   기존 인스턴스: cd <경로> && docker compose down"
    echo "   다른 포트:     VEILKEY_URL=https://localhost:$((PORT+1)) bash install/macos/install.sh"
    echo "   Docker 건너뜁니다."
else
    # Create .env if missing
    [ ! -f "$REPO_ROOT/.env" ] && cp "$REPO_ROOT/.env.example" "$REPO_ROOT/.env" 2>/dev/null || true
    docker compose up --build -d 2>&1 | tail -5
fi

echo ""
echo "=== Installation complete ==="
echo ""
echo "1. 초기 설정:"
echo "   https://localhost:${PORT} 접속 → 마스터/관리자 비밀번호 설정"
echo ""
echo "2. 사용:"
echo "   cd $REPO_ROOT && veil"
echo ""
echo "3. 서버 재시작 후:"
echo "   마스터 비밀번호 입력 필요 (비밀번호는 메모리에만 존재)"
echo ""
