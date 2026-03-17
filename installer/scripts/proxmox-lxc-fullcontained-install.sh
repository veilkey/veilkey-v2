#!/usr/bin/env bash
# VeilKey LXC Full-Contained — Orchestration Installer
# Installs everything inside a single LXC:
#   1. KeyCenter + LocalVault (via proxmox-lxc-allinone-install.sh)
#   2. Proxy runtime (via proxy/install.sh)
#   3. Veilroot boundary (via install-veilroot-boundary.sh)
#   4. VeilKey CLI (via client/cli/install.sh)
#
# Usage:
#   bash installer/scripts/proxmox-lxc-fullcontained-install.sh [--activate] [root] [bundle_root]
#
# Required env:
#   VEILKEY_KEYCENTER_PASSWORD
#   VEILKEY_LOCALVAULT_PASSWORD
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "${ROOT_DIR}/.." && pwd)"

usage() {
  cat <<'EOF'
Usage: ./scripts/proxmox-lxc-fullcontained-install.sh [--activate] [root] [bundle_root]

Install the full VeilKey stack inside a single LXC:
  1. keycenter + localvault + bootstrap SSH (via lxc-allinone)
  2. proxy runtime + session-tools
  3. veilroot boundary (user + scripts + systemd)
  4. veilkey CLI
EOF
}

if [[ "${1:-}" =~ ^(-h|--help)$ ]]; then
  usage
  exit 0
fi

args=()
while [[ $# -gt 0 && "${1:-}" == --* ]]; do
  args+=("$1")
  shift
done

root="${1:-/}"
bundle_root="${2:-}"

# Step 1: KeyCenter + LocalVault via existing allinone installer
printf '[fullcontained] step 1/4: keycenter + localvault\n'
if [[ -n "${bundle_root}" ]]; then
  "${ROOT_DIR}/scripts/proxmox-lxc-allinone-install.sh" "${args[@]}" "${root}" "${bundle_root}"
else
  "${ROOT_DIR}/scripts/proxmox-lxc-allinone-install.sh" "${args[@]}" "${root}"
fi

# Step 2: Proxy runtime
printf '[fullcontained] step 2/4: proxy runtime\n'
VEILKEY_LOCALVAULT_URL="${VEILKEY_LOCALVAULT_URL:-https://127.0.0.1:10180}" \
VEILKEY_KEYCENTER_URL="${VEILKEY_KEYCENTER_URL:-https://127.0.0.1:10181}" \
  bash "${ROOT_DIR}/scripts/proxy/install.sh" "${root}"

# Step 3: Veilroot boundary
BOUNDARY_SCRIPT="${root%/}/usr/local/lib/veilkey-proxy/install-veilroot-boundary.sh"
if [[ ! -x "${BOUNDARY_SCRIPT}" ]]; then
  BOUNDARY_SCRIPT="${REPO_ROOT}/services/proxy/deploy/host/install-veilroot-boundary.sh"
fi
if [[ -x "${BOUNDARY_SCRIPT}" ]]; then
  printf '[fullcontained] step 3/4: veilroot boundary\n'
  bash "${BOUNDARY_SCRIPT}" "${root%/}/etc/veilkey/session-tools.toml"
else
  printf '[fullcontained] step 3/4: skipped (install-veilroot-boundary.sh not found)\n'
fi

# Step 4: VeilKey CLI
CLI_INSTALL="${REPO_ROOT}/client/cli/install.sh"
if [[ -f "${CLI_INSTALL}" ]]; then
  printf '[fullcontained] step 4/4: veilkey CLI\n'
  bash "${CLI_INSTALL}"
else
  printf '[fullcontained] step 4/4: skipped (client/cli/install.sh not found)\n'
fi

printf '[fullcontained] completed\n'
