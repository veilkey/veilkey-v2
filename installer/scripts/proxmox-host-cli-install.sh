#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
  cat <<'EOF'
Usage: ./scripts/proxmox-host-cli-install.sh [--activate] [--health] [root] [bundle_root]

Install the Proxmox host CLI profile:
  1. proxy assets via install.sh install-profile
  2. veilroot boundary (user + scripts + systemd)
  3. veilkey CLI
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

# Step 1: Install proxy assets via manifest engine
printf '[host-cli] step 1/3: proxy assets\n'
if [[ -n "${bundle_root}" ]]; then
  "${ROOT_DIR}/install.sh" install-profile "${args[@]}" proxmox-host-cli "${root}" "${bundle_root}"
else
  "${ROOT_DIR}/install.sh" install-profile "${args[@]}" proxmox-host-cli "${root}"
fi

# Step 2: Set up veilroot boundary (user, scripts, systemd)
BOUNDARY_SCRIPT="${root%/}/usr/local/lib/veilkey-proxy/install-veilroot-boundary.sh"
if [[ -x "${BOUNDARY_SCRIPT}" ]]; then
  printf '[host-cli] step 2/3: veilroot boundary\n'
  bash "${BOUNDARY_SCRIPT}" "${root%/}/etc/veilkey/session-tools.toml"
else
  printf '[host-cli] step 2/3: skipped (install-veilroot-boundary.sh not found)\n'
fi

# Step 3: Install veilkey CLI (if source available)
CLI_INSTALL="${ROOT_DIR}/../client/cli/install.sh"
if [[ -f "${CLI_INSTALL}" ]]; then
  printf '[host-cli] step 3/3: veilkey CLI\n'
  bash "${CLI_INSTALL}"
else
  printf '[host-cli] step 3/3: skipped (client/cli/install.sh not found)\n'
fi

printf '[host-cli] completed\n'
