# Proxmox Host — veil-cli Installation

Install veil CLI on the Proxmox host to use `veil` directly without entering the LXC container.

## Prerequisites

- Rust / cargo: `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`
- VeilKey LXC running and unlocked

## Install

```bash
cd veilkey-selfhosted
VEILKEY_URL=https://<CT_IP>:<VC_PORT> bash install/proxmox-lxc-debian/install-veil-cli.sh
```

## After install

```bash
# Load env (or add to ~/.bashrc)
source ~/.veilkey/env

# Check connection
veilkey-cli status

# Enter protected shell
veil
```

## Uninstall

```bash
bash install/proxmox-lxc-debian/uninstall-veil-cli.sh
```

See [uninstall-veil-cli.sh](./uninstall-veil-cli.sh) for details.
