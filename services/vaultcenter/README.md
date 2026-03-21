# VaultCenter

Central management server for VeilKey. Handles encryption keys (agentDEK), admin UI, CometBFT blockchain audit, and secret promotion.

## Build

```bash
CGO_ENABLED=1 go build -o veilkey-vaultcenter ./cmd
```

## Docker

```bash
docker compose up --build -d vaultcenter
```

## Key responsibilities

- Master password → KEK derivation → DEK management
- Admin web UI (Vue.js SPA)
- Keycenter: temp ref CRUD, promote to vault
- Registration token management for LocalVault onboarding
- CometBFT ABCI chain layer for audit trail
- Bulk-apply: template rendering + workflow proxy to LocalVault

## API

See [docs/setup/](../../docs/setup/README.md) for usage guides.

## Environment

See [docs/setup/env-vars.md](../../docs/setup/env-vars.md).
