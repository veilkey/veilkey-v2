# VeilKey Security Boundary for AI Agents

This project uses VeilKey for secret management. Follow these rules when working with secrets.

## Rules

1. **Never read `.env` files directly.** They contain infrastructure secrets and VaultCenter URLs.
2. **Never run `veilkey-cli resolve`** or any command that decrypts secrets to plaintext.
3. **Never read `/proc/*/environ`** or process memory. Resolved env vars contain plaintext.
4. **Never read `~/.bash_history`.** It may contain unmasked secret values.
5. **Use VK refs only.** Reference secrets as `VK:LOCAL:xxxxx` — never as plaintext values.

## Allowed

- Check LocalVault health: `curl -sk https://localhost:10180/health`
- Check service status: `docker compose ps`
- View logs: `tail -f .localvault/localvault.log`
- Use VK refs in code: `export DB_PASSWORD=VK:LOCAL:xxxxx`
- Check veil status: `veilkey-cli status`

## If you need a secret value

Ask the human operator. Do not attempt to resolve, decrypt, or read secrets yourself.
