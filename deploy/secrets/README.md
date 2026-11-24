# Docker secrets

Nothing in this folder except this README is ever committed (see `.gitignore`). Create each file on the server, owned by root, mode `0400`.

| File | How to create |
| --- | --- |
| `pg_owner_password` | `openssl rand -base64 32 > pg_owner_password` |
| `pg_app_password` | `openssl rand -base64 32 > pg_app_password` |
| `pg_readonly_password` | `openssl rand -base64 32 > pg_readonly_password` |
| `redis_password` | `openssl rand -hex 32 > redis_password` |
| `master_key` | `openssl rand -base64 32 > master_key` (must decode to exactly 32 bytes) |
| `redaction_salt` | `openssl rand -base64 48 > redaction_salt` |
| `anthropic_api_key` | The administrator pastes the platform's Anthropic API key into this file (Phase 4). An empty file is allowed: LLM steps are then refused and the deterministic rules decide alone. |

The master key is never included in backups. Losing it makes TOTP secrets unreadable (users re-enrol).

Later phases add: `github_app_private_key`, `github_webhook_secret`.
