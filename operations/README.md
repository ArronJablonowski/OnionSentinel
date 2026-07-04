# Operations

Cross-node checks and operator workflows live here.

## Verify Stack

```bash
operations/verify-stack.zsh
```

The script checks:

- Pi reachability.
- Pi access to Security Onion SSH.
- Pi access to Mac Studio n8n.
- DNS and Telegram reachability.
- n8n health.
- Docker Compose status on the Mac Studio.

## Secret Scan

```bash
operations/secret-scan.zsh
```

Run before every commit and before every push.
