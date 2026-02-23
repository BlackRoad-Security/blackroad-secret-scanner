# blackroad-secret-scanner

High-signal secret detection engine using regex pattern matching + Shannon entropy analysis.

## Features

- 🔑 **17 Pattern Rules** – AWS keys, GitHub tokens, Anthropic/OpenAI API keys, Stripe, Slack, JWT, PEM keys, Cloudflare, Vercel tokens
- 📊 **Shannon Entropy** – Detects novel secrets without explicit patterns (threshold configurable)
- 🚫 **Smart Exclusions** – Skips `.git`, `__pycache__`, `node_modules`, binary files, lockfiles
- 📄 **JSON/Text/SARIF** – Multiple output formats
- ⚡ **Fast** – Regex pre-compile, per-file deduplication

## Detected Patterns

| Pattern | Severity |
|---------|----------|
| AWS Access Key (`AKIA...`) | CRITICAL |
| GitHub Token (`ghp_`/`gho_`) | CRITICAL |
| Anthropic Key (`sk-ant-`) | CRITICAL |
| OpenAI Key (`sk-`) | CRITICAL |
| Stripe Key | CRITICAL |
| Private Key PEM | CRITICAL |
| JWT Token | HIGH |
| Basic Auth URL | HIGH |
| Generic API Key | HIGH |
| High-entropy string | MEDIUM |

## Usage

```bash
# Scan current directory
python src/secret_scanner.py .

# JSON output
python src/secret_scanner.py . --format json --output findings.json

# Only critical findings
python src/secret_scanner.py . --severity CRITICAL

# Disable entropy scanning
python src/secret_scanner.py . --no-entropy
```

## Tests

```bash
pytest tests/ -v --cov=src
```

## License

Proprietary – BlackRoad OS, Inc. All rights reserved.