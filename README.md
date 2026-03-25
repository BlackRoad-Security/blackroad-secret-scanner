<!-- BlackRoad SEO Enhanced -->

# ulackroad secret scanner

> Part of **[BlackRoad OS](https://blackroad.io)** — Sovereign Computing for Everyone

[![BlackRoad OS](https://img.shields.io/badge/BlackRoad-OS-ff1d6c?style=for-the-badge)](https://blackroad.io)
[![BlackRoad Security](https://img.shields.io/badge/Org-BlackRoad-Security-2979ff?style=for-the-badge)](https://github.com/BlackRoad-Security)
[![License](https://img.shields.io/badge/License-Proprietary-f5a623?style=for-the-badge)](LICENSE)

**ulackroad secret scanner** is part of the **BlackRoad OS** ecosystem — a sovereign, distributed operating system built on edge computing, local AI, and mesh networking by **BlackRoad OS, Inc.**

## About BlackRoad OS

BlackRoad OS is a sovereign computing platform that runs AI locally on your own hardware. No cloud dependencies. No API keys. No surveillance. Built by [BlackRoad OS, Inc.](https://github.com/BlackRoad-OS-Inc), a Delaware C-Corp founded in 2025.

### Key Features
- **Local AI** — Run LLMs on Raspberry Pi, Hailo-8, and commodity hardware
- **Mesh Networking** — WireGuard VPN, NATS pub/sub, peer-to-peer communication
- **Edge Computing** — 52 TOPS of AI acceleration across a Pi fleet
- **Self-Hosted Everything** — Git, DNS, storage, CI/CD, chat — all sovereign
- **Zero Cloud Dependencies** — Your data stays on your hardware

### The BlackRoad Ecosystem
| Organization | Focus |
|---|---|
| [BlackRoad OS](https://github.com/BlackRoad-OS) | Core platform and applications |
| [BlackRoad OS, Inc.](https://github.com/BlackRoad-OS-Inc) | Corporate and enterprise |
| [BlackRoad AI](https://github.com/BlackRoad-AI) | Artificial intelligence and ML |
| [BlackRoad Hardware](https://github.com/BlackRoad-Hardware) | Edge hardware and IoT |
| [BlackRoad Security](https://github.com/BlackRoad-Security) | Cybersecurity and auditing |
| [BlackRoad Quantum](https://github.com/BlackRoad-Quantum) | Quantum computing research |
| [BlackRoad Agents](https://github.com/BlackRoad-Agents) | Autonomous AI agents |
| [BlackRoad Network](https://github.com/BlackRoad-Network) | Mesh and distributed networking |
| [BlackRoad Education](https://github.com/BlackRoad-Education) | Learning and tutoring platforms |
| [BlackRoad Labs](https://github.com/BlackRoad-Labs) | Research and experiments |
| [BlackRoad Cloud](https://github.com/BlackRoad-Cloud) | Self-hosted cloud infrastructure |
| [BlackRoad Forge](https://github.com/BlackRoad-Forge) | Developer tools and utilities |

### Links
- **Website**: [blackroad.io](https://blackroad.io)
- **Documentation**: [docs.blackroad.io](https://docs.blackroad.io)
- **Chat**: [chat.blackroad.io](https://chat.blackroad.io)
- **Search**: [search.blackroad.io](https://search.blackroad.io)

---


> BlackRoad Security - ublackroad secret scanner

Part of the [BlackRoad OS](https://blackroad.io) ecosystem — [BlackRoad-Security](https://github.com/BlackRoad-Security)

---

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
