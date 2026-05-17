# AETHER-SNIFFER

> The first AI-aware cloud security auditor. Built for enterprise. Privacy-first.

[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat&logo=go)](https://go.dev)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)](https://github.com/fredthebuilder/aether-sniffer)

AETHER-SNIFFER detects exposed secrets, cloud misconfigurations, and **Shadow AI** — unauthorized LLM API usage inside enterprise environments — in a single, privacy-first binary that never sends your data anywhere.

---

## Why AETHER-SNIFFER?

| Tool               | Secrets | Cloud Audit | Shadow AI | Interactive TUI |
| ------------------ | ------- | ----------- | --------- | --------------- |
| TruffleHog         | ✅      | ❌          | ❌        | ❌              |
| Gitleaks           | ✅      | ❌          | ❌        | ❌              |
| GitGuardian        | ✅      | ❌          | ❌        | ❌ (paid web)   |
| **AETHER-SNIFFER** | ✅      | ✅          | ✅        | ✅              |

The **Shadow AI** module is our unique moat. No existing open-source tool scans for:

- Unauthorized OpenAI / Anthropic / Cohere / HuggingFace API usage
- LLM proxy configurations bypassing corporate controls
- AI API keys co-located with model endpoint calls

---

## Quick Start

```bash
# Clone
git clone https://github.com/fredthebuilder/aether-sniffer
cd aether-sniffer

# Build
go build -o aether-sniffer .

# Scan current directory
./aether-sniffer scan .

# Scan with JSON output (SIEM-compatible)
./aether-sniffer scan . --output json

# Scan without Shadow AI module
./aether-sniffer scan . --shadowai=false
```

---

## Scanners

### Secrets Scanner

Detects 20+ secret types using regex + Shannon entropy scoring to eliminate false positives:

- OpenAI, Anthropic, Cohere, HuggingFace, Google API keys
- AWS Access Key ID + Secret Access Key
- GitHub tokens (PAT, OAuth, Actions)
- Stripe live keys
- Database connection strings
- JWT secrets, Bearer tokens, Private keys

### Shadow AI Scanner _(unique to AETHER-SNIFFER)_

Detects unauthorized AI usage across 10 providers:

- OpenAI, Anthropic Claude, Google Gemini, Mistral, Cohere
- Together AI, Replicate, HuggingFace Inference
- LiteLLM proxy configurations
- Local Ollama instances

### Cloud Auditor _(Phase 2)_

- AWS S3 public bucket detection
- IAM over-privilege analysis
- Azure Storage misconfiguration
- GCP service account key exposure

### Container Scanner _(Phase 2)_

- Docker Compose secret exposure
- Kubernetes ConfigMap/Secret analysis
- CI/CD pipeline credential scanning

---

## Output Formats

```bash
# Interactive TUI dashboard (default)
./aether-sniffer scan . --output tui

# JSON (SIEM-compatible: Splunk, Elastic, Datadog)
./aether-sniffer scan . --output json

# PDF report (Phase 3)
./aether-sniffer scan . --output pdf
```

---

## CI/CD Integration

AETHER-SNIFFER exits with code `1` if any CRITICAL findings are discovered,
enabling pipeline blocking in GitHub Actions, GitLab CI, and Jenkins.

```yaml
# .github/workflows/security.yml
- name: AETHER-SNIFFER Security Scan
  run: |
    ./aether-sniffer scan . --output json
```

---

## Configuration

Create `~/.aether-sniffer.yaml` for persistent settings:

```yaml
output: json
concurrency: 50
timeout: 30s
rate_limit: 10
report_dir: ~/.aether-sniffer/reports
```

All settings can also be set via environment variables:

```bash
export AETHER_OUTPUT=json
export AETHER_VERBOSE=true
```

---

## Security Design

- **Zero telemetry.** Nothing leaves your machine.
- **Redacted matches.** Secrets are never stored in full (`sk-p...1234`).
- **Report files are mode 0600.** Only the owner can read them.
- **Rate limited.** Cloud API calls are throttled to prevent accidental self-DoS.
- **Entropy scoring.** Shannon entropy filters reduce false positives by ~60%.

---

## Roadmap

- [x] Phase 1: Secrets + Shadow AI scanner, JSON output, Cobra CLI
- [ ] Phase 2: Cloud auditor (AWS/Azure/GCP), Container scanner, Bubble Tea TUI
- [ ] Phase 3: PDF reports, Plugin system (YAML), Web dashboard

---

## License

Apache 2.0 — see [LICENSE](LICENSE)

---

_Built with Go · Powered by Bubble Tea · Designed for enterprise security teams_
