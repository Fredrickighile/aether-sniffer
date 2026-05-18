# AETHER-SNIFFER

> **The first AI-aware cloud security auditor.**
> Detects exposed secrets, cloud misconfigurations, and Shadow AI in seconds.

[![Release](https://img.shields.io/github/v/release/Fredrickighile/aether-sniffer?color=1D9E75)](https://github.com/Fredrickighile/aether-sniffer/releases)
[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?logo=go)](https://go.dev)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)](https://github.com/Fredrickighile/aether-sniffer/releases)
[![CI](https://github.com/Fredrickighile/aether-sniffer/actions/workflows/aether-sniffer.yml/badge.svg)](https://github.com/Fredrickighile/aether-sniffer/actions)

---

## What is Shadow AI?

Developers paste company data into ChatGPT, Claude, and Copilot every day without realising the risk.
That data goes to third-party servers. In Canada, that violates PIPEDA. In Europe, it violates GDPR.
IBM says Shadow AI adds **$670,000** to the cost of every data breach.

**AETHER-SNIFFER is the only open-source tool that detects this.**

---

## What It Does

```
aether-sniffer scan /path/to/project
```

In one command it finds:

- **Exposed secrets** — API keys, tokens, passwords, private keys (20+ types)
- **Shadow AI** — unauthorized OpenAI, Anthropic, Cohere, HuggingFace endpoints in your code
- **AWS misconfigurations** — public S3 buckets, stale IAM keys
- **Azure misconfigurations** — public blob access, weak TLS, HTTP-only storage
- **GCP misconfigurations** — public buckets, stale service account keys

Results are shown in a beautiful interactive terminal dashboard, exported as JSON for SIEMs, or generated as a professional PDF report for compliance teams.

---

## Why AETHER-SNIFFER?

| Feature | TruffleHog | Gitleaks | GitGuardian | **AETHER-SNIFFER** |
|---|---|---|---|---|
| Secret scanning | ✅ | ✅ | ✅ (paid) | ✅ |
| Shadow AI detection | ❌ | ❌ | ❌ | ✅ **unique** |
| AWS / Azure / GCP audit | ❌ | ❌ | ❌ | ✅ |
| Interactive TUI dashboard | ❌ | ❌ | ❌ | ✅ |
| PDF compliance report | ❌ | ❌ | ❌ | ✅ |
| Single binary, no install | ❌ | ✅ | ❌ | ✅ |
| Fully local, privacy-first | ✅ | ✅ | ❌ | ✅ |
| Free and open source | ✅ | ✅ | ❌ | ✅ |

---

## Quick Install

**Linux / macOS:**
```bash
curl -sSL https://github.com/Fredrickighile/aether-sniffer/releases/latest/download/aether-sniffer_linux_amd64.tar.gz | tar xz
sudo mv aether-sniffer /usr/local/bin/
aether-sniffer scan .
```

**Windows:**
Download `aether-sniffer_windows_amd64.zip` from the [releases page](https://github.com/Fredrickighile/aether-sniffer/releases), extract, and run:
```
aether-sniffer.exe scan .
```

**Build from source:**
```bash
git clone https://github.com/Fredrickighile/aether-sniffer.git
cd aether-sniffer
go build -o aether-sniffer .
./aether-sniffer scan .
```

---

## Usage

### Scan a local codebase
```bash
# Interactive TUI dashboard (default)
aether-sniffer scan /path/to/project

# JSON output for SIEM (Splunk, Datadog, Elastic)
aether-sniffer scan /path/to/project --output json

# Professional PDF report for compliance teams
aether-sniffer scan /path/to/project --output pdf
```

### Audit cloud infrastructure
```bash
# AWS (uses ~/.aws/credentials automatically)
aether-sniffer cloud --provider aws --region ca-central-1

# Azure (uses 'az login' automatically)
aether-sniffer cloud --provider azure --subscription YOUR_SUBSCRIPTION_ID

# GCP (uses 'gcloud auth application-default login' automatically)
aether-sniffer cloud --provider gcp --project YOUR_PROJECT_ID
```

### CI/CD pipeline integration
```yaml
name: AETHER-SNIFFER Security Scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run AETHER-SNIFFER
        run: |
          curl -sSL https://github.com/Fredrickighile/aether-sniffer/releases/latest/download/aether-sniffer_linux_amd64.tar.gz | tar xz
          ./aether-sniffer scan . --output json
```

---

## Secret Types Detected

| Category | Types |
|---|---|
| AI / LLM | OpenAI, Anthropic, Cohere, HuggingFace, Google Gemini, Mistral |
| Cloud | AWS Access Key + Secret, Google API Key, Azure Storage Key |
| Version Control | GitHub PAT, GitHub OAuth, GitHub Actions tokens |
| Payments | Stripe live secret + publishable keys |
| Communication | Slack bot tokens, Slack webhooks, Twilio auth tokens |
| Database | PostgreSQL, MySQL, MongoDB, Redis connection strings |
| Auth | JWT secrets, Bearer tokens, Private keys (RSA/EC/SSH) |

---

## Shadow AI Providers Detected

`OpenAI` `Anthropic Claude` `Google Gemini` `Cohere` `HuggingFace` `Mistral` `Together AI` `Replicate` `LiteLLM Proxy` `Ollama`

---

## Security Design

- **Zero telemetry.** Nothing leaves your machine. Ever.
- **Redacted matches.** Secrets never stored in full — always shown as `sk-a...6789`
- **Report files are mode 0600.** Only the file owner can read them.
- **Read-only cloud scanning.** The tool never modifies any cloud resource.
- **Rate limited.** Cloud API calls throttled to prevent accidental self-DoS.
- **Entropy scoring.** Shannon entropy filtering reduces false positives by ~80%.
- **Lockfile exclusion.** go.sum, package-lock.json, yarn.lock always skipped.

---

## Roadmap

- [x] Secrets scanner - 20+ credential types
- [x] Shadow AI scanner - 10 AI providers
- [x] Interactive Bubble Tea TUI dashboard
- [x] JSON output - SIEM compatible
- [x] AWS cloud auditor - S3, IAM
- [x] Azure cloud auditor - Storage, TLS, ACL
- [x] GCP cloud auditor - Buckets, Service Accounts
- [x] PDF compliance report
- [x] GitHub Actions CI/CD integration
- [x] GoReleaser - Windows, Linux, macOS binaries
- [ ] Web dashboard with team accounts (SaaS)
- [ ] Scheduled scans with Slack alerts
- [ ] YAML plugin system for custom rules

---

## Contributing

Pull requests are welcome.

```bash
git clone https://github.com/Fredrickighile/aether-sniffer.git
cd aether-sniffer
go mod tidy
go build -o aether-sniffer .
```

---

## License

Apache 2.0 - see [LICENSE](LICENSE)

---

*Built with Go · Bubble Tea · Lip Gloss · Designed for enterprise security teams*

*2026 Fred Ighile - github.com/Fredrickighile/aether-sniffer*
