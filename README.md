# AETHER-SNIFFER

> **AI-aware secret and Shadow AI scanner.**
> Finds exposed credentials and unauthorized AI API usage in your codebase.

[![Release](https://img.shields.io/github/v/release/Fredrickighile/aether-sniffer?color=1D9E75)](https://github.com/Fredrickighile/aether-sniffer/releases)
[![Go Version](https://img.shields.io/badge/Go-1.26+-00ADD8?logo=go)](https://go.dev)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)](https://github.com/Fredrickighile/aether-sniffer/releases)
[![CI](https://github.com/Fredrickighile/aether-sniffer/actions/workflows/aether-sniffer.yml/badge.svg)](https://github.com/Fredrickighile/aether-sniffer/actions)

---

## What is Shadow AI?

Developers send company data to AI services like ChatGPT, Claude, and Copilot, often without approval.
That data goes to third-party servers, which can create compliance exposure under privacy laws such as
PIPEDA (Canada) and GDPR (EU). According to IBM's Cost of a Data Breach research, breaches involving
unsanctioned AI tools cost more on average.

AETHER-SNIFFER looks for the footprints of this in your code: hardcoded AI provider endpoints and
the API keys that go with them.

---

## What It Does

```
aether-sniffer scan /path/to/project
```

- **Exposed secrets**: API keys, tokens, passwords, and private keys (20 credential patterns)
- **Shadow AI**: hardcoded endpoints for 10 AI providers (OpenAI, Anthropic, Cohere, HuggingFace, and more)
- **Cloud auditing (experimental)**: AWS, Azure and GCP storage and IAM checks. Implemented, but not yet verified against live cloud accounts. Use read-only credentials.

Results appear in an interactive terminal dashboard, as JSON for SIEMs and CI, or as a PDF report.

**Limits to know about:** detection is pattern-based (regex plus entropy scoring), so it can miss secrets in unusual formats and can flag false positives. Shadow AI detection looks for hardcoded endpoint URLs, not SDK imports.

---

## Quick Install

**Linux / macOS (one command):**

```bash
curl -sSL https://raw.githubusercontent.com/Fredrickighile/aether-sniffer/main/scripts/install.sh | sh
aether-sniffer scan .
```

**Windows:**
Download the Windows `.zip` from the [releases page](https://github.com/Fredrickighile/aether-sniffer/releases)
(named `aether-sniffer_<version>_windows_amd64.zip`), extract it, and run:

```
aether-sniffer.exe scan .
```

**Build from source (requires Go 1.26.3 or newer):**

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
# Interactive terminal dashboard (default)
aether-sniffer scan /path/to/project

# JSON output for SIEMs and CI
aether-sniffer scan /path/to/project --output json

# PDF report
aether-sniffer scan /path/to/project --output pdf
```

### Exit codes (for CI/CD)

| Code | Meaning                                                                       |
| ---- | ----------------------------------------------------------------------------- |
| 0    | Scan completed, no CRITICAL findings                                          |
| 1    | At least one CRITICAL finding                                                 |
| 2    | Scan did not complete (timeout or scanner error). Results are not trustworthy |

### Sync results to the web dashboard (optional)

```bash
aether-sniffer login
aether-sniffer scan /path/to/project --sync
```

### Audit cloud infrastructure (experimental)

```bash
aether-sniffer cloud --provider aws --region ca-central-1
aether-sniffer cloud --provider azure --subscription YOUR_SUBSCRIPTION_ID
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
      - name: Install AETHER-SNIFFER
        run: curl -sSL https://raw.githubusercontent.com/Fredrickighile/aether-sniffer/main/scripts/install.sh | sh
      - name: Scan
        run: aether-sniffer scan . --output json
```

The step fails on exit code 1 (critical findings) or 2 (incomplete scan).

---

## Secret Types Detected

| Category        | Types                                                                         |
| --------------- | ----------------------------------------------------------------------------- |
| AI / LLM        | OpenAI, Anthropic, Cohere, HuggingFace                                        |
| Cloud           | AWS Access Key ID and Secret, Google API Key, Azure Storage connection string |
| Version Control | GitHub personal, OAuth and Actions tokens                                     |
| Payments        | Stripe live secret and publishable keys                                       |
| Communication   | Slack bot tokens and webhooks, Twilio auth tokens                             |
| Database        | PostgreSQL, MySQL, MongoDB, Redis connection strings                          |
| Auth            | JWT secrets, Bearer tokens, private key headers (RSA/EC/SSH/DSA)              |

## Shadow AI Providers Detected

`OpenAI` `Anthropic` `Google Vertex AI / Gemini` `Cohere` `HuggingFace` `Mistral` `Together AI` `Replicate` `LiteLLM Proxy` `Ollama`

---

## Security Design

- **Scanning runs locally.** Your source code is never uploaded.
- **Sync is opt-in.** Only if you use `--sync`, finding metadata is sent to the dashboard: file paths, titles, descriptions, severity, and redacted match previews.
- **Redacted matches.** Secrets are never stored in full. Matches show only the first and last four characters, for example `AKIA...MPLE`.
- **Report files are written with mode 0600** (owner-only on Linux and macOS).
- **Entropy scoring.** Shannon entropy filtering removes low-randomness matches to reduce false positives.
- **Skips noise.** Lockfiles (go.sum, package-lock.json, yarn.lock), `.git`, `node_modules`, binaries and files over 5 MB are skipped.
- **Fails safe.** A scan that times out or loses a scanner exits with code 2 and never reports "clean".
- **Cloud checks are read-only.** They only list and read resource settings.

---

## Roadmap

- [x] Secrets scanner (20 credential patterns)
- [x] Shadow AI scanner (10 AI providers)
- [x] Interactive terminal dashboard
- [x] JSON output for SIEMs
- [x] PDF report
- [x] Web dashboard with API-key sync
- [x] GoReleaser binaries for Windows, Linux and macOS
- [ ] Verify cloud auditors against live AWS, Azure and GCP accounts
- [ ] Detect AI SDK imports (not just endpoint URLs)
- [ ] Checksum verification in the installer
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

Apache 2.0. See [LICENSE](LICENSE).

---

_Built with Go, Bubble Tea and Lip Gloss._

_2026 Fred Ighile, github.com/Fredrickighile/aether-sniffer_
