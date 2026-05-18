// Package secrets scans files, environment variables, and git history
// for exposed API keys, tokens, and credentials.
//
// Security design decisions:
//   - Findings NEVER contain the full secret. Match is always redacted.
//   - Entropy scoring reduces false positives from generic patterns.
//   - All regex patterns are compiled once at init() for performance.
//   - File size is capped at MaxFileSizeBytes to prevent memory exhaustion.
//   - Lockfiles, checksum files, and .git folders are always skipped.
package secrets

import (
	"context"
	"crypto/sha256"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Fredrickighile/aether-sniffer/internal/engine"
)

const (
	MaxFileSizeBytes = 5 * 1024 * 1024
	MinEntropy       = 3.5
	RedactKeepChars  = 4
)

type pattern struct {
	name        string
	regex       *regexp.Regexp
	severity    engine.Severity
	remediation string
}

var patterns []pattern

func init() {
	raw := []struct {
		name        string
		expr        string
		severity    engine.Severity
		remediation string
	}{
		{"OpenAI API Key", `sk-[a-zA-Z0-9]{20,}`, engine.SeverityCritical, "Revoke this key immediately at platform.openai.com/api-keys. Rotate all systems using it. Store new keys in a secrets manager (AWS Secrets Manager, HashiCorp Vault)."},
		{"Anthropic API Key", `sk-ant-[a-zA-Z0-9\-]{20,}`, engine.SeverityCritical, "Revoke at console.anthropic.com. Audit usage logs for unauthorized calls. Never commit API keys to version control."},
		{"AWS Access Key ID", `AKIA[0-9A-Z]{16}`, engine.SeverityCritical, "Immediately deactivate in AWS IAM console. Check CloudTrail for unauthorized activity in the last 90 days. Enable AWS GuardDuty."},
		{"AWS Secret Access Key", `[a-zA-Z0-9/+]{40}`, engine.SeverityHigh, "Rotate AWS credentials immediately. Review IAM policies — apply least-privilege. Use IAM roles instead of long-lived keys."},
		{"GitHub Personal Access Token", `ghp_[a-zA-Z0-9]{36}`, engine.SeverityCritical, "Revoke at github.com/settings/tokens. Audit recent API activity. Enable GitHub secret scanning on all repos."},
		{"GitHub OAuth Token", `gho_[a-zA-Z0-9]{36}`, engine.SeverityHigh, "Revoke the OAuth token and re-authorize the application with minimal scopes."},
		{"GitHub Actions Token", `ghs_[a-zA-Z0-9]{36}`, engine.SeverityHigh, "Tokens are short-lived but rotate any associated secrets. Review workflow permissions."},
		{"Stripe Secret Key", `sk_live_[a-zA-Z0-9]{24,}`, engine.SeverityCritical, "Roll the key immediately at dashboard.stripe.com/apikeys. Review recent charges for fraud. Never use live keys in development."},
		{"Stripe Publishable Key", `pk_live_[a-zA-Z0-9]{24,}`, engine.SeverityMedium, "Publishable keys are less sensitive but should still be rotated. Ensure test keys are used in non-production environments."},
		{"Google API Key", `AIza[0-9A-Za-z\-_]{35}`, engine.SeverityHigh, "Restrict the key in Google Cloud Console to specific APIs and IP addresses. Rotate immediately."},
		{"Azure Storage Account Key", `DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[a-zA-Z0-9+/=]{88}`, engine.SeverityCritical, "Regenerate the storage account key in Azure Portal. Use Azure Managed Identities instead of connection strings."},
		{"Slack Bot Token", `xoxb-[0-9]{11}-[0-9]{11}-[a-zA-Z0-9]{24}`, engine.SeverityHigh, "Revoke at api.slack.com/apps. Audit bot activity logs. Use Slack's app-level tokens with minimal scopes."},
		{"Slack Webhook URL", `hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+`, engine.SeverityMedium, "Rotate the webhook in your Slack app settings. Webhooks allow anyone to post to your channel."},
		{"HuggingFace API Token", `hf_[a-zA-Z0-9]{34,}`, engine.SeverityHigh, "Revoke at huggingface.co/settings/tokens. HuggingFace tokens can access private models and datasets."},
		{"Cohere API Key", `[a-zA-Z0-9]{40}`, engine.SeverityHigh, "Revoke at dashboard.cohere.com. AI API keys can incur significant costs if abused."},
		{"Generic Private Key Header", `-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----`, engine.SeverityCritical, "Private keys must NEVER be committed. Revoke and regenerate the key pair. Use SSH agent or a hardware security module (HSM)."},
		{"Bearer Token in Code", `[Aa]uthorization:\s*[Bb]earer\s+[a-zA-Z0-9\-_.~+/]+=*`, engine.SeverityHigh, "Remove hardcoded authorization headers. Tokens must be loaded from environment variables or a secrets manager at runtime."},
		{"Database Connection String", `(postgres|mysql|mongodb|redis)://[a-zA-Z0-9]+:[^@\s]+@[^\s]+`, engine.SeverityCritical, "Rotate the database password immediately. Use a secrets manager. Restrict database network access to specific IP ranges."},
		{"JWT Secret", `jwt[_\-\s]?secret[\s]*[=:]\s*["']?[a-zA-Z0-9+/]{16,}`, engine.SeverityHigh, "Rotate the JWT signing secret. All existing tokens are now compromised. Implement token rotation and short expiry."},
		{"Twilio Auth Token", `[0-9a-f]{32}`, engine.SeverityMedium, "Rotate at console.twilio.com. Review message logs for unauthorized SMS/calls."},
	}

	for _, r := range raw {
		compiled, err := regexp.Compile(r.expr)
		if err != nil {
			panic(fmt.Sprintf("aether-sniffer: failed to compile pattern %q: %v", r.name, err))
		}
		patterns = append(patterns, pattern{
			name:        r.name,
			regex:       compiled,
			severity:    r.severity,
			remediation: r.remediation,
		})
	}
}

type Scanner struct {
	targetPath string
}

func New(targetPath string) *Scanner {
	return &Scanner{targetPath: targetPath}
}

func (s *Scanner) Scan(ctx context.Context) ([]engine.Finding, error) {
	var findings []engine.Finding

	err := filepath.WalkDir(s.targetPath, func(path string, d os.DirEntry, err error) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if err != nil {
			return nil
		}

		// Skip the entire .git directory tree — never scan it.
		if d.IsDir() && isGitDir(path) {
			return filepath.SkipDir
		}

		if d.IsDir() || ShouldSkipPath(path) {
			return nil
		}

		fileFindings, err := s.scanFile(path)
		if err != nil {
			return nil
		}

		findings = append(findings, fileFindings...)
		return nil
	})

	return findings, err
}

func (s *Scanner) scanFile(path string) ([]engine.Finding, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	if info.Size() > MaxFileSizeBytes {
		return []engine.Finding{{
			ID:           generateID("secrets", path, "oversized"),
			Scanner:      "secrets",
			Severity:     engine.SeverityInfo,
			Title:        "File too large to scan",
			Description:  fmt.Sprintf("File %s (%d MB) exceeds the 5 MB scan limit and was skipped.", path, info.Size()/1024/1024),
			Location:     path,
			DiscoveredAt: time.Now(),
		}}, nil
	}

	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var findings []engine.Finding

	for _, p := range patterns {
		matches := p.regex.FindAllString(string(content), -1)
		for _, match := range matches {
			if shannonEntropy(match) < MinEntropy {
				continue
			}

			findings = append(findings, engine.Finding{
				ID:           generateID("secrets", path, match),
				Scanner:      "secrets",
				Severity:     p.severity,
				Title:        fmt.Sprintf("Exposed %s", p.name),
				Description:  fmt.Sprintf("A %s was found in %s. This credential is potentially valid and exposed.", p.name, path),
				Location:     path,
				Match:        redact(match),
				Confidence:   confidenceFromEntropy(shannonEntropy(match)),
				Remediation:  p.remediation,
				DiscoveredAt: time.Now(),
			})
		}
	}

	return findings, nil
}

// isGitDir returns true if the path is a .git directory.
// Uses filepath.SkipDir to skip the entire .git tree — fastest approach.
func isGitDir(path string) bool {
	base := filepath.Base(path)
	return base == ".git"
}

// ShouldSkipPath returns true for paths that never contain real secrets.
// Exported so the shadowai scanner can reuse the same logic.
func ShouldSkipPath(path string) bool {
	// Normalize to forward slashes for cross-platform safety (Windows uses \).
	normalized := strings.ReplaceAll(strings.ToLower(path), "\\", "/")
	base := filepath.Base(normalized)

	// Specific filenames that cause false positives.
	// These files contain hashes/checksums that look like secrets but never are.
	skipFiles := []string{
		"go.sum", "go.mod",
		"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "shrinkwrap.json",
		"composer.lock", "gemfile.lock", "cargo.lock", "poetry.lock",
	}
	for _, f := range skipFiles {
		if base == f {
			return true
		}
	}

	// Directories that never contain secrets.
	// .git is handled separately via filepath.SkipDir for performance.
	skipDirs := []string{
		".git", "node_modules", "vendor", ".venv", "__pycache__",
		".idea", ".vscode", "dist", "build", "target", ".terraform",
	}
	for _, dir := range skipDirs {
		if strings.Contains(normalized, "/"+dir+"/") ||
			strings.HasSuffix(normalized, "/"+dir) ||
			strings.HasPrefix(normalized, dir+"/") ||
			normalized == dir {
			return true
		}
	}

	// File extensions that are binary or non-secret files.
	skipExts := []string{
		".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
		".mp4", ".mp3", ".zip", ".tar", ".gz", ".exe", ".dll",
		".pdf", ".woff", ".woff2", ".ttf", ".eot",
	}
	for _, ext := range skipExts {
		if strings.HasSuffix(normalized, ext) {
			return true
		}
	}

	return false
}

func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]float64)
	for _, c := range s {
		freq[c]++
	}
	var entropy float64
	length := float64(len(s))
	for _, count := range freq {
		p := count / length
		entropy -= p * math.Log2(p)
	}
	return entropy
}

func confidenceFromEntropy(entropy float64) int {
	switch {
	case entropy >= 5.0:
		return 95
	case entropy >= 4.5:
		return 85
	case entropy >= 4.0:
		return 75
	case entropy >= 3.5:
		return 60
	default:
		return 40
	}
}

func redact(secret string) string {
	if len(secret) <= RedactKeepChars*2 {
		return strings.Repeat("*", len(secret))
	}
	return secret[:RedactKeepChars] + "..." + secret[len(secret)-RedactKeepChars:]
}

func generateID(scanner, location, match string) string {
	h := sha256.Sum256([]byte(scanner + location + match))
	return fmt.Sprintf("%s-%x", scanner, h[:4])
}