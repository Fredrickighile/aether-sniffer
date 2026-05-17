// Package shadowai is AETHER-SNIFFER's unique competitive moat.
// It detects "Shadow AI" — unauthorized use of LLM APIs inside
// enterprise environments — by scanning for:
//
//  1. AI provider API keys (OpenAI, Anthropic, Cohere, HuggingFace, etc.)
//  2. Hardcoded LLM endpoint URLs in source code and config files
//  3. Unusual AI model names that indicate unauthorized model usage
//  4. LLM proxy configurations that bypass corporate security controls
//
// No existing open-source tool covers this attack surface as of 2026.
// This module is what makes AETHER-SNIFFER fundable.
package shadowai

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/fredthebuilder/aether-sniffer/internal/engine"
	"github.com/fredthebuilder/aether-sniffer/internal/scanners/secrets"
)

// aiEndpoint defines a known AI provider's API endpoint pattern.
type aiEndpoint struct {
	provider    string
	urlPattern  *regexp.Regexp
	keyPattern  *regexp.Regexp
	severity    engine.Severity
	description string
	remediation string
}

// endpoints is the master list of all AI providers AETHER-SNIFFER tracks.
var endpoints []aiEndpoint

func init() {
	raw := []struct {
		provider    string
		urlExpr     string
		keyExpr     string
		severity    engine.Severity
		description string
		remediation string
	}{
		{
			"OpenAI",
			`https?://api\.openai\.com/v\d+`,
			`sk-[a-zA-Z0-9\-]{20,}`,
			engine.SeverityCritical,
			"Unauthorized OpenAI API usage detected. This can result in massive unexpected billing and exposure of proprietary data to a third-party LLM.",
			"Implement an approved AI gateway (e.g. Azure OpenAI with private endpoints). Revoke the exposed key. Add OpenAI endpoint to network egress blocklist until approved.",
		},
		{
			"Anthropic Claude",
			`https?://api\.anthropic\.com`,
			`sk-ant-[a-zA-Z0-9\-]{20,}`,
			engine.SeverityCritical,
			"Unauthorized Anthropic Claude API usage detected. Enterprise data may be sent to Anthropic's servers without a DPA in place.",
			"Revoke the API key at console.anthropic.com. Review what data was sent via the API. Establish a formal AI usage policy before re-enabling.",
		},
		{
			"Cohere",
			`https?://api\.cohere\.ai`,
			`[a-zA-Z0-9]{40}`,
			engine.SeverityHigh,
			"Cohere AI API endpoint detected in codebase. Unauthorized LLM usage may violate data residency requirements.",
			"Revoke the Cohere API key. Review all prompts sent — they may contain PII or proprietary business logic.",
		},
		{
			"HuggingFace Inference",
			`https?://api-inference\.huggingface\.co`,
			`hf_[a-zA-Z0-9]{34,}`,
			engine.SeverityHigh,
			"HuggingFace Inference API usage detected. Unauthorized model inference may expose internal data.",
			"Rotate the HuggingFace token. Consider running approved models locally using Ollama or a private HuggingFace endpoint.",
		},
		{
			"Google Vertex AI / Gemini",
			`https?://(generativelanguage|us-central1-aiplatform)\.googleapis\.com`,
			`AIza[0-9A-Za-z\-_]{35}`,
			engine.SeverityHigh,
			"Google Vertex AI or Gemini API usage detected. Verify this model usage is approved and covered by your Google Cloud DPA.",
			"Restrict the Google API key to specific services. Ensure Vertex AI usage is covered by your enterprise agreement.",
		},
		{
			"Mistral AI",
			`https?://api\.mistral\.ai`,
			`[a-zA-Z0-9]{32,}`,
			engine.SeverityHigh,
			"Mistral AI API endpoint detected. This is a relatively new provider — verify it is covered by your vendor risk assessment.",
			"Revoke the Mistral API key. Add to approved AI tools list only after vendor risk assessment is complete.",
		},
		{
			"Together AI",
			`https?://api\.together\.xyz`,
			`[a-zA-Z0-9\-]{40,}`,
			engine.SeverityMedium,
			"Together AI API usage detected. This provider hosts many open-source models — verify data handling compliance.",
			"Review Together AI's data retention policy. Ensure no PII is included in prompts before approving this vendor.",
		},
		{
			"Replicate",
			`https?://api\.replicate\.com`,
			`r8_[a-zA-Z0-9]{36,}`,
			engine.SeverityMedium,
			"Replicate API usage detected. Replicate runs user-submitted models — verify which model is being called.",
			"Rotate the Replicate API token. Review which models are being called and audit their data handling practices.",
		},
		{
			"Ollama Local Proxy",
			`https?://localhost:11434`,
			``,
			engine.SeverityInfo,
			"Ollama local AI proxy detected. This is privacy-safe (runs locally) but verify the model is approved for enterprise use.",
			"Local AI models are generally lower risk. Ensure the model was downloaded from an approved source and has not been fine-tuned on proprietary data.",
		},
		{
			"LiteLLM Proxy",
			`https?://[a-zA-Z0-9.\-]+:\d+/v1`,
			``,
			engine.SeverityMedium,
			"LiteLLM proxy configuration detected. This may route requests to multiple AI providers, some of which may not be approved.",
			"Audit the LiteLLM configuration to identify all backend AI providers. Ensure each is approved and covered by a DPA.",
		},
	}

	for _, r := range raw {
		ep := aiEndpoint{
			provider:    r.provider,
			severity:    r.severity,
			description: r.description,
			remediation: r.remediation,
		}

		var err error
		ep.urlPattern, err = regexp.Compile(r.urlExpr)
		if err != nil {
			panic(fmt.Sprintf("shadowai: invalid URL pattern for %s: %v", r.provider, err))
		}

		if r.keyExpr != "" {
			ep.keyPattern, err = regexp.Compile(r.keyExpr)
			if err != nil {
				panic(fmt.Sprintf("shadowai: invalid key pattern for %s: %v", r.provider, err))
			}
		}

		endpoints = append(endpoints, ep)
	}
}

// Scanner is the Shadow AI detection module.
type Scanner struct {
	targetPath string
}

// New creates a Shadow AI scanner for the given local path.
func New(targetPath string) *Scanner {
	return &Scanner{targetPath: targetPath}
}

// Scan walks the target path and detects Shadow AI usage.
// It is designed to be passed as Job.Execute to the engine orchestrator.
func (s *Scanner) Scan(ctx context.Context) ([]engine.Finding, error) {
	var findings []engine.Finding

	err := filepath.WalkDir(s.targetPath, func(path string, d os.DirEntry, entry error) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if entry != nil || d.IsDir() || secrets.ShouldSkipPath(path) {
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

// scanFile checks a single file for Shadow AI indicators.
func (s *Scanner) scanFile(path string) ([]engine.Finding, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	text := string(content)
	var findings []engine.Finding
	seen := make(map[string]bool) // Deduplication within a file.

	for _, ep := range endpoints {
		// Check for URL pattern match.
		if ep.urlPattern.MatchString(text) {
			dedupeKey := ep.provider + path
			if !seen[dedupeKey] {
				seen[dedupeKey] = true

				finding := engine.Finding{
					ID:           generateID("shadowai", path, ep.provider),
					Scanner:      "shadowai",
					Severity:     ep.severity,
					Title:        fmt.Sprintf("Shadow AI: %s endpoint detected", ep.provider),
					Description:  ep.description,
					Location:     path,
					Match:        ep.provider + " API endpoint",
					Confidence:   90,
					Remediation:  ep.remediation,
					DiscoveredAt: time.Now(),
				}

				// Upgrade severity if we also find a key in the same file.
				if ep.keyPattern != nil && ep.keyPattern.MatchString(text) {
					if ep.severity != engine.SeverityCritical {
						finding.Severity = engine.SeverityCritical
					}
					finding.Title = fmt.Sprintf("Shadow AI: %s endpoint + exposed key detected", ep.provider)
					finding.Confidence = 98
					finding.Description += " An API key was also found in the same file, confirming active unauthorized usage."
				}

				findings = append(findings, finding)
			}
		}
	}

	return findings, nil
}

// generateID creates a stable unique ID for a finding.
func generateID(scanner, location, identifier string) string {
	// Re-use the same ID generation logic from secrets package for consistency.
	return fmt.Sprintf("%s-%x", scanner,
		[]byte(strings.ToLower(scanner+location+identifier))[:4])
}