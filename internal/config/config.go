// Package config defines the single source of truth for all AETHER-SNIFFER
// runtime settings. Every scanner, engine, and output module reads from here.
// No magic strings. No scattered constants. One place, always.
package config

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/viper"
)

// OutputFormat is a typed enum for --output flag values.
// Using a type prevents raw string comparisons scattered across the codebase.
type OutputFormat string

const (
	OutputTUI  OutputFormat = "tui"
	OutputJSON OutputFormat = "json"
	OutputPDF  OutputFormat = "pdf"
)

// ScanTarget defines what AETHER-SNIFFER will scan in a given run.
type ScanTarget struct {
	// Cloud provider targets (at least one required for cloud scan).
	AWS   bool
	Azure bool
	GCP   bool

	// Path to a local directory, container manifest, or repo to scan.
	LocalPath string

	// GitHub repository URL (optional, for remote repo scanning).
	RepoURL string
}

// Config is the global runtime configuration object.
// It is populated once at startup and treated as read-only afterward.
// All fields have safe defaults via Load().
type Config struct {
	// Output controls how results are presented to the user.
	Output OutputFormat

	// Verbose enables debug-level logging across all modules.
	Verbose bool

	// Concurrency is the max number of goroutines the engine will run.
	// Default: 50. Higher values use more memory but scan faster.
	Concurrency int

	// Timeout is the maximum time any single scan operation may take.
	// Operations exceeding this are cancelled gracefully, not killed.
	Timeout time.Duration

	// RateLimit is the max number of API calls per second to external
	// cloud providers. Prevents accidental DoS of your own AWS account.
	RateLimit int

	// Target defines what will be scanned in this run.
	Target ScanTarget

	// PluginDir is the path to the plugins/ directory.
	PluginDir string

	// ReportDir is where JSON and PDF reports are written.
	ReportDir string

	// Version is injected at build time via ldflags.
	// Build command: go build -ldflags "-X .../config.Version=0.1.0"
	Version string
}

// Version is set at build time. Default is "dev" for local builds.
var Version = "dev"

// Load reads all configuration from viper (which merges CLI flags,
// config file, and environment variables) and returns a validated Config.
// Returns an error if any required value is invalid or missing.
func Load() (*Config, error) {
	cfg := &Config{
		Output:      OutputFormat(viper.GetString("output")),
		Verbose:     viper.GetBool("verbose"),
		Concurrency: viper.GetInt("concurrency"),
		Timeout:     viper.GetDuration("timeout"),
		RateLimit:   viper.GetInt("rate_limit"),
		PluginDir:   viper.GetString("plugin_dir"),
		ReportDir:   viper.GetString("report_dir"),
		Version:     Version,
	}

	// Apply safe defaults for any unset values.
	cfg.applyDefaults()

	// Validate before returning. Fail fast, fail clearly.
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return cfg, nil
}

// applyDefaults fills in safe production defaults for any zero-value fields.
func (c *Config) applyDefaults() {
	if c.Output == "" {
		c.Output = OutputTUI
	}
	if c.Concurrency <= 0 {
		c.Concurrency = 50
	}
	if c.Timeout <= 0 {
		c.Timeout = 30 * time.Second
	}
	if c.RateLimit <= 0 {
		c.RateLimit = 10
	}
	if c.PluginDir == "" {
		c.PluginDir = "plugins"
	}
	if c.ReportDir == "" {
		home, _ := os.UserHomeDir()
		c.ReportDir = home + "/.aether-sniffer/reports"
	}
}

// validate checks that all config values are within safe, sensible bounds.
func (c *Config) validate() error {
	switch c.Output {
	case OutputTUI, OutputJSON, OutputPDF:
		// valid
	default:
		return fmt.Errorf("invalid output format %q: must be tui, json, or pdf", c.Output)
	}

	if c.Concurrency > 500 {
		return fmt.Errorf("concurrency %d exceeds maximum of 500", c.Concurrency)
	}
	if c.Timeout > 5*time.Minute {
		return fmt.Errorf("timeout %s exceeds maximum of 5 minutes", c.Timeout)
	}
	if c.RateLimit > 100 {
		return fmt.Errorf("rate_limit %d exceeds maximum of 100 req/s", c.RateLimit)
	}

	return nil
}