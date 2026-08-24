// Package config — credential loading from ~/.aether-sniffer/config.yaml
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"gopkg.in/yaml.v3"
)

// Credentials holds the saved dashboard credentials.
type Credentials struct {
	DashboardURL string `yaml:"dashboard_url"`
	APIKey       string `yaml:"api_key"`
	Email        string `yaml:"email"`
	SavedAt      string `yaml:"saved_at"`
}

// LoadCredentials reads saved credentials from ~/.aether-sniffer/config.yaml.
func LoadCredentials() (*Credentials, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("could not find home directory: %w", err)
	}

	configPath := filepath.Join(home, ".aether-sniffer", "config.yaml")

	info, err := os.Stat(configPath)
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("not logged in — run: aether-sniffer login")
	}
	if err != nil {
		return nil, fmt.Errorf("could not read config: %w", err)
	}

	// On Unix only — enforce 0600 permissions.
	// Windows file permissions work differently so we skip this check.
	if runtime.GOOS != "windows" {
		mode := info.Mode()
		if mode.Perm()&0077 != 0 {
			return nil, fmt.Errorf(
				"config file %s has insecure permissions — run: chmod 600 %s",
				configPath, configPath,
			)
		}
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("could not read config file: %w", err)
	}

	var creds Credentials
	if err := yaml.Unmarshal(data, &creds); err != nil {
		return nil, fmt.Errorf("config file is corrupted — run: aether-sniffer login")
	}

	if creds.APIKey == "" {
		return nil, fmt.Errorf("no API key found — run: aether-sniffer login")
	}

	if creds.DashboardURL == "" {
		creds.DashboardURL = "https://aether-sniffer-api.onrender.com"
	}

	return &creds, nil
}
