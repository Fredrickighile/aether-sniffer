// Package config — credential loading from ~/.aether-sniffer/config.yaml
// This file handles reading saved login credentials for the --sync flag.
// Security: config file must have permissions 0600 or credentials are rejected.
package config

import (
	"fmt"
	"os"
	"path/filepath"

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
// Returns an error if the file does not exist, has wrong permissions,
// or does not contain a valid API key.
func LoadCredentials() (*Credentials, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("could not find home directory: %w", err)
	}

	configPath := filepath.Join(home, ".aether-sniffer", "config.yaml")

	// Check file permissions — reject if readable by others.
	// This prevents other users on the system from stealing the API key.
	info, err := os.Stat(configPath)
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("not logged in — run: aether-sniffer login")
	}
	if err != nil {
		return nil, fmt.Errorf("could not read config: %w", err)
	}

	// On Unix systems, enforce 0600 permissions.
	mode := info.Mode()
	if mode.Perm()&0077 != 0 {
		return nil, fmt.Errorf(
			"config file %s has insecure permissions %v — run: chmod 600 %s",
			configPath, mode.Perm(), configPath,
		)
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
