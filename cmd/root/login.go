// Package root — login command.
//
// Security design:
//   - Password read with echo disabled — never visible on screen
//   - JWT token used once to generate API key, never stored on disk
//   - API key stored in ~/.aether-sniffer/config.yaml with mode 0600
//   - All communication over HTTPS only
package root

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"
	"gopkg.in/yaml.v3"
)

// ANSI colour codes — make the CLI look professional.
const (
	clrReset  = "\033[0m"
	clrBold   = "\033[1m"
	clrDim    = "\033[2m"
	clrPurple = "\033[38;5;99m"
	clrGreen  = "\033[38;5;84m"
	clrRed    = "\033[38;5;203m"
	clrYellow = "\033[38;5;220m"
	clrGray   = "\033[38;5;245m"
	clrWhite  = "\033[38;5;255m"
	clrCyan   = "\033[38;5;117m"
)

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Log in to your Aether Sniffer dashboard",
	Long: `Authenticate with your Aether Sniffer dashboard.

Your credentials are used once to generate an API key.
The key is saved to ~/.aether-sniffer/config.yaml (permissions 0600).
Your password is NEVER stored on disk.

Examples:
  aether-sniffer login
  aether-sniffer login --dashboard https://aether-sniffer-api.onrender.com
`,
	RunE: runLogin,
}

func init() {
	loginCmd.Flags().String("dashboard", "https://aether-sniffer-api.onrender.com", "dashboard API URL")
	rootCmd.AddCommand(loginCmd)
}

type savedConfig struct {
	DashboardURL string `yaml:"dashboard_url"`
	APIKey       string `yaml:"api_key"`
	Email        string `yaml:"email"`
	SavedAt      string `yaml:"saved_at"`
}

func runLogin(cmd *cobra.Command, _ []string) error {
	dashURL, _ := cmd.Flags().GetString("dashboard")

	// Header
	fmt.Println()
	fmt.Printf("  %s%sAETHER-SNIFFER%s %s— Dashboard Login%s\n",
		clrPurple, clrBold, clrReset, clrGray, clrReset)
	fmt.Printf("  %s%s%s\n", clrGray, strings.Repeat("─", 40), clrReset)
	fmt.Println()

	// Email prompt
	fmt.Printf("  %sEmail%s    : ", clrGray, clrReset)
	var email string
	fmt.Scanln(&email)
	email = strings.TrimSpace(email)
	if email == "" {
		return fmt.Errorf("%serror:%s email cannot be empty", clrRed, clrReset)
	}

	// Password prompt — hidden input
	fmt.Printf("  %sPassword%s : ", clrGray, clrReset)
	passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}
	password := strings.TrimSpace(string(passwordBytes))
	if len(password) < 8 {
		return fmt.Errorf("%serror:%s password must be at least 8 characters", clrRed, clrReset)
	}

	fmt.Println()

	// Step 1 — Authenticate
	fmt.Printf("  %s[1/3]%s Authenticating ...  ", clrPurple, clrReset)
	token, err := loginToAPI(dashURL, email, password)
	if err != nil {
		fmt.Printf("%s✗%s\n", clrRed, clrReset)
		return fmt.Errorf("%serror:%s %v", clrRed, clrReset, err)
	}
	fmt.Printf("%s✔%s\n", clrGreen, clrReset)

	// Step 2 — Generate API key
	fmt.Printf("  %s[2/3]%s Generating API key ... ", clrPurple, clrReset)
	apiKey, err := generateAPIKey(dashURL, token)
	if err != nil {
		if strings.Contains(err.Error(), "already have") {
			fmt.Printf("%s↻%s (loading existing key)\n", clrYellow, clrReset)

			// Load existing key from config if available
			existing, loadErr := loadExistingKey()
			if loadErr == nil && existing != "" {
				apiKey = existing
				fmt.Printf("  %s[2/3]%s Loaded from config  %s✔%s\n", clrPurple, clrReset, clrGreen, clrReset)
			} else {
				fmt.Println()
				fmt.Printf("  %s!%s You already have an active API key.\n", clrYellow, clrReset)
				fmt.Printf("  %sTo generate a new one:%s\n", clrGray, clrReset)
				fmt.Printf("    1. Visit %saethersniffer.vercel.app/settings%s\n", clrCyan, clrReset)
				fmt.Printf("    2. Click %sRevoke%s → then run %saether-sniffer login%s again\n",
					clrRed, clrReset, clrPurple, clrReset)
				fmt.Println()
				return nil
			}
		} else {
			fmt.Printf("%s✗%s\n", clrRed, clrReset)
			return fmt.Errorf("%serror:%s %v", clrRed, clrReset, err)
		}
	} else {
		fmt.Printf("%s✔%s\n", clrGreen, clrReset)
	}

	// Step 3 — Save config
	fmt.Printf("  %s[3/3]%s Saving credentials  ... ", clrPurple, clrReset)
	if err := saveConfig(dashURL, email, apiKey); err != nil {
		fmt.Printf("%s✗%s\n", clrRed, clrReset)
		return fmt.Errorf("%serror:%s %v", clrRed, clrReset, err)
	}
	fmt.Printf("%s✔%s\n", clrGreen, clrReset)

	// Success
	fmt.Println()
	fmt.Printf("  %s%s%s\n", clrGray, strings.Repeat("─", 40), clrReset)
	fmt.Printf("  %s✔ Logged in as%s %s%s%s\n", clrGreen, clrReset, clrWhite, email, clrReset)
	fmt.Printf("  %s✔ Credentials saved to%s %s~/.aether-sniffer/config.yaml%s\n",
		clrGreen, clrReset, clrCyan, clrReset)
	fmt.Println()
	fmt.Printf("  %sRun your first scan:%s\n", clrGray, clrReset)
	fmt.Printf("  %s$ aether-sniffer scan /path/to/project --sync%s\n", clrPurple, clrReset)
	fmt.Println()

	return nil
}

func loginToAPI(dashURL, email, password string) (string, error) {
	payload := map[string]string{"email": email, "password": password}
	body, _ := json.Marshal(payload)

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 20 * time.Second,
		},
	}
	req, err := http.NewRequest("POST", dashURL+"/auth/login", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("could not reach dashboard — check your internet connection")
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == http.StatusUnauthorized {
		return "", fmt.Errorf("invalid email or password")
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("server returned %d", resp.StatusCode)
	}

	var result struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil || result.Token == "" {
		return "", fmt.Errorf("unexpected response from server")
	}

	return result.Token, nil
}

func generateAPIKey(dashURL, token string) (string, error) {
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 20 * time.Second,
		},
	}
	req, err := http.NewRequest("POST", dashURL+"/api/keys", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("could not reach dashboard")
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == http.StatusConflict {
		return "", fmt.Errorf("already have an active API key")
	}
	if resp.StatusCode != http.StatusCreated {
		var errResp struct {
			Error string `json:"error"`
		}
		json.Unmarshal(respBody, &errResp)
		return "", fmt.Errorf("%s", errResp.Error)
	}

	var result struct {
		Key string `json:"key"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil || result.Key == "" {
		return "", fmt.Errorf("unexpected response from server")
	}

	return result.Key, nil
}

func loadExistingKey() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	configPath := filepath.Join(home, ".aether-sniffer", "config.yaml")
	data, err := os.ReadFile(configPath)
	if err != nil {
		return "", err
	}
	var cfg savedConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return "", err
	}
	return cfg.APIKey, nil
}

func saveConfig(dashURL, email, apiKey string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("could not find home directory: %w", err)
	}

	configDir := filepath.Join(home, ".aether-sniffer")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return fmt.Errorf("could not create config directory: %w", err)
	}

	cfg := savedConfig{
		DashboardURL: dashURL,
		APIKey:       apiKey,
		Email:        email,
		SavedAt:      time.Now().UTC().Format(time.RFC3339),
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("could not marshal config: %w", err)
	}

	configPath := filepath.Join(configDir, "config.yaml")
	// 0600 — only owner can read/write. Your password is NEVER in this file.
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		return fmt.Errorf("could not write config file: %w", err)
	}

	return nil
}
