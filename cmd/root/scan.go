// Package root registers all CLI sub-commands.
// This file defines the `aether-sniffer scan` command.
package root

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/Fredrickighile/aether-sniffer/internal/config"
	"github.com/Fredrickighile/aether-sniffer/internal/engine"
	"github.com/Fredrickighile/aether-sniffer/internal/output"
	"github.com/Fredrickighile/aether-sniffer/internal/report"
	"github.com/Fredrickighile/aether-sniffer/internal/scanners/secrets"
	"github.com/Fredrickighile/aether-sniffer/internal/scanners/shadowai"
	"github.com/Fredrickighile/aether-sniffer/internal/tui"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// scanCmd defines the `scan` sub-command.
var scanCmd = &cobra.Command{
	Use:   "scan [path]",
	Short: "Scan a local path for secrets and Shadow AI",
	Long: `Scan a target for exposed secrets and unauthorized AI usage.

Examples:
  # Scan the current directory
  aether-sniffer scan .

  # Scan and sync results to your dashboard
  aether-sniffer scan . --sync --api-key as_live_your_key_here

  # Scan with JSON output
  aether-sniffer scan /path/to/project --output json

  # Scan and generate PDF compliance report
  aether-sniffer scan . --output pdf
`,
	Args: cobra.ExactArgs(1),
	RunE: runScan,
}

func init() {
	scanCmd.Flags().StringP("report-dir", "r", "", "directory to save reports (default: ~/.aether-sniffer/reports)")
	scanCmd.Flags().BoolP("secrets", "s", true, "enable secrets scanner")
	scanCmd.Flags().BoolP("shadowai", "a", true, "enable Shadow AI scanner")

	// Dashboard sync flags.
	scanCmd.Flags().Bool("sync", false, "sync scan results to your Aether Sniffer dashboard")
	scanCmd.Flags().String("api-key", "", "your dashboard API key (get it from aethersniffer.vercel.app/settings)")
	scanCmd.Flags().String("dashboard-url", "https://aether-sniffer-api.onrender.com", "dashboard API URL (advanced)")

	_ = viper.BindPFlag("report_dir", scanCmd.Flags().Lookup("report-dir"))
	_ = viper.BindPFlag("api_key", scanCmd.Flags().Lookup("api-key"))

	rootCmd.AddCommand(scanCmd)
}

// runScan is the main execution function for `aether-sniffer scan`.
func runScan(cmd *cobra.Command, args []string) error {
	targetPath := args[0]

	if _, err := os.Stat(targetPath); os.IsNotExist(err) {
		return fmt.Errorf("target path %q does not exist", targetPath)
	}

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("configuration error: %w", err)
	}

	if rd, _ := cmd.Flags().GetString("report-dir"); rd != "" {
		cfg.ReportDir = rd
	}

	fmt.Fprintf(os.Stderr, "\n[AETHER-SNIFFER v%s] Starting scan of: %s\n\n", cfg.Version, targetPath)

	orch := engine.New(cfg)
	startedAt := time.Now()

	enableSecrets, _ := cmd.Flags().GetBool("secrets")
	enableShadowAI, _ := cmd.Flags().GetBool("shadowai")

	if enableSecrets {
		s := secrets.New(targetPath)
		orch.Submit(engine.Job{ID: "secrets-scanner", Execute: s.Scan})
	}

	if enableShadowAI {
		s := shadowai.New(targetPath)
		orch.Submit(engine.Job{ID: "shadowai-scanner", Execute: s.Scan})
	}

	ctx := context.Background()
	results, err := orch.Run(ctx)
	if err != nil && err != context.DeadlineExceeded {
		return fmt.Errorf("scan failed: %w", err)
	}
	if err == context.DeadlineExceeded {
		fmt.Fprintln(os.Stderr, "warning: scan timed out — partial results follow")
	}

	totalFindings := 0
	for _, r := range results {
		totalFindings += len(r.Findings)
		if r.Err != nil {
			fmt.Fprintf(os.Stderr, "warning: scanner %q encountered an error: %v\n", r.JobID, r.Err)
		}
	}

	fmt.Fprintf(os.Stderr, "Scan complete in %s — %d finding(s) found.\n\n",
		time.Since(startedAt).Round(time.Millisecond), totalFindings)

	// Write output.
	switch cfg.Output {
	case config.OutputJSON:
		w := output.NewJSONWriter(cfg.ReportDir, cfg.Version)
		if err := w.Write(results, targetPath, startedAt); err != nil {
			return fmt.Errorf("failed to write JSON report: %w", err)
		}

	case config.OutputTUI:
		tuiResults := results
		tuiStart := startedAt
		err := tui.Run(targetPath, func() ([]engine.Result, time.Duration) {
			return tuiResults, time.Since(tuiStart)
		})
		if err != nil {
			return fmt.Errorf("TUI error: %w", err)
		}

	case config.OutputPDF:
		w := report.NewPDFReport(cfg.ReportDir, cfg.Version)
		path, err := w.Generate(results, targetPath, startedAt)
		if err != nil {
			return fmt.Errorf("failed to generate PDF report: %w", err)
		}
		fmt.Fprintf(os.Stderr, "PDF report saved to: %s\n", path)
	}

	// Sync to dashboard if --sync flag is set.
	syncEnabled, _ := cmd.Flags().GetBool("sync")
	apiKey, _ := cmd.Flags().GetString("api-key")

	// Also check environment variable for API key.
	if apiKey == "" {
		apiKey = os.Getenv("AETHER_API_KEY")
	}

	if syncEnabled {
		if apiKey == "" {
			fmt.Fprintln(os.Stderr, "warning: --sync requires --api-key or AETHER_API_KEY env var. Skipping sync.")
		} else {
			dashURL, _ := cmd.Flags().GetString("dashboard-url")
			if err := syncToDashboard(results, targetPath, startedAt, apiKey, dashURL); err != nil {
				fmt.Fprintf(os.Stderr, "warning: dashboard sync failed: %v\n", err)
			} else {
				fmt.Fprintln(os.Stderr, "✔ Results synced to dashboard successfully")
			}
		}
	}

	// Exit with code 1 if critical findings — enables CI/CD pipeline blocking.
	for _, r := range results {
		for _, f := range r.Findings {
			if f.Severity == engine.SeverityCritical {
				os.Exit(1)
			}
		}
	}

	return nil
}

// syncToDashboard posts scan results to the Aether Sniffer dashboard API.
// Uses the ingest endpoint which is API-key authenticated.
func syncToDashboard(results []engine.Result, target string, startedAt time.Time, apiKey, dashURL string) error {
	// Build severity counts.
	bySeverity := map[string]int{}
	total := 0
	type ingestFinding struct {
		Scanner     string `json:"scanner"`
		Severity    string `json:"severity"`
		Title       string `json:"title"`
		Description string `json:"description"`
		Location    string `json:"location"`
		Match       string `json:"match"`
		Confidence  int    `json:"confidence"`
		Remediation string `json:"remediation"`
	}
	var findings []ingestFinding

	for _, r := range results {
		for _, f := range r.Findings {
			total++
			bySeverity[string(f.Severity)]++
			findings = append(findings, ingestFinding{
				Scanner:     r.JobID,
				Severity:    string(f.Severity),
				Title:       f.Title,
				Description: f.Description,
				Location:    f.Location,
				Match:       f.Match,
				Confidence:  f.Confidence,
				Remediation: f.Remediation,
			})
		}
	}

	payload := map[string]interface{}{
		"target":   target,
		"duration": time.Since(startedAt).Round(time.Millisecond).String(),
		"summary": map[string]interface{}{
			"total":       total,
			"by_severity": bySeverity,
		},
		"findings": findings,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal results: %w", err)
	}

	req, err := http.NewRequest("POST", dashURL+"/ingest", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", apiKey)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to reach dashboard: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("dashboard returned status %d", resp.StatusCode)
	}

	return nil
}

// printTerminalSummary renders a clean text summary.
func printTerminalSummary(results []engine.Result, startedAt time.Time) {
	severityOrder := []engine.Severity{
		engine.SeverityCritical,
		engine.SeverityHigh,
		engine.SeverityMedium,
		engine.SeverityLow,
		engine.SeverityInfo,
	}

	counts := make(map[engine.Severity]int)
	var allFindings []engine.Finding

	for _, r := range results {
		for _, f := range r.Findings {
			counts[f.Severity]++
			allFindings = append(allFindings, f)
		}
	}

	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println("  AETHER-SNIFFER — Scan Results")
	fmt.Printf("  Duration: %s\n", time.Since(startedAt).Round(time.Millisecond))
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println()

	for _, sev := range severityOrder {
		if counts[sev] > 0 {
			fmt.Printf("  [%s] %d finding(s)\n", sev, counts[sev])
		}
	}

	fmt.Println()

	for _, f := range allFindings {
		fmt.Printf("  ── %s ──\n", f.Severity)
		fmt.Printf("     Title:    %s\n", f.Title)
		fmt.Printf("     Location: %s\n", f.Location)
		fmt.Printf("     Match:    %s\n", f.Match)
		fmt.Printf("     Confidence: %d%%\n", f.Confidence)
		fmt.Printf("     Fix: %s\n", f.Remediation)
		fmt.Println()
	}

	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
}
