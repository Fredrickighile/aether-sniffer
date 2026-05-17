// Package root registers all CLI sub-commands.
// This file defines the `aether-sniffer scan` command — the main entry point
// for users running a scan. It wires together: config → engine → scanners → output.
package root

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/fredthebuilder/aether-sniffer/internal/config"
	"github.com/fredthebuilder/aether-sniffer/internal/engine"
	"github.com/fredthebuilder/aether-sniffer/internal/output"
	"github.com/fredthebuilder/aether-sniffer/internal/scanners/secrets"
	"github.com/fredthebuilder/aether-sniffer/internal/scanners/shadowai"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// scanCmd defines the `scan` sub-command.
var scanCmd = &cobra.Command{
	Use:   "scan [path]",
	Short: "Scan a local path, repo, or cloud environment for secrets and Shadow AI",
	Long: `Scan a target for exposed secrets, misconfigurations, and unauthorized AI usage.

Examples:
  # Scan the current directory for secrets and Shadow AI endpoints
  aether-sniffer scan .

  # Scan a specific project folder and output JSON
  aether-sniffer scan /path/to/project --output json

  # Scan with verbose logging
  aether-sniffer scan . --verbose

  # Scan and save report to a custom directory
  aether-sniffer scan . --report-dir ./reports
`,
	Args: cobra.ExactArgs(1), // Exactly one positional argument: the target path.
	RunE: runScan,            // RunE returns an error — cobra handles printing it cleanly.
}

func init() {
	// Register scan-specific flags.
	scanCmd.Flags().StringP("report-dir", "r", "", "directory to save reports (default: ~/.aether-sniffer/reports)")
	scanCmd.Flags().BoolP("secrets", "s", true, "enable secrets scanner")
	scanCmd.Flags().BoolP("shadowai", "a", true, "enable Shadow AI scanner")

	// Bind to viper so config file can also set these.
	_ = viper.BindPFlag("report_dir", scanCmd.Flags().Lookup("report-dir"))

	// Register this command as a child of root.
	rootCmd.AddCommand(scanCmd)
}

// runScan is the main execution function for `aether-sniffer scan`.
// It follows a strict pipeline: validate → configure → scan → output.
func runScan(cmd *cobra.Command, args []string) error {
	targetPath := args[0]

	// --- 1. Validate target path ---
	if _, err := os.Stat(targetPath); os.IsNotExist(err) {
		return fmt.Errorf("target path %q does not exist", targetPath)
	}

	// --- 2. Load and validate config ---
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("configuration error: %w", err)
	}

	// Override report dir from flag if set.
	if rd, _ := cmd.Flags().GetString("report-dir"); rd != "" {
		cfg.ReportDir = rd
	}

	fmt.Fprintf(os.Stderr, "\n[AETHER-SNIFFER v%s] Starting scan of: %s\n\n", cfg.Version, targetPath)

	// --- 3. Build the engine ---
	orch := engine.New(cfg)
	startedAt := time.Now()

	// --- 4. Register scanner jobs ---
	enableSecrets, _ := cmd.Flags().GetBool("secrets")
	enableShadowAI, _ := cmd.Flags().GetBool("shadowai")

	if enableSecrets {
		s := secrets.New(targetPath)
		orch.Submit(engine.Job{
			ID:      "secrets-scanner",
			Execute: s.Scan,
		})
	}

	if enableShadowAI {
		s := shadowai.New(targetPath)
		orch.Submit(engine.Job{
			ID:      "shadowai-scanner",
			Execute: s.Scan,
		})
	}

	// --- 5. Run all scanners concurrently ---
	ctx := context.Background()
	results, err := orch.Run(ctx)
	if err != nil && err != context.DeadlineExceeded {
		return fmt.Errorf("scan failed: %w", err)
	}
	if err == context.DeadlineExceeded {
		fmt.Fprintln(os.Stderr, "warning: scan timed out — partial results follow")
	}

	// --- 6. Count total findings for summary ---
	totalFindings := 0
	for _, r := range results {
		totalFindings += len(r.Findings)
		if r.Err != nil {
			fmt.Fprintf(os.Stderr, "warning: scanner %q encountered an error: %v\n", r.JobID, r.Err)
		}
	}

	fmt.Fprintf(os.Stderr, "Scan complete in %s — %d finding(s) found.\n\n",
		time.Since(startedAt).Round(time.Millisecond), totalFindings)

	// --- 7. Write output ---
	switch cfg.Output {
	case config.OutputJSON:
		w := output.NewJSONWriter(cfg.ReportDir, cfg.Version)
		if err := w.Write(results, targetPath, startedAt); err != nil {
			return fmt.Errorf("failed to write JSON report: %w", err)
		}

	case config.OutputTUI:
		// TUI output is handled by the Bubble Tea dashboard.
		// Phase 2 will implement this. For now, fall back to a clean summary.
		printTerminalSummary(results, startedAt)

	case config.OutputPDF:
		fmt.Fprintln(os.Stderr, "PDF output coming in Phase 3. Using JSON for now.")
		w := output.NewJSONWriter(cfg.ReportDir, cfg.Version)
		if err := w.Write(results, targetPath, startedAt); err != nil {
			return fmt.Errorf("failed to write report: %w", err)
		}
	}

	// Exit with code 1 if critical findings exist — enables CI/CD pipeline blocking.
	for _, r := range results {
		for _, f := range r.Findings {
			if f.Severity == engine.SeverityCritical {
				os.Exit(1)
			}
		}
	}

	return nil
}

// printTerminalSummary renders a clean text summary when TUI is not yet available.
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