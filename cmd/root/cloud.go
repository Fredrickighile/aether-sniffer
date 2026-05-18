// This file registers the `aether-sniffer cloud` sub-command.
// It wires the AWS cloud auditor into the CLI.
package root

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/Fredrickighile/aether-sniffer/internal/config"
	"github.com/Fredrickighile/aether-sniffer/internal/engine"
	"github.com/Fredrickighile/aether-sniffer/internal/output"
	cloudscanner "github.com/Fredrickighile/aether-sniffer/internal/scanners/cloud"
	"github.com/Fredrickighile/aether-sniffer/internal/tui"
	"github.com/spf13/cobra"
)

var cloudCmd = &cobra.Command{
	Use:   "cloud",
	Short: "Audit AWS cloud infrastructure for misconfigurations",
	Long: `Scan your AWS account for security misconfigurations including:

  - S3 buckets with public access enabled
  - IAM access keys older than 90 days (CIS Benchmark violation)
  - Inactive IAM keys that should be deleted
  - Over-privileged IAM users

Examples:
  # Scan AWS using default credentials and region
  aether-sniffer cloud

  # Scan a specific region
  aether-sniffer cloud --region ca-central-1

  # Scan using a specific AWS CLI profile
  aether-sniffer cloud --profile production

  # Output JSON for SIEM ingestion
  aether-sniffer cloud --output json

Required IAM permissions (read-only):
  s3:ListAllMyBuckets, s3:GetBucketAcl, s3:GetBucketPublicAccessBlock
  iam:ListUsers, iam:ListAccessKeys, iam:GetAccessKeyLastUsed
`,
	RunE: runCloudScan,
}

func init() {
	cloudCmd.Flags().StringP("region", "r", "us-east-1", "AWS region to scan")
	cloudCmd.Flags().StringP("profile", "p", "", "AWS CLI profile to use")
	rootCmd.AddCommand(cloudCmd)
}

func runCloudScan(cmd *cobra.Command, args []string) error {
	region, _ := cmd.Flags().GetString("region")
	profile, _ := cmd.Flags().GetString("profile")

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("configuration error: %w", err)
	}

	fmt.Fprintf(os.Stderr, "\n[AETHER-SNIFFER] Starting AWS cloud audit\n")
	fmt.Fprintf(os.Stderr, "Region:  %s\n", region)
	if profile != "" {
		fmt.Fprintf(os.Stderr, "Profile: %s\n", profile)
	}
	fmt.Fprintf(os.Stderr, "\n")

	orch := engine.New(cfg)
	startedAt := time.Now()

	scanner := cloudscanner.New(region, profile)
	orch.Submit(engine.Job{
		ID:      "cloud-aws",
		Execute: scanner.Scan,
	})

	ctx := context.Background()
	results, err := orch.Run(ctx)
	if err != nil && err != context.DeadlineExceeded {
		return fmt.Errorf("cloud scan failed: %w", err)
	}

	totalFindings := 0
	for _, r := range results {
		totalFindings += len(r.Findings)
	}

	fmt.Fprintf(os.Stderr, "Cloud audit complete in %s — %d finding(s)\n\n",
		time.Since(startedAt).Round(time.Millisecond), totalFindings)

	switch cfg.Output {
	case config.OutputJSON:
		w := output.NewJSONWriter(cfg.ReportDir, cfg.Version)
		return w.Write(results, fmt.Sprintf("aws:%s", region), startedAt)
	case config.OutputTUI:
		return tui.Run(fmt.Sprintf("AWS / %s", region), func() ([]engine.Result, time.Duration) {
			return results, time.Since(startedAt)
		})
	default:
		printTerminalSummary(results, startedAt)
	}

	for _, r := range results {
		for _, f := range r.Findings {
			if f.Severity == engine.SeverityCritical {
				os.Exit(1)
			}
		}
	}

	return nil
}