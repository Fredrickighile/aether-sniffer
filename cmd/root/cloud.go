// Package root - cloud subcommand
// Registers `aether-sniffer cloud` which audits AWS, Azure, and GCP.
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
	Short: "Audit AWS, Azure, or GCP cloud infrastructure for misconfigurations",
	Long: `Scan your cloud account for security misconfigurations.

Supports AWS, Azure, and GCP.

AWS checks:
  - S3 buckets with public access enabled
  - IAM access keys older than 90 days
  - Inactive IAM keys that should be deleted

Azure checks:
  - Storage accounts with public blob access
  - Storage accounts allowing unencrypted HTTP
  - Weak TLS versions (below 1.2)
  - Shared key access that should use Azure AD

GCP checks:
  - GCS buckets accessible by allUsers or allAuthenticatedUsers
  - Buckets without uniform access control
  - Service account keys older than 90 days

Examples:
  # Scan AWS (uses ~/.aws/credentials automatically)
  aether-sniffer cloud --provider aws --region ca-central-1

  # Scan Azure (uses 'az login' automatically)
  aether-sniffer cloud --provider azure --subscription YOUR_SUBSCRIPTION_ID

  # Scan GCP (uses 'gcloud auth application-default login' automatically)
  aether-sniffer cloud --provider gcp --project YOUR_PROJECT_ID

  # Output JSON for SIEM ingestion
  aether-sniffer cloud --provider aws --output json
`,
	RunE: runCloudScan,
}

func init() {
	cloudCmd.Flags().StringP("provider", "p", "aws", "cloud provider: aws | azure | gcp")
	cloudCmd.Flags().StringP("region", "r", "us-east-1", "AWS region to scan")
	cloudCmd.Flags().String("profile", "", "AWS CLI profile to use")
	cloudCmd.Flags().StringP("subscription", "s", "", "Azure subscription ID")
	cloudCmd.Flags().StringP("project", "j", "", "GCP project ID")
	rootCmd.AddCommand(cloudCmd)
}

func runCloudScan(cmd *cobra.Command, args []string) error {
	provider, _ := cmd.Flags().GetString("provider")
	region, _ := cmd.Flags().GetString("region")
	profile, _ := cmd.Flags().GetString("profile")
	subscription, _ := cmd.Flags().GetString("subscription")
	project, _ := cmd.Flags().GetString("project")

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("configuration error: %w", err)
	}

	fmt.Fprintf(os.Stderr, "\n[AETHER-SNIFFER] Starting cloud audit\n")
	fmt.Fprintf(os.Stderr, "Provider: %s\n\n", provider)

	orch := engine.New(cfg)
	startedAt := time.Now()
	target := provider

	switch provider {
	case "aws":
		s := cloudscanner.New(region, profile)
		orch.Submit(engine.Job{ID: "cloud-aws", Execute: s.Scan})
		target = fmt.Sprintf("AWS / %s", region)

	case "azure":
		if subscription == "" {
			subscription = os.Getenv("AZURE_SUBSCRIPTION_ID")
		}
		if subscription == "" {
			return fmt.Errorf("Azure subscription ID required — use --subscription flag or set AZURE_SUBSCRIPTION_ID")
		}
		s := cloudscanner.NewAzure(subscription)
		orch.Submit(engine.Job{ID: "cloud-azure", Execute: s.Scan})
		target = fmt.Sprintf("Azure / %s", subscription)

	case "gcp":
		if project == "" {
			project = os.Getenv("GOOGLE_CLOUD_PROJECT")
		}
		if project == "" {
			return fmt.Errorf("GCP project ID required — use --project flag or set GOOGLE_CLOUD_PROJECT")
		}
		s := cloudscanner.NewGCP(project)
		orch.Submit(engine.Job{ID: "cloud-gcp", Execute: s.Scan})
		target = fmt.Sprintf("GCP / %s", project)

	default:
		return fmt.Errorf("unknown provider %q — must be aws, azure, or gcp", provider)
	}

	ctx := context.Background()
	results, err := orch.Run(ctx)
	if err != nil && err != context.DeadlineExceeded {
		return fmt.Errorf("cloud scan failed: %w", err)
	}

	totalFindings := 0
	for _, r := range results {
		totalFindings += len(r.Findings)
		if r.Err != nil {
			fmt.Fprintf(os.Stderr, "warning: %s\n", r.Err)
		}
	}

	fmt.Fprintf(os.Stderr, "Cloud audit complete in %s — %d finding(s)\n\n",
		time.Since(startedAt).Round(time.Millisecond), totalFindings)

	switch cfg.Output {
	case config.OutputJSON:
		w := output.NewJSONWriter(cfg.ReportDir, cfg.Version)
		return w.Write(results, target, startedAt)
	case config.OutputTUI:
		return tui.Run(target, func() ([]engine.Result, time.Duration) {
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