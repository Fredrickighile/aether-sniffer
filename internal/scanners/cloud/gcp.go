// Package cloud - GCP scanner
// Audits Google Cloud Platform projects for storage and IAM misconfigurations.
//
// Authentication uses Application Default Credentials (ADC) — works with:
//   - gcloud CLI (gcloud auth application-default login)
//   - Environment variable GOOGLE_APPLICATION_CREDENTIALS pointing to a service account key
//   - Workload Identity (when running on GCP VMs/GKE)
//
// Required GCP IAM roles (read-only):
//   - roles/storage.objectViewer
//   - roles/iam.securityReviewer
//
// This scanner is READ-ONLY. It never modifies any GCP resource.
package cloud

import (
	"context"
	"fmt"
	"time"

	"golang.org/x/oauth2/google"
	"google.golang.org/api/iam/v1"
	"google.golang.org/api/option"
	"google.golang.org/api/storage/v1"
	"github.com/Fredrickighile/aether-sniffer/internal/engine"
)

// GCPScanner audits GCP infrastructure for misconfigurations.
type GCPScanner struct {
	projectID string
}

// NewGCP creates a GCP scanner for the given project ID.
// projectID: GCP project ID (find it in GCP Console → Project Info)
func NewGCP(projectID string) *GCPScanner {
	return &GCPScanner{projectID: projectID}
}

// Scan runs all GCP audit checks and returns findings.
// Designed to be passed as Job.Execute to the engine orchestrator.
func (s *GCPScanner) Scan(ctx context.Context) ([]engine.Finding, error) {
	if s.projectID == "" {
		return nil, fmt.Errorf("GCP project ID is required — " +
			"use --project flag or set GOOGLE_CLOUD_PROJECT environment variable")
	}

	// Load Application Default Credentials.
	// Never hardcodes credentials — reads from gcloud CLI or service account.
	creds, err := google.FindDefaultCredentials(ctx,
		storage.DevstorageReadOnlyScope,
		iam.CloudPlatformScope,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get GCP credentials: %w — "+
			"run 'gcloud auth application-default login' or set GOOGLE_APPLICATION_CREDENTIALS", err)
	}

	var findings []engine.Finding

	// Audit GCS storage buckets.
	storageFindings, err := s.auditStorageBuckets(ctx, creds)
	if err != nil {
		findings = append(findings, makeErrorFinding("cloud-gcp-storage", err))
	} else {
		findings = append(findings, storageFindings...)
	}

	// Audit IAM service accounts.
	iamFindings, err := s.auditServiceAccounts(ctx, creds)
	if err != nil {
		findings = append(findings, makeErrorFinding("cloud-gcp-iam", err))
	} else {
		findings = append(findings, iamFindings...)
	}

	return findings, nil
}

// auditStorageBuckets checks all GCS buckets for public access misconfigurations.
func (s *GCPScanner) auditStorageBuckets(ctx context.Context, creds *google.Credentials) ([]engine.Finding, error) {
	svc, err := storage.NewService(ctx, option.WithCredentials(creds))
	if err != nil {
		return nil, fmt.Errorf("failed to create GCS client: %w", err)
	}

	var findings []engine.Finding

	// List all buckets in the project.
	listCtx, cancel := context.WithTimeout(ctx, AWSReadTimeout)
	defer cancel()

	buckets, err := svc.Buckets.List(s.projectID).Context(listCtx).Do()
	if err != nil {
		return nil, fmt.Errorf("storage.buckets.list failed: %w", err)
	}

	for _, bucket := range buckets.Items {
		// Check bucket IAM policy for public access.
		iamCtx, iamCancel := context.WithTimeout(ctx, AWSReadTimeout)
		policy, err := svc.Buckets.GetIamPolicy(bucket.Name).Context(iamCtx).Do()
		iamCancel()

		if err != nil {
			continue // Skip if we cannot read IAM policy.
		}

		for _, binding := range policy.Bindings {
			for _, member := range binding.Members {
				// allUsers = fully public, allAuthenticatedUsers = any Google account
				if member == "allUsers" || member == "allAuthenticatedUsers" {
					severity := engine.SeverityHigh
					label := "authenticated Google users"
					if member == "allUsers" {
						severity = engine.SeverityCritical
						label = "the entire internet (no authentication required)"
					}

					findings = append(findings, engine.Finding{
						ID:      generateID("cloud-gcp", bucket.Name, member+"-"+binding.Role),
						Scanner: "cloud",
						Severity: severity,
						Title:   fmt.Sprintf("GCS bucket is publicly accessible: %s", bucket.Name),
						Description: fmt.Sprintf(
							"Bucket %s grants %s role to %s. "+
								"This means the bucket contents can be accessed by %s. "+
								"Public GCS buckets are a leading cause of data breaches.",
							bucket.Name, binding.Role, member, label),
						Location:    fmt.Sprintf("gs://%s", bucket.Name),
						Match:       fmt.Sprintf("IAM binding: %s → %s", binding.Role, member),
						Confidence:  99,
						Remediation: fmt.Sprintf("Run: gsutil iam ch -d %s gs://%s — then audit all objects in the bucket for sensitive data.", member, bucket.Name),
						DiscoveredAt: time.Now(),
					})
				}
			}
		}

		// Check uniform bucket-level access is enabled.
		// Without this, object-level ACLs can override bucket policies.
		if bucket.IamConfiguration != nil &&
			bucket.IamConfiguration.UniformBucketLevelAccess != nil &&
			!bucket.IamConfiguration.UniformBucketLevelAccess.Enabled {
			findings = append(findings, engine.Finding{
				ID:      generateID("cloud-gcp", bucket.Name, "no-uniform-access"),
				Scanner: "cloud",
				Severity: engine.SeverityMedium,
				Title:   fmt.Sprintf("GCS bucket lacks uniform access control: %s", bucket.Name),
				Description: fmt.Sprintf(
					"Bucket %s does not have uniform bucket-level access enabled. "+
						"This means individual objects can have ACLs that override the bucket policy, "+
						"making it harder to audit and control access.",
					bucket.Name),
				Location:    fmt.Sprintf("gs://%s", bucket.Name),
				Confidence:  90,
				Remediation: fmt.Sprintf("Run: gsutil uniformbucketlevelaccess set on gs://%s", bucket.Name),
				DiscoveredAt: time.Now(),
			})
		}
	}

	if len(buckets.Items) == 0 {
		findings = append(findings, engine.Finding{
			ID:           generateID("cloud-gcp", s.projectID, "no-buckets"),
			Scanner:      "cloud",
			Severity:     engine.SeverityInfo,
			Title:        "No GCS buckets found in this project",
			Description:  fmt.Sprintf("Project %s has no GCS buckets to audit.", s.projectID),
			Location:     fmt.Sprintf("GCP project: %s", s.projectID),
			DiscoveredAt: time.Now(),
		})
	}

	return findings, nil
}

// auditServiceAccounts checks for overprivileged or misconfigured service accounts.
func (s *GCPScanner) auditServiceAccounts(ctx context.Context, creds *google.Credentials) ([]engine.Finding, error) {
	svc, err := iam.NewService(ctx, option.WithCredentials(creds))
	if err != nil {
		return nil, fmt.Errorf("failed to create IAM client: %w", err)
	}

	var findings []engine.Finding

	// List all service accounts in the project.
	listCtx, cancel := context.WithTimeout(ctx, AWSReadTimeout)
	defer cancel()

	resource := fmt.Sprintf("projects/%s", s.projectID)
	accounts, err := svc.Projects.ServiceAccounts.List(resource).Context(listCtx).Do()
	if err != nil {
		return nil, fmt.Errorf("iam.serviceaccounts.list failed: %w", err)
	}

	for _, sa := range accounts.Accounts {
		// Check for service account keys — external keys are a security risk.
		keysCtx, keysCancel := context.WithTimeout(ctx, AWSReadTimeout)
		keys, err := svc.Projects.ServiceAccounts.Keys.List(sa.Name).
			KeyTypes("USER_MANAGED").
			Context(keysCtx).Do()
		keysCancel()

		if err != nil {
			continue
		}

		for _, key := range keys.Keys {
			// Parse key creation time.
			created, err := time.Parse(time.RFC3339, key.ValidAfterTime)
			if err != nil {
				continue
			}

			ageDays := int(time.Since(created).Hours() / 24)

			if ageDays > MaxKeyAgeDays {
				severity := engine.SeverityMedium
				if ageDays > 180 {
					severity = engine.SeverityHigh
				}
				if ageDays > 365 {
					severity = engine.SeverityCritical
				}

				findings = append(findings, engine.Finding{
					ID:      generateID("cloud-gcp-iam", sa.Email, key.Name),
					Scanner: "cloud",
					Severity: severity,
					Title:   fmt.Sprintf("GCP service account key not rotated in %d days: %s", ageDays, sa.Email),
					Description: fmt.Sprintf(
						"Service account %s has a user-managed key that is %d days old. "+
							"Long-lived service account keys significantly increase the risk "+
							"of credential compromise. Google recommends rotating keys every 90 days.",
						sa.Email, ageDays),
					Location:    fmt.Sprintf("GCP IAM / Service Account: %s", sa.Email),
					Confidence:  99,
					Remediation: fmt.Sprintf("Create a new key, update all systems, then delete the old key: gcloud iam service-accounts keys delete KEY_ID --iam-account=%s", sa.Email),
					DiscoveredAt: time.Now(),
				})
			}
		}
	}

	return findings, nil
}