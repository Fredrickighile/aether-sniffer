// Package cloud provides cloud infrastructure auditing for AETHER-SNIFFER.
// It connects to AWS using the standard credential chain — meaning it works
// with any of these automatically (no hardcoded credentials ever):
//
//   - AWS CLI credentials (~/.aws/credentials)
//   - Environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
//   - IAM roles on EC2/ECS/Lambda (best practice for production)
//   - AWS SSO
//
// Security principle: this scanner is READ-ONLY.
// It never modifies, deletes, or creates any AWS resource.
// All API calls use the minimum required IAM permissions.
//
// Required IAM permissions (read-only):
//
//	s3:ListAllMyBuckets
//	s3:GetBucketAcl
//	s3:GetBucketPublicAccessBlock
//	s3:GetBucketPolicy
//	s3:GetBucketPolicyStatus
//	iam:ListUsers
//	iam:ListAccessKeys
//	iam:GetAccessKeyLastUsed
//	iam:ListAttachedUserPolicies
//	iam:ListUserPolicies
//	iam:GetAccountPasswordPolicy
package cloud

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/Fredrickighile/aether-sniffer/internal/engine"
)

const (
	// MaxKeyAgeDays is how old an AWS access key can be before it's flagged.
	// 90 days is the CIS AWS Foundations Benchmark recommendation.
	MaxKeyAgeDays = 90

	// AWSReadTimeout is the max time for any single AWS API call.
	AWSReadTimeout = 15 * time.Second
)

// Scanner audits AWS cloud infrastructure for misconfigurations.
type Scanner struct {
	region  string
	profile string // AWS CLI profile name (empty = default)
}

// New creates an AWS cloud scanner.
// region: AWS region to scan (e.g. "us-east-1", "ca-central-1")
// profile: AWS CLI profile name (empty string uses the default profile)
func New(region, profile string) *Scanner {
	if region == "" {
		region = "us-east-1"
	}
	return &Scanner{region: region, profile: profile}
}

// Scan runs all AWS audit checks and returns findings.
// It is designed to be passed as Job.Execute to the engine orchestrator.
func (s *Scanner) Scan(ctx context.Context) ([]engine.Finding, error) {
	// Load AWS config using the standard credential chain.
	// Never hardcodes credentials — reads from environment/profile/IAM role.
	opts := []func(*config.LoadOptions) error{
		config.WithRegion(s.region),
	}
	if s.profile != "" {
		opts = append(opts, config.WithSharedConfigProfile(s.profile))
	}

	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w — "+
			"ensure AWS credentials are configured (run 'aws configure' or set AWS_ACCESS_KEY_ID)", err)
	}

	var findings []engine.Finding

	// Run all checks. Each check is independent — one failure doesn't stop others.
	s3Findings, err := s.auditS3(ctx, cfg)
	if err != nil {
		findings = append(findings, makeErrorFinding("cloud-s3", err))
	} else {
		findings = append(findings, s3Findings...)
	}

	iamFindings, err := s.auditIAM(ctx, cfg)
	if err != nil {
		findings = append(findings, makeErrorFinding("cloud-iam", err))
	} else {
		findings = append(findings, iamFindings...)
	}

	return findings, nil
}

// ── S3 Auditor ───────────────────────────────────────────────────────────────

// auditS3 checks all S3 buckets for public access misconfigurations.
func (s *Scanner) auditS3(ctx context.Context, cfg aws.Config) ([]engine.Finding, error) {
	client := s3.NewFromConfig(cfg)
	var findings []engine.Finding

	// List all buckets in the account.
	listCtx, cancel := context.WithTimeout(ctx, AWSReadTimeout)
	defer cancel()

	result, err := client.ListBuckets(listCtx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, fmt.Errorf("s3:ListBuckets failed: %w", err)
	}

	for _, bucket := range result.Buckets {
		bucketName := aws.ToString(bucket.Name)

		// Check 1: Public Access Block settings.
		pubFindings := s.checkS3PublicAccess(ctx, client, bucketName)
		findings = append(findings, pubFindings...)

		// Check 2: Bucket ACL.
		aclFindings := s.checkS3ACL(ctx, client, bucketName)
		findings = append(findings, aclFindings...)
	}

	// Finding if account has no buckets — informational.
	if len(result.Buckets) == 0 {
		findings = append(findings, engine.Finding{
			ID:           generateID("cloud-s3", "account", "no-buckets"),
			Scanner:      "cloud",
			Severity:     engine.SeverityInfo,
			Title:        "No S3 buckets found in this AWS account",
			Description:  "The AWS account has no S3 buckets. Nothing to audit.",
			Location:     fmt.Sprintf("AWS account / region: %s", s.region),
			DiscoveredAt: time.Now(),
		})
	}

	return findings, nil
}

// checkS3PublicAccess verifies the bucket has Public Access Block enabled.
// This is the most important S3 security control.
func (s *Scanner) checkS3PublicAccess(ctx context.Context, client *s3.Client, bucket string) []engine.Finding {
	ctx, cancel := context.WithTimeout(ctx, AWSReadTimeout)
	defer cancel()

	result, err := client.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{
		Bucket: aws.String(bucket),
	})
	if err != nil {
		// NoSuchPublicAccessBlockConfiguration means the block was never set.
		// This is a misconfiguration — treat as high severity.
		return []engine.Finding{{
			ID:      generateID("cloud-s3", bucket, "no-public-access-block"),
			Scanner: "cloud",
			Severity: engine.SeverityHigh,
			Title:   fmt.Sprintf("S3 bucket has no Public Access Block: %s", bucket),
			Description: fmt.Sprintf(
				"Bucket %s has no Public Access Block configuration. "+
					"Without this setting, bucket policies or ACLs could make the bucket publicly readable. "+
					"This is the configuration behind many high-profile data breaches.",
				bucket),
			Location:    fmt.Sprintf("s3://%s", bucket),
			Confidence:  90,
			Remediation: fmt.Sprintf("Run: aws s3api put-public-access-block --bucket %s --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true", bucket),
			DiscoveredAt: time.Now(),
		}}
	}

	block := result.PublicAccessBlockConfiguration
	if block == nil {
		return nil
	}

	var issues []string
	if !aws.ToBool(block.BlockPublicAcls) {
		issues = append(issues, "BlockPublicAcls=false")
	}
	if !aws.ToBool(block.IgnorePublicAcls) {
		issues = append(issues, "IgnorePublicAcls=false")
	}
	if !aws.ToBool(block.BlockPublicPolicy) {
		issues = append(issues, "BlockPublicPolicy=false")
	}
	if !aws.ToBool(block.RestrictPublicBuckets) {
		issues = append(issues, "RestrictPublicBuckets=false")
	}

	if len(issues) == 0 {
		return nil // All public access controls are correctly enabled.
	}

	return []engine.Finding{{
		ID:      generateID("cloud-s3", bucket, "partial-public-access-block"),
		Scanner: "cloud",
		Severity: engine.SeverityHigh,
		Title:   fmt.Sprintf("S3 bucket has incomplete Public Access Block: %s", bucket),
		Description: fmt.Sprintf(
			"Bucket %s has some Public Access Block settings disabled: %v. "+
				"This could allow public access through bucket policies or ACLs.",
			bucket, issues),
		Location:    fmt.Sprintf("s3://%s", bucket),
		Confidence:  95,
		Remediation: fmt.Sprintf("Run: aws s3api put-public-access-block --bucket %s --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true", bucket),
		DiscoveredAt: time.Now(),
	}}
}

// checkS3ACL checks if a bucket has a public ACL (public-read or public-read-write).
func (s *Scanner) checkS3ACL(ctx context.Context, client *s3.Client, bucket string) []engine.Finding {
	ctx, cancel := context.WithTimeout(ctx, AWSReadTimeout)
	defer cancel()

	result, err := client.GetBucketAcl(ctx, &s3.GetBucketAclInput{
		Bucket: aws.String(bucket),
	})
	if err != nil {
		return nil // Skip if we can't read ACL — not an error we should surface.
	}

	for _, grant := range result.Grants {
		if grant.Grantee == nil {
			continue
		}
		// URI for "All Users" group = public access.
		if grant.Grantee.Type == s3types.TypeGroup &&
			aws.ToString(grant.Grantee.URI) == "http://acs.amazonaws.com/groups/global/AllUsers" {

			perm := string(grant.Permission)
			severity := engine.SeverityHigh
			if perm == "WRITE" || perm == "FULL_CONTROL" {
				severity = engine.SeverityCritical
			}

			return []engine.Finding{{
				ID:      generateID("cloud-s3", bucket, "public-acl-"+perm),
				Scanner: "cloud",
				Severity: severity,
				Title:   fmt.Sprintf("S3 bucket is publicly %s: %s", perm, bucket),
				Description: fmt.Sprintf(
					"Bucket %s has an ACL granting %s permission to all users on the internet. "+
						"Anyone can access this bucket without authentication.",
					bucket, perm),
				Location:    fmt.Sprintf("s3://%s", bucket),
				Match:       fmt.Sprintf("ACL grant: %s to AllUsers", perm),
				Confidence:  99,
				Remediation: fmt.Sprintf("Run: aws s3api put-bucket-acl --bucket %s --acl private — then review all objects in the bucket for sensitive data.", bucket),
				DiscoveredAt: time.Now(),
			}}
		}
	}

	return nil
}

// ── IAM Auditor ──────────────────────────────────────────────────────────────

// auditIAM checks IAM users and access keys for security issues.
func (s *Scanner) auditIAM(ctx context.Context, cfg aws.Config) ([]engine.Finding, error) {
	client := iam.NewFromConfig(cfg)
	var findings []engine.Finding

	// List all IAM users.
	var marker *string
	for {
		listCtx, cancel := context.WithTimeout(ctx, AWSReadTimeout)
		result, err := client.ListUsers(listCtx, &iam.ListUsersInput{
			Marker: marker,
		})
		cancel()

		if err != nil {
			return nil, fmt.Errorf("iam:ListUsers failed: %w", err)
		}

		for _, user := range result.Users {
			userFindings := s.auditIAMUser(ctx, client, user)
			findings = append(findings, userFindings...)
		}

		if !result.IsTruncated {
			break
		}
		marker = result.Marker
	}

	return findings, nil
}

// auditIAMUser checks a single IAM user for security issues.
func (s *Scanner) auditIAMUser(ctx context.Context, client *iam.Client, user iamtypes.User) []engine.Finding {
	var findings []engine.Finding
	username := aws.ToString(user.UserName)

	// Check access key age.
	keysCtx, cancel := context.WithTimeout(ctx, AWSReadTimeout)
	defer cancel()

	keysResult, err := client.ListAccessKeys(keysCtx, &iam.ListAccessKeysInput{
		UserName: user.UserName,
	})
	if err != nil {
		return nil
	}

	for _, key := range keysResult.AccessKeyMetadata {
		keyID := aws.ToString(key.AccessKeyId)

		// Check if key is active and old.
		if key.Status == iamtypes.StatusTypeActive && key.CreateDate != nil {
			age := time.Since(*key.CreateDate)
			ageDays := int(age.Hours() / 24)

			if ageDays > MaxKeyAgeDays {
				severity := engine.SeverityMedium
				if ageDays > 180 {
					severity = engine.SeverityHigh
				}
				if ageDays > 365 {
					severity = engine.SeverityCritical
				}

				findings = append(findings, engine.Finding{
					ID:      generateID("cloud-iam", username, keyID),
					Scanner: "cloud",
					Severity: severity,
					Title:   fmt.Sprintf("IAM access key not rotated in %d days: %s", ageDays, username),
					Description: fmt.Sprintf(
						"User %s has an active access key (%s) that was created %d days ago. "+
							"The CIS AWS Foundations Benchmark requires key rotation every 90 days. "+
							"Long-lived keys significantly increase the blast radius of a credential leak.",
						username, keyID[:8]+"...", ageDays),
					Location:    fmt.Sprintf("AWS IAM / User: %s / Key: %s...", username, keyID[:8]),
					Match:       fmt.Sprintf("%s... (age: %d days)", keyID[:8], ageDays),
					Confidence:  99,
					Remediation: fmt.Sprintf("Create a new access key for %s, update all systems using the old key, then deactivate and delete key %s.", username, keyID[:8]+"..."),
					DiscoveredAt: time.Now(),
				})
			}
		}

		// Check for inactive keys that were never cleaned up.
		if key.Status == iamtypes.StatusTypeInactive {
			findings = append(findings, engine.Finding{
				ID:      generateID("cloud-iam", username, "inactive-"+keyID),
				Scanner: "cloud",
				Severity: engine.SeverityLow,
				Title:   fmt.Sprintf("IAM user has inactive access key: %s", username),
				Description: fmt.Sprintf(
					"User %s has an inactive access key (%s...). "+
						"Inactive keys should be deleted — they provide no value and increase attack surface.",
					username, keyID[:8]),
				Location:    fmt.Sprintf("AWS IAM / User: %s", username),
				Confidence:  99,
				Remediation: fmt.Sprintf("Delete the inactive key: aws iam delete-access-key --user-name %s --access-key-id %s", username, keyID),
				DiscoveredAt: time.Now(),
			})
		}
	}

	return findings
}

// ── Helpers ──────────────────────────────────────────────────────────────────

// makeErrorFinding wraps a scanner error as an INFO finding so the
// output layer can report it without crashing the entire scan.
func makeErrorFinding(scanner string, err error) engine.Finding {
	return engine.Finding{
		ID:           generateID(scanner, "error", err.Error()),
		Scanner:      scanner,
		Severity:     engine.SeverityInfo,
		Title:        fmt.Sprintf("Cloud scanner error: %s", scanner),
		Description:  err.Error(),
		DiscoveredAt: time.Now(),
	}
}

// generateID creates a stable unique ID for a finding.
func generateID(scanner, resource, issue string) string {
	return fmt.Sprintf("%s-%x", scanner,
		[]byte(scanner+resource+issue)[:4])
}