// Package cloud - Azure scanner
// Audits Azure subscriptions for storage account misconfigurations.
//
// Authentication uses the Azure Default Credential chain — works with:
//   - Azure CLI (az login)
//   - Environment variables (AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID)
//   - Managed Identity (when running on Azure VMs/containers)
//
// Required Azure RBAC roles (read-only):
//   - Reader on the subscription
//   - Storage Blob Data Reader
//
// This scanner is READ-ONLY. It never modifies any Azure resource.
package cloud

import (
	"context"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	"github.com/Fredrickighile/aether-sniffer/internal/engine"
)

// AzureScanner audits Azure infrastructure for misconfigurations.
type AzureScanner struct {
	subscriptionID string
}

// NewAzure creates an Azure scanner for the given subscription ID.
// subscriptionID: Azure subscription ID (find it in Azure Portal → Subscriptions)
func NewAzure(subscriptionID string) *AzureScanner {
	return &AzureScanner{subscriptionID: subscriptionID}
}

// Scan runs all Azure audit checks and returns findings.
func (s *AzureScanner) Scan(ctx context.Context) ([]engine.Finding, error) {
	if s.subscriptionID == "" {
		return nil, fmt.Errorf("Azure subscription ID is required — " +
			"use --subscription flag or set AZURE_SUBSCRIPTION_ID environment variable")
	}

	// Use DefaultAzureCredential — tries CLI, env vars, managed identity automatically.
	// Never hardcodes credentials.
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get Azure credentials: %w — " +
			"run 'az login' or set AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID", err)
	}

	var findings []engine.Finding

	// Audit storage accounts.
	storageFindings, err := s.auditStorageAccounts(ctx, cred)
	if err != nil {
		findings = append(findings, makeErrorFinding("cloud-azure", err))
	} else {
		findings = append(findings, storageFindings...)
	}

	return findings, nil
}

// auditStorageAccounts checks all storage accounts for security misconfigurations.
func (s *AzureScanner) auditStorageAccounts(ctx context.Context, cred *azidentity.DefaultAzureCredential) ([]engine.Finding, error) {
	client, err := armstorage.NewAccountsClient(s.subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Azure storage client: %w", err)
	}

	var findings []engine.Finding

	// List all storage accounts in the subscription.
	pager := client.NewListPager(nil)
	for pager.More() {
		listCtx, cancel := context.WithTimeout(ctx, AWSReadTimeout)
		page, err := pager.NextPage(listCtx)
		cancel()

		if err != nil {
			return nil, fmt.Errorf("failed to list Azure storage accounts: %w", err)
		}

		for _, account := range page.Value {
			if account.Name == nil {
				continue
			}
			name := *account.Name

			// Check 1: Public blob access enabled.
			if account.Properties != nil &&
				account.Properties.AllowBlobPublicAccess != nil &&
				*account.Properties.AllowBlobPublicAccess {
				findings = append(findings, engine.Finding{
					ID:      generateID("cloud-azure", name, "public-blob-access"),
					Scanner: "cloud",
					Severity: engine.SeverityHigh,
					Title:   fmt.Sprintf("Azure storage account allows public blob access: %s", name),
					Description: fmt.Sprintf(
						"Storage account %s has AllowBlobPublicAccess=true. "+
							"This allows any container in this account to be made publicly "+
							"accessible, potentially exposing sensitive data.",
						name),
					Location:    fmt.Sprintf("azure://storageaccounts/%s", name),
					Confidence:  95,
					Remediation: fmt.Sprintf("In Azure Portal: Storage account %s → Configuration → Blob public access → Disabled. Or run: az storage account update --name %s --allow-blob-public-access false", name, name),
					DiscoveredAt: time.Now(),
				})
			}

			// Check 2: HTTPS-only traffic not enforced.
			if account.Properties != nil &&
				account.Properties.EnableHTTPSTrafficOnly != nil &&
				!*account.Properties.EnableHTTPSTrafficOnly {
				findings = append(findings, engine.Finding{
					ID:      generateID("cloud-azure", name, "http-allowed"),
					Scanner: "cloud",
					Severity: engine.SeverityCritical,
					Title:   fmt.Sprintf("Azure storage account allows unencrypted HTTP: %s", name),
					Description: fmt.Sprintf(
						"Storage account %s allows HTTP traffic (not HTTPS only). "+
							"Data transmitted over HTTP is unencrypted and can be intercepted. "+
							"This violates most enterprise security policies and compliance frameworks.",
						name),
					Location:    fmt.Sprintf("azure://storageaccounts/%s", name),
					Confidence:  99,
					Remediation: fmt.Sprintf("Run: az storage account update --name %s --https-only true", name),
					DiscoveredAt: time.Now(),
				})
			}

			// Check 3: Minimum TLS version below 1.2.
			if account.Properties != nil &&
				account.Properties.MinimumTLSVersion != nil {
				tlsVersion := string(*account.Properties.MinimumTLSVersion)
				if tlsVersion == "TLS1_0" || tlsVersion == "TLS1_1" {
					findings = append(findings, engine.Finding{
						ID:      generateID("cloud-azure", name, "weak-tls-"+tlsVersion),
						Scanner: "cloud",
						Severity: engine.SeverityHigh,
						Title:   fmt.Sprintf("Azure storage account uses weak TLS (%s): %s", tlsVersion, name),
						Description: fmt.Sprintf(
							"Storage account %s allows %s which is deprecated and insecure. "+
								"TLS 1.0 and 1.1 have known vulnerabilities (POODLE, BEAST). "+
								"PCI DSS and most enterprise security policies require TLS 1.2 minimum.",
							name, tlsVersion),
						Location:    fmt.Sprintf("azure://storageaccounts/%s", name),
						Confidence:  99,
						Remediation: fmt.Sprintf("Run: az storage account update --name %s --min-tls-version TLS1_2", name),
						DiscoveredAt: time.Now(),
					})
				}
			}

			// Check 4: Storage account key access enabled (should use Azure AD instead).
			if account.Properties != nil &&
				account.Properties.AllowSharedKeyAccess != nil &&
				*account.Properties.AllowSharedKeyAccess {
				findings = append(findings, engine.Finding{
					ID:      generateID("cloud-azure", name, "shared-key-access"),
					Scanner: "cloud",
					Severity: engine.SeverityMedium,
					Title:   fmt.Sprintf("Azure storage account uses shared key access: %s", name),
					Description: fmt.Sprintf(
						"Storage account %s allows shared key authorization. "+
							"Storage account keys provide full access to the account and never expire. "+
							"Microsoft recommends using Azure AD authentication instead.",
						name),
					Location:    fmt.Sprintf("azure://storageaccounts/%s", name),
					Confidence:  85,
					Remediation: fmt.Sprintf("Migrate to Azure AD authentication, then run: az storage account update --name %s --allow-shared-key-access false", name),
					DiscoveredAt: time.Now(),
				})
			}
		}
	}

	if len(findings) == 0 {
		findings = append(findings, engine.Finding{
			ID:           generateID("cloud-azure", s.subscriptionID, "clean"),
			Scanner:      "cloud",
			Severity:     engine.SeverityInfo,
			Title:        "Azure storage accounts are correctly configured",
			Description:  "All storage accounts in this subscription passed security checks.",
			Location:     fmt.Sprintf("Azure subscription: %s", s.subscriptionID),
			DiscoveredAt: time.Now(),
		})
	}

	return findings, nil
}