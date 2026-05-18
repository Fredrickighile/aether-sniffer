// Package output handles all result presentation for AETHER-SNIFFER.
// JSON output is SIEM-compatible (Splunk, Elastic, Datadog ready).
// Every field is documented so security teams know exactly what they're reading.
package output

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Fredrickighile/aether-sniffer/internal/engine"
)

// ScanReport is the top-level JSON structure written to disk and stdout.
// It is designed to be ingested directly by SIEMs and CI/CD pipelines.
type ScanReport struct {
	// Meta contains information about the scan run itself.
	Meta ScanMeta `json:"meta"`

	// Summary contains aggregated counts for quick triage.
	Summary ScanSummary `json:"summary"`

	// Findings is the full list of all issues discovered.
	Findings []ReportFinding `json:"findings"`
}

// ScanMeta describes the scan run context.
type ScanMeta struct {
	Tool      string    `json:"tool"`       // Always "AETHER-SNIFFER"
	Version   string    `json:"version"`    // Injected at build time
	StartedAt time.Time `json:"started_at"` // ISO 8601
	EndedAt   time.Time `json:"ended_at"`
	Duration  string    `json:"duration"` // Human-readable e.g. "4.2s"
	Target    string    `json:"target"`   // Path or cloud provider scanned
	ScanID    string    `json:"scan_id"`  // Unique per run, for SIEM correlation
}

// ScanSummary gives a fast overview of the findings.
type ScanSummary struct {
	Total    int            `json:"total"`
	BySeverity map[string]int `json:"by_severity"`
	ByScanner  map[string]int `json:"by_scanner"`
}

// ReportFinding is the JSON-serialized form of engine.Finding.
// All fields use snake_case for SIEM compatibility.
type ReportFinding struct {
	ID           string `json:"id"`
	Scanner      string `json:"scanner"`
	Severity     string `json:"severity"`
	Title        string `json:"title"`
	Description  string `json:"description"`
	Location     string `json:"location"`
	Match        string `json:"match"`       // Always redacted
	Confidence   int    `json:"confidence"`  // 0–100
	Remediation  string `json:"remediation"`
	DiscoveredAt string `json:"discovered_at"` // ISO 8601
}

// JSONWriter writes scan results as structured JSON.
type JSONWriter struct {
	outputDir string
	version   string
}

// NewJSONWriter creates a JSONWriter that saves reports to outputDir.
func NewJSONWriter(outputDir, version string) *JSONWriter {
	return &JSONWriter{outputDir: outputDir, version: version}
}

// Write serializes all findings to a JSON file and also prints to stdout
// so CI/CD pipelines can pipe the output directly to jq or Splunk HEC.
func (w *JSONWriter) Write(results []engine.Result, target string, startedAt time.Time) error {
	// Flatten all results into a single findings list.
	var allFindings []engine.Finding
	for _, r := range results {
		allFindings = append(allFindings, r.Findings...)
	}

	report := ScanReport{
		Meta: ScanMeta{
			Tool:      "AETHER-SNIFFER",
			Version:   w.version,
			StartedAt: startedAt,
			EndedAt:   time.Now(),
			Duration:  time.Since(startedAt).Round(time.Millisecond).String(),
			Target:    target,
			ScanID:    generateScanID(startedAt),
		},
		Summary:  buildSummary(allFindings),
		Findings: toReportFindings(allFindings),
	}

	// Serialize with indentation for human readability.
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal report to JSON: %w", err)
	}

	// Ensure the output directory exists.
	if err := os.MkdirAll(w.outputDir, 0700); err != nil {
		return fmt.Errorf("failed to create report directory %s: %w", w.outputDir, err)
	}

	// Write to file. Mode 0600: only owner can read/write — secrets are in here.
	filename := filepath.Join(w.outputDir,
		fmt.Sprintf("aether-sniffer-%s.json", startedAt.Format("2006-01-02T15-04-05")))

	if err := os.WriteFile(filename, data, 0600); err != nil {
		return fmt.Errorf("failed to write report file: %w", err)
	}

	// Also print to stdout for CI/CD pipeline piping.
	fmt.Println(string(data))
	fmt.Fprintf(os.Stderr, "\nReport saved to: %s\n", filename)

	return nil
}

// buildSummary aggregates findings into counts by severity and scanner.
func buildSummary(findings []engine.Finding) ScanSummary {
	s := ScanSummary{
		Total:     len(findings),
		BySeverity: make(map[string]int),
		ByScanner:  make(map[string]int),
	}
	for _, f := range findings {
		s.BySeverity[string(f.Severity)]++
		s.ByScanner[f.Scanner]++
	}
	return s
}

// toReportFindings converts engine findings to the JSON report format.
func toReportFindings(findings []engine.Finding) []ReportFinding {
	out := make([]ReportFinding, len(findings))
	for i, f := range findings {
		out[i] = ReportFinding{
			ID:           f.ID,
			Scanner:      f.Scanner,
			Severity:     string(f.Severity),
			Title:        f.Title,
			Description:  f.Description,
			Location:     f.Location,
			Match:        f.Match,
			Confidence:   f.Confidence,
			Remediation:  f.Remediation,
			DiscoveredAt: f.DiscoveredAt.UTC().Format(time.RFC3339),
		}
	}
	return out
}

// generateScanID creates a unique ID for a scan run.
// Format: "as-<unix-timestamp>" — sortable and unique.
func generateScanID(t time.Time) string {
	return fmt.Sprintf("as-%d", t.UnixMilli())
}