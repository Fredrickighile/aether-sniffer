// Package report generates professional PDF security reports from scan findings.
// The PDF is designed to be handed directly to a CISO, auditor, or compliance team.
//
// Report sections:
//  1. Cover page - tool name, scan target, date, severity summary
//  2. Executive summary - plain English overview for non-technical readers
//  3. Findings - full details, location, match, confidence, remediation
//  4. Appendix - scan metadata, tool version, duration
package report

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jung-kurt/gofpdf"
	"github.com/Fredrickighile/aether-sniffer/internal/engine"
)

// colours
const (
	colBgR, colBgG, colBgB         = 13, 17, 23     // #0D1117 dark background
	colAccR, colAccG, colAccB       = 29, 158, 117   // #1D9E75 green accent
	colCritR, colCritG, colCritB    = 232, 93, 74    // #E85D4A red
	colHighR, colHighG, colHighB    = 240, 165, 0    // #F0A500 amber
	colMedR, colMedG, colMedB       = 75, 156, 211   // #4B9CD3 blue
	colLowR, colLowG, colLowB       = 139, 148, 158  // #8B949E grey
	colTextR, colTextG, colTextB    = 230, 237, 243  // #E6EDF3 light text
	colDarkR, colDarkG, colDarkB    = 22, 27, 34     // #161B22 card bg
	colBorderR, colBorderG, colBorderB = 48, 54, 61  // #30363D border
)

// PDFReport generates a professional PDF security report.
type PDFReport struct {
	pdf       *gofpdf.Fpdf
	outputDir string
	version   string
}

// NewPDFReport creates a PDFReport writer.
//
// EXACT LOCATION: internal/report/pdf.go
func NewPDFReport(outputDir, version string) *PDFReport {
	return &PDFReport{
		outputDir: outputDir,
		version:   version,
	}
}

// Generate builds the PDF from scan results and saves it to outputDir.
// Returns the full path to the generated PDF file.
func (r *PDFReport) Generate(results []engine.Result, target string, startedAt time.Time) (string, error) {
	// Flatten all findings.
	var findings []engine.Finding
	for _, res := range results {
		findings = append(findings, res.Findings...)
	}

	// Count by severity.
	counts := map[engine.Severity]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}

	// Initialise PDF - A4, portrait, millimetres.
	r.pdf = gofpdf.New("P", "mm", "A4", "")
	r.pdf.SetAuthor("AETHER-SNIFFER", true)
	r.pdf.SetTitle("AETHER-SNIFFER Security Report", true)
	r.pdf.SetCreator("AETHER-SNIFFER v"+r.version, true)
	r.pdf.SetMargins(15, 15, 15)
	r.pdf.SetAutoPageBreak(true, 15)

	// ── Cover page ──────────────────────────────────────────────
	r.pdf.AddPage()
	r.renderCover(target, startedAt, counts, len(findings))

	// ── Executive summary ───────────────────────────────────────
	r.pdf.AddPage()
	r.renderExecutiveSummary(findings, counts, target, startedAt)

	// ── Findings ────────────────────────────────────────────────
	if len(findings) > 0 {
		r.pdf.AddPage()
		r.renderFindings(findings)
	}

	// ── Appendix ────────────────────────────────────────────────
	r.pdf.AddPage()
	r.renderAppendix(results, startedAt)

	// Save to disk. Mode 0600 - report contains sensitive finding data.
	if err := os.MkdirAll(r.outputDir, 0700); err != nil {
		return "", fmt.Errorf("failed to create report directory: %w", err)
	}

	filename := filepath.Join(r.outputDir,
		fmt.Sprintf("aether-sniffer-report-%s.pdf",
			startedAt.Format("2006-01-02T15-04-05")))

	if err := r.pdf.OutputFileAndClose(filename); err != nil {
		return "", fmt.Errorf("failed to write PDF: %w", err)
	}

	return filename, nil
}

// ── Cover page ─────────────────────────────────────────────────────────────

func (r *PDFReport) renderCover(target string, startedAt time.Time, counts map[engine.Severity]int, total int) {
	// Dark background.
	r.pdf.SetFillColor(colBgR, colBgG, colBgB)
	r.pdf.Rect(0, 0, 210, 297, "F")

	// Green accent bar at top.
	r.pdf.SetFillColor(colAccR, colAccG, colAccB)
	r.pdf.Rect(0, 0, 210, 8, "F")

	// Tool name.
	r.pdf.SetY(40)
	r.pdf.SetFont("Helvetica", "B", 32)
	r.pdf.SetTextColor(230, 237, 243)
	r.pdf.CellFormat(180, 14, "AETHER-SNIFFER", "", 1, "C", false, 0, "")

	// Subtitle.
	r.pdf.SetFont("Helvetica", "", 14)
	r.pdf.SetTextColor(colAccR, colAccG, colAccB)
	r.pdf.CellFormat(180, 8, "Security Audit Report", "", 1, "C", false, 0, "")

	r.pdf.Ln(12)

	// Divider.
	r.pdf.SetDrawColor(colAccR, colAccG, colAccB)
	r.pdf.SetLineWidth(0.5)
	r.pdf.Line(30, r.pdf.GetY(), 180, r.pdf.GetY())
	r.pdf.Ln(10)

	// Scan details.
	r.pdf.SetFont("Helvetica", "", 11)
	r.pdf.SetTextColor(colLowR, colLowG, colLowB)
	details := [][]string{
		{"Target", target},
		{"Date", startedAt.Format("January 2, 2006 at 15:04 UTC")},
		{"Tool Version", "v" + r.version},
		{"Total Findings", fmt.Sprintf("%d", total)},
	}
	for _, d := range details {
		r.pdf.SetFont("Helvetica", "B", 11)
		r.pdf.SetTextColor(colLowR, colLowG, colLowB)
		r.pdf.CellFormat(60, 8, d[0]+":", "", 0, "R", false, 0, "")
		r.pdf.SetFont("Helvetica", "", 11)
		r.pdf.SetTextColor(colTextR, colTextG, colTextB)
		r.pdf.CellFormat(100, 8, d[1], "", 1, "L", false, 0, "")
	}

	r.pdf.Ln(16)

	// Severity summary boxes.
	severities := []struct {
		label string
		sev   engine.Severity
		r, g, b int
	}{
		{"CRITICAL", engine.SeverityCritical, colCritR, colCritG, colCritB},
		{"HIGH", engine.SeverityHigh, colHighR, colHighG, colHighB},
		{"MEDIUM", engine.SeverityMedium, colMedR, colMedG, colMedB},
		{"LOW", engine.SeverityLow, colLowR, colLowG, colLowB},
	}

	startX := 25.0
	boxW := 37.0
	boxH := 28.0
	gap := 5.0

	for i, s := range severities {
		x := startX + float64(i)*(boxW+gap)
		y := r.pdf.GetY()

		// Box background.
		r.pdf.SetFillColor(colDarkR, colDarkG, colDarkB)
		r.pdf.SetDrawColor(s.r, s.g, s.b)
		r.pdf.SetLineWidth(0.8)
		r.pdf.RoundedRect(x, y, boxW, boxH, 3, "1234", "FD")

		// Count.
		r.pdf.SetFont("Helvetica", "B", 20)
		r.pdf.SetTextColor(s.r, s.g, s.b)
		r.pdf.SetXY(x, y+4)
		r.pdf.CellFormat(boxW, 10, fmt.Sprintf("%d", counts[s.sev]), "", 1, "C", false, 0, "")

		// Label.
		r.pdf.SetFont("Helvetica", "B", 8)
		r.pdf.SetTextColor(s.r, s.g, s.b)
		r.pdf.SetXY(x, y+16)
		r.pdf.CellFormat(boxW, 6, s.label, "", 1, "C", false, 0, "")
	}

	r.pdf.Ln(40)

	// Footer.
	r.pdf.SetY(270)
	r.pdf.SetFont("Helvetica", "", 9)
	r.pdf.SetTextColor(colLowR, colLowG, colLowB)
	r.pdf.CellFormat(180, 6,
		"Generated by AETHER-SNIFFER - github.com/Fredrickighile/aether-sniffer",
		"", 1, "C", false, 0, "")
	r.pdf.CellFormat(180, 6,
		"CONFIDENTIAL - Contains sensitive security findings. Do not distribute.",
		"", 1, "C", false, 0, "")

	// Green accent bar at bottom.
	r.pdf.SetFillColor(colAccR, colAccG, colAccB)
	r.pdf.Rect(0, 289, 210, 8, "F")
}

// ── Executive Summary ──────────────────────────────────────────────────────

func (r *PDFReport) renderExecutiveSummary(findings []engine.Finding, counts map[engine.Severity]int, target string, startedAt time.Time) {
	r.sectionHeader("Executive Summary")

	r.pdf.SetFont("Helvetica", "", 11)
	r.pdf.SetTextColor(80, 80, 80)

	total := len(findings)
	critical := counts[engine.SeverityCritical]
	high := counts[engine.SeverityHigh]

	var summary string
	if total == 0 {
		summary = fmt.Sprintf(
			"AETHER-SNIFFER scanned %s on %s and found no security issues. "+
				"The target is clean. No secrets, misconfigurations, or Shadow AI endpoints were detected.",
			target, startedAt.Format("January 2, 2006"))
	} else if critical > 0 {
		summary = fmt.Sprintf(
			"AETHER-SNIFFER scanned %s on %s and found %d security issue(s) requiring immediate attention. "+
				"%d finding(s) are rated CRITICAL and must be remediated before this codebase or "+
				"infrastructure is considered safe. Exposed credentials should be rotated immediately.",
			target, startedAt.Format("January 2, 2006"), total, critical)
	} else if high > 0 {
		summary = fmt.Sprintf(
			"AETHER-SNIFFER scanned %s on %s and found %d security issue(s). "+
				"%d finding(s) are rated HIGH severity and should be remediated within 7 days "+
				"according to most enterprise security policies.",
			target, startedAt.Format("January 2, 2006"), total, high)
	} else {
		summary = fmt.Sprintf(
			"AETHER-SNIFFER scanned %s on %s and found %d low to medium severity issue(s). "+
				"No critical or high severity findings were detected. "+
				"The identified issues should be addressed as part of regular security maintenance.",
			target, startedAt.Format("January 2, 2006"), total)
	}

	r.pdf.MultiCell(180, 6, summary, "", "L", false)
	r.pdf.Ln(8)

	// Findings breakdown table.
	r.subHeader("Findings Breakdown")

	headers := []string{"Severity", "Count", "Priority"}
	colW := []float64{50, 30, 100}
	rows := [][]string{
		{"CRITICAL", fmt.Sprintf("%d", counts[engine.SeverityCritical]), "Remediate immediately - credentials exposed"},
		{"HIGH", fmt.Sprintf("%d", counts[engine.SeverityHigh]), "Remediate within 7 days"},
		{"MEDIUM", fmt.Sprintf("%d", counts[engine.SeverityMedium]), "Remediate within 30 days"},
		{"LOW", fmt.Sprintf("%d", counts[engine.SeverityLow]), "Remediate in next security sprint"},
		{"INFO", fmt.Sprintf("%d", counts[engine.SeverityInfo]), "Review and acknowledge"},
	}

	// Table header.
	r.pdf.SetFillColor(colDarkR, colDarkG, colDarkB)
	r.pdf.SetTextColor(colTextR, colTextG, colTextB)
	r.pdf.SetFont("Helvetica", "B", 10)
	for i, h := range headers {
		r.pdf.CellFormat(colW[i], 8, h, "1", 0, "C", true, 0, "")
	}
	r.pdf.Ln(-1)

	// Table rows.
	r.pdf.SetFont("Helvetica", "", 10)
	for _, row := range rows {
		r.pdf.SetFillColor(255, 255, 255)
		r.pdf.SetTextColor(60, 60, 60)

		// Colour the severity cell.
		switch row[0] {
		case "CRITICAL":
			r.pdf.SetTextColor(colCritR, colCritG, colCritB)
		case "HIGH":
			r.pdf.SetTextColor(colHighR, colHighG, colHighB)
		case "MEDIUM":
			r.pdf.SetTextColor(colMedR, colMedG, colMedB)
		case "LOW":
			r.pdf.SetTextColor(colLowR, colLowG, colLowB)
		}

		r.pdf.CellFormat(colW[0], 7, row[0], "1", 0, "C", false, 0, "")
		r.pdf.SetTextColor(60, 60, 60)
		r.pdf.CellFormat(colW[1], 7, row[1], "1", 0, "C", false, 0, "")
		r.pdf.CellFormat(colW[2], 7, row[2], "1", 0, "L", false, 0, "")
		r.pdf.Ln(-1)
	}
}

// ── Findings ───────────────────────────────────────────────────────────────

func (r *PDFReport) renderFindings(findings []engine.Finding) {
	r.sectionHeader("Detailed Findings")

	// Sort by severity: Critical first.
	order := []engine.Severity{
		engine.SeverityCritical,
		engine.SeverityHigh,
		engine.SeverityMedium,
		engine.SeverityLow,
		engine.SeverityInfo,
	}

	findingNum := 0
	for _, sev := range order {
		for _, f := range findings {
			if f.Severity != sev {
				continue
			}
			findingNum++
			r.renderFinding(findingNum, f)
		}
	}
}

func (r *PDFReport) renderFinding(num int, f engine.Finding) {
	// Check if we need a new page.
	if r.pdf.GetY() > 230 {
		r.pdf.AddPage()
	}

	sevR, sevG, sevB := severityColor(f.Severity)

	// Finding header bar.
	r.pdf.SetFillColor(colDarkR, colDarkG, colDarkB)
	r.pdf.SetDrawColor(sevR, sevG, sevB)
	r.pdf.SetLineWidth(0.5)
	r.pdf.RoundedRect(15, r.pdf.GetY(), 180, 10, 2, "1234", "FD")

	r.pdf.SetFont("Helvetica", "B", 10)
	r.pdf.SetTextColor(sevR, sevG, sevB)
	r.pdf.CellFormat(20, 10, fmt.Sprintf("#%d", num), "", 0, "C", false, 0, "")

	r.pdf.SetTextColor(sevR, sevG, sevB)
	r.pdf.CellFormat(25, 10, string(f.Severity), "", 0, "C", false, 0, "")

	r.pdf.SetTextColor(230, 237, 243)
	title := f.Title
	if len(title) > 60 {
		title = title[:57] + "..."
	}
	r.pdf.CellFormat(135, 10, title, "", 1, "L", false, 0, "")

	r.pdf.Ln(2)

	// Finding details.
	details := [][]string{
		{"Scanner", f.Scanner},
		{"Location", f.Location},
		{"Confidence", fmt.Sprintf("%d%%", f.Confidence)},
	}
	if f.Match != "" {
		details = append(details, []string{"Match", f.Match})
	}

	r.pdf.SetFont("Helvetica", "", 9)
	for _, d := range details {
		r.pdf.SetTextColor(colLowR, colLowG, colLowB)
		r.pdf.CellFormat(30, 5, d[0]+":", "", 0, "R", false, 0, "")
		r.pdf.SetTextColor(60, 60, 60)
		val := d[1]
		if len(val) > 80 {
			val = val[:77] + "..."
		}
		r.pdf.CellFormat(150, 5, val, "", 1, "L", false, 0, "")
	}

	r.pdf.Ln(2)

	// Description.
	r.pdf.SetFont("Helvetica", "B", 9)
	r.pdf.SetTextColor(80, 80, 80)
	r.pdf.CellFormat(180, 5, "Description:", "", 1, "L", false, 0, "")
	r.pdf.SetFont("Helvetica", "", 9)
	r.pdf.SetTextColor(60, 60, 60)
	r.pdf.MultiCell(180, 4, f.Description, "", "L", false)

	r.pdf.Ln(1)

	// Remediation box.
	if f.Remediation != "" {
		r.pdf.SetFillColor(232, 248, 240)
		r.pdf.SetDrawColor(colAccR, colAccG, colAccB)
		r.pdf.SetLineWidth(0.3)

		yBefore := r.pdf.GetY()
		r.pdf.SetFont("Helvetica", "B", 9)
		r.pdf.SetTextColor(colAccR, colAccG, colAccB)
		r.pdf.CellFormat(180, 5, "Remediation:", "LTR", 1, "L", true, 0, "")
		r.pdf.SetFont("Helvetica", "", 9)
		r.pdf.SetTextColor(40, 80, 60)
		r.pdf.MultiCell(180, 4, f.Remediation, "LBR", "L", true)
		_ = yBefore
	}

	r.pdf.Ln(6)

	// Separator line.
	r.pdf.SetDrawColor(colBorderR, colBorderG, colBorderB)
	r.pdf.SetLineWidth(0.2)
	r.pdf.Line(15, r.pdf.GetY(), 195, r.pdf.GetY())
	r.pdf.Ln(4)
}

// ── Appendix ───────────────────────────────────────────────────────────────

func (r *PDFReport) renderAppendix(results []engine.Result, startedAt time.Time) {
	r.sectionHeader("Appendix - Scan Metadata")

	var totalDuration time.Duration
	scannerNames := []string{}
	for _, res := range results {
		totalDuration += res.Duration
		scannerNames = append(scannerNames, res.JobID)
	}

	meta := [][]string{
		{"Tool", "AETHER-SNIFFER v" + r.version},
		{"GitHub", "github.com/Fredrickighile/aether-sniffer"},
		{"Scan started", startedAt.UTC().Format(time.RFC3339)},
		{"Total duration", totalDuration.Round(time.Millisecond).String()},
		{"Scanners run", strings.Join(scannerNames, ", ")},
		{"Scan ID", fmt.Sprintf("as-%d", startedAt.UnixMilli())},
	}

	r.pdf.SetFont("Helvetica", "", 10)
	for _, m := range meta {
		r.pdf.SetTextColor(colLowR, colLowG, colLowB)
		r.pdf.SetFont("Helvetica", "B", 10)
		r.pdf.CellFormat(50, 6, m[0]+":", "", 0, "R", false, 0, "")
		r.pdf.SetTextColor(60, 60, 60)
		r.pdf.SetFont("Helvetica", "", 10)
		r.pdf.CellFormat(130, 6, m[1], "", 1, "L", false, 0, "")
	}

	r.pdf.Ln(8)
	r.subHeader("About AETHER-SNIFFER")
	r.pdf.SetFont("Helvetica", "", 10)
	r.pdf.SetTextColor(80, 80, 80)
	r.pdf.MultiCell(180, 5,
		"AETHER-SNIFFER is the first AI-aware cloud security auditor. It detects exposed secrets, "+
			"cloud misconfigurations, and Shadow AI - unauthorized use of LLM APIs inside enterprise "+
			"codebases. Built in Go for performance and distributed as a single binary for ease of deployment. "+
			"All scanning runs locally. No data leaves the machine.",
		"", "L", false)
}

// ── Helpers ────────────────────────────────────────────────────────────────

func (r *PDFReport) sectionHeader(title string) {
	r.pdf.SetFont("Helvetica", "B", 16)
	r.pdf.SetTextColor(colAccR, colAccG, colAccB)
	r.pdf.CellFormat(180, 10, title, "", 1, "L", false, 0, "")
	r.pdf.SetDrawColor(colAccR, colAccG, colAccB)
	r.pdf.SetLineWidth(0.5)
	r.pdf.Line(15, r.pdf.GetY(), 195, r.pdf.GetY())
	r.pdf.Ln(6)
}

func (r *PDFReport) subHeader(title string) {
	r.pdf.SetFont("Helvetica", "B", 12)
	r.pdf.SetTextColor(60, 60, 60)
	r.pdf.CellFormat(180, 8, title, "", 1, "L", false, 0, "")
	r.pdf.Ln(2)
}

func severityColor(s engine.Severity) (int, int, int) {
	switch s {
	case engine.SeverityCritical:
		return colCritR, colCritG, colCritB
	case engine.SeverityHigh:
		return colHighR, colHighG, colHighB
	case engine.SeverityMedium:
		return colMedR, colMedG, colMedB
	case engine.SeverityLow:
		return colLowR, colLowG, colLowB
	default:
		return colLowR, colLowG, colLowB
	}
}