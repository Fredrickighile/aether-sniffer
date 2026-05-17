// Package tui provides the interactive terminal dashboard for AETHER-SNIFFER.
// Built with Bubble Tea (Elm architecture) and Lip Gloss for styling.
// This is the "wow factor" — a live, animated dashboard that no competitor has.
package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/progress"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/fredthebuilder/aether-sniffer/internal/engine"
)

// ── Colours ────────────────────────────────────────────────────────────────
var (
	colorAccent   = lipgloss.Color("#1D9E75")
	colorCritical = lipgloss.Color("#E85D4A")
	colorHigh     = lipgloss.Color("#F0A500")
	colorMedium   = lipgloss.Color("#4B9CD3")
	colorLow      = lipgloss.Color("#8B949E")
	colorInfo     = lipgloss.Color("#6B5CE7")
	colorBorder   = lipgloss.Color("#30363D")
	colorDim      = lipgloss.Color("#8B949E")
	colorWhite    = lipgloss.Color("#E6EDF3")
	colorBg       = lipgloss.Color("#0D1117")
)

// ── Styles ─────────────────────────────────────────────────────────────────
var (
	styleBanner = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorAccent).
			PaddingBottom(1)

	styleBox = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(colorBorder).
			Padding(0, 1)

	styleTitle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorWhite)

	styleDim = lipgloss.NewStyle().
			Foreground(colorDim)

	styleCritical = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorCritical)

	styleHigh = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorHigh)

	styleMedium = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorMedium)

	styleLow = lipgloss.NewStyle().
			Foreground(colorLow)

	styleInfo = lipgloss.NewStyle().
			Foreground(colorInfo)

	styleBadgeCritical = lipgloss.NewStyle().
				Bold(true).
				Foreground(colorBg).
				Background(colorCritical).
				Padding(0, 1)

	styleBadgeHigh = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorBg).
			Background(colorHigh).
			Padding(0, 1)

	styleBadgeMedium = lipgloss.NewStyle().
				Bold(true).
				Foreground(colorBg).
				Background(colorMedium).
				Padding(0, 1)

	styleBadgeLow = lipgloss.NewStyle().
			Foreground(colorWhite).
			Background(colorLow).
			Padding(0, 1)

	styleFooter = lipgloss.NewStyle().
			Foreground(colorDim).
			BorderTop(true).
			BorderStyle(lipgloss.NormalBorder()).
			BorderForeground(colorBorder).
			PaddingTop(1).
			MarginTop(1)
)

// ── Tick message for the spinner ───────────────────────────────────────────
type tickMsg time.Time

func tick() tea.Cmd {
	return tea.Tick(120*time.Millisecond, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

// ── ScanDoneMsg is sent when the scan finishes ─────────────────────────────
type ScanDoneMsg struct {
	Results  []engine.Result
	Duration time.Duration
}

// ── Model is the Bubble Tea application state ──────────────────────────────
type Model struct {
	// Scan state
	target    string
	results   []engine.Result
	done      bool
	duration  time.Duration
	startedAt time.Time

	// UI state
	spinnerIdx  int
	progress    progress.Model
	progPercent float64
	width       int
	height      int
	scrollIdx   int // which finding is highlighted

	// Findings cache (flattened after scan)
	findings []engine.Finding
}

var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// New creates the initial TUI model.
func New(target string) Model {
	p := progress.New(
		progress.WithDefaultGradient(),
		progress.WithWidth(50),
		progress.WithoutPercentage(),
	)
	return Model{
		target:    target,
		startedAt: time.Now(),
		progress:  p,
		width:     80,
	}
}

// Init starts the spinner tick and waits for ScanDoneMsg.
func (m Model) Init() tea.Cmd {
	return tick()
}

// Update handles all incoming messages.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.progress.Width = m.width - 10
		if m.progress.Width > 60 {
			m.progress.Width = 60
		}
		return m, nil

	case tickMsg:
		if m.done {
			return m, nil
		}
		m.spinnerIdx = (m.spinnerIdx + 1) % len(spinnerFrames)
		// Animate progress bar during scan (fake progress for UX).
		if m.progPercent < 0.85 {
			m.progPercent += 0.03
		}
		return m, tick()

	case ScanDoneMsg:
		m.done = true
		m.results = msg.Results
		m.duration = msg.Duration
		m.progPercent = 1.0
		// Flatten findings.
		for _, r := range m.results {
			m.findings = append(m.findings, r.Findings...)
		}
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "down", "j":
			if m.scrollIdx < len(m.findings)-1 {
				m.scrollIdx++
			}
		case "up", "k":
			if m.scrollIdx > 0 {
				m.scrollIdx--
			}
		}
		return m, nil
	}

	return m, nil
}

// View renders the entire TUI.
func (m Model) View() string {
	var sb strings.Builder

	sb.WriteString(m.renderBanner())
	sb.WriteString("\n")
	sb.WriteString(m.renderStatus())
	sb.WriteString("\n\n")

	if m.done {
		sb.WriteString(m.renderSummary())
		sb.WriteString("\n")
		if len(m.findings) > 0 {
			sb.WriteString(m.renderFindings())
		} else {
			sb.WriteString(m.renderClean())
		}
	}

	sb.WriteString(m.renderFooter())
	return sb.String()
}

// renderBanner renders the ASCII logo and version.
func (m Model) renderBanner() string {
	logo := styleBanner.Render("AETHER-SNIFFER") +
		styleDim.Render(" v0.1.0  —  AI-aware cloud security auditor")
	sep := styleDim.Render(strings.Repeat("─", min(m.width-2, 60)))
	return logo + "\n" + sep
}

// renderStatus shows the scan progress / spinner.
func (m Model) renderStatus() string {
	elapsed := time.Since(m.startedAt).Round(time.Millisecond)
	if m.done {
		elapsed = m.duration
	}

	targetLine := styleTitle.Render("Target: ") +
		styleDim.Render(m.target)

	var statusLine string
	if m.done {
		statusLine = lipgloss.NewStyle().Foreground(colorAccent).Bold(true).
			Render("✔  Scan complete") +
			styleDim.Render(fmt.Sprintf("  (%s)", elapsed))
	} else {
		spinner := lipgloss.NewStyle().Foreground(colorAccent).
			Render(spinnerFrames[m.spinnerIdx])
		statusLine = spinner + styleDim.Render(fmt.Sprintf("  Scanning...  %s", elapsed))
	}

	bar := m.progress.ViewAs(m.progPercent)

	return targetLine + "\n" + statusLine + "\n" + bar
}

// renderSummary shows the finding counts by severity.
func (m Model) renderSummary() string {
	counts := map[engine.Severity]int{}
	for _, f := range m.findings {
		counts[f.Severity]++
	}

	total := len(m.findings)
	totalStr := fmt.Sprintf("%d finding(s)", total)
	if total == 0 {
		totalStr = "0 findings"
	}

	header := styleTitle.Render("Summary  ") + styleDim.Render(totalStr)

	badges := []string{}
	if n := counts[engine.SeverityCritical]; n > 0 {
		badges = append(badges, styleBadgeCritical.Render(fmt.Sprintf(" CRITICAL %d ", n)))
	}
	if n := counts[engine.SeverityHigh]; n > 0 {
		badges = append(badges, styleBadgeHigh.Render(fmt.Sprintf(" HIGH %d ", n)))
	}
	if n := counts[engine.SeverityMedium]; n > 0 {
		badges = append(badges, styleBadgeMedium.Render(fmt.Sprintf(" MEDIUM %d ", n)))
	}
	if n := counts[engine.SeverityLow]; n > 0 {
		badges = append(badges, styleBadgeLow.Render(fmt.Sprintf(" LOW %d ", n)))
	}
	if len(badges) == 0 {
		badges = append(badges, lipgloss.NewStyle().
			Foreground(colorAccent).Bold(true).Render("✔  Clean"))
	}

	badgeLine := strings.Join(badges, "  ")
	content := header + "\n" + badgeLine
	return styleBox.Width(min(m.width-4, 62)).Render(content) + "\n"
}

// renderFindings renders the scrollable findings list.
func (m Model) renderFindings() string {
	var sb strings.Builder

	sb.WriteString(styleTitle.Render("Findings") +
		styleDim.Render("  ↑/↓ to navigate  q to quit") + "\n\n")

	// Show up to 8 findings at a time.
	visible := 8
	start := 0
	if m.scrollIdx >= visible {
		start = m.scrollIdx - visible + 1
	}
	end := start + visible
	if end > len(m.findings) {
		end = len(m.findings)
	}

	for i := start; i < end; i++ {
		f := m.findings[i]
		selected := i == m.scrollIdx

		sevStyle := severityStyle(f.Severity)
		sevBadge := severityBadge(f.Severity)

		prefix := "  "
		if selected {
			prefix = lipgloss.NewStyle().Foreground(colorAccent).Render("▶ ")
		}

		title := prefix + sevBadge + "  " + sevStyle.Render(f.Title)
		loc := "   " + styleDim.Render("Location: ") + styleDim.Render(f.Location)
		match := "   " + styleDim.Render("Match:    ") + styleDim.Render(f.Match)
		conf := "   " + styleDim.Render(fmt.Sprintf("Confidence: %d%%", f.Confidence))

		sb.WriteString(title + "\n")
		sb.WriteString(loc + "\n")
		sb.WriteString(match + "\n")
		sb.WriteString(conf + "\n")

		// Show fix only for selected finding.
		if selected && f.Remediation != "" {
			fix := wrapText("   Fix: "+f.Remediation, min(m.width-6, 72))
			sb.WriteString(lipgloss.NewStyle().Foreground(colorAccent).Render(fix) + "\n")
		}

		sb.WriteString(styleDim.Render("   " + strings.Repeat("─", min(m.width-8, 54))) + "\n")
	}

	if len(m.findings) > visible {
		sb.WriteString(styleDim.Render(fmt.Sprintf(
			"   %d of %d findings shown", end-start, len(m.findings))) + "\n")
	}

	return sb.String()
}

// renderClean renders the all-clear panel when nothing is found.
func (m Model) renderClean() string {
	content := lipgloss.NewStyle().
		Bold(true).
		Foreground(colorAccent).
		Render("✔  No secrets or Shadow AI endpoints detected.") +
		"\n" +
		styleDim.Render("   This codebase is clean. Keep it that way.")
	return styleBox.
		BorderForeground(colorAccent).
		Width(min(m.width-4, 62)).
		Render(content) + "\n"
}

// renderFooter renders the key hint bar.
func (m Model) renderFooter() string {
	hints := styleDim.Render("q quit  ·  ↑/↓ navigate  ·  github.com/Fredrickighile/aether-sniffer")
	return styleFooter.Width(min(m.width-2, 62)).Render(hints)
}

// ── Helpers ────────────────────────────────────────────────────────────────

func severityStyle(s engine.Severity) lipgloss.Style {
	switch s {
	case engine.SeverityCritical:
		return styleCritical
	case engine.SeverityHigh:
		return styleHigh
	case engine.SeverityMedium:
		return styleMedium
	case engine.SeverityLow:
		return styleLow
	default:
		return styleInfo
	}
}

func severityBadge(s engine.Severity) string {
	switch s {
	case engine.SeverityCritical:
		return styleBadgeCritical.Render("CRITICAL")
	case engine.SeverityHigh:
		return styleBadgeHigh.Render("HIGH")
	case engine.SeverityMedium:
		return styleBadgeMedium.Render("MEDIUM")
	case engine.SeverityLow:
		return styleBadgeLow.Render("LOW")
	default:
		return styleInfo.Render("INFO")
	}
}

func wrapText(text string, width int) string {
	if len(text) <= width {
		return text
	}
	words := strings.Fields(text)
	var lines []string
	line := ""
	for _, w := range words {
		if len(line)+len(w)+1 > width {
			lines = append(lines, line)
			line = w
		} else {
			if line == "" {
				line = w
			} else {
				line += " " + w
			}
		}
	}
	if line != "" {
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Run launches the Bubble Tea program and blocks until the user quits.
func Run(target string, scanFn func() ([]engine.Result, time.Duration)) error {
	m := New(target)
	p := tea.NewProgram(m, tea.WithAltScreen())

	// Run the scan in a goroutine and send result to the TUI.
	go func() {
		results, dur := scanFn()
		p.Send(ScanDoneMsg{Results: results, Duration: dur})
	}()

	_, err := p.Run()
	return err
}