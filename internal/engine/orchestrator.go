// Package engine is the heart of AETHER-SNIFFER.
// It owns the goroutine pool, rate limiter, and scan lifecycle.
// Every scanner module submits jobs here. The engine handles
// concurrency, cancellation, timeouts, and result aggregation.
package engine

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/Fredrickighile/aether-sniffer/internal/config"
	"golang.org/x/time/rate"
)

// Severity classifies how dangerous a finding is.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// Finding is a single security issue discovered by any scanner module.
// It is the universal output type — every scanner produces []Finding.
type Finding struct {
	// ID is a unique, deterministic identifier for deduplication.
	// Format: "<scanner>-<sha256 of target+match[:8]>"
	ID string

	// Scanner is the name of the module that found this issue.
	// e.g. "secrets", "cloud", "shadowai", "container"
	Scanner string

	// Severity is the risk level of this finding.
	Severity Severity

	// Title is a short, human-readable summary (max 80 chars).
	Title string

	// Description explains what was found and why it matters.
	Description string

	// Location is where the finding was discovered.
	// e.g. "s3://my-bucket/config.env" or "docker-compose.yml:42"
	Location string

	// Match is the redacted secret or misconfiguration that triggered this.
	// NEVER store the full secret. Always redact: "sk-...abcd"
	Match string

	// Confidence is 0–100. Our AI layer sets this after triage.
	Confidence int

	// Remediation is a concrete, actionable fix the user can apply now.
	Remediation string

	// DiscoveredAt is when this finding was recorded.
	DiscoveredAt time.Time
}

// Job is a unit of work submitted to the engine by a scanner.
// The engine calls Execute() in a goroutine from the pool.
type Job struct {
	// ID is a human-readable job identifier for logging.
	ID string

	// Execute performs the scan and returns findings + any error.
	// It MUST respect ctx cancellation — check ctx.Done() in long loops.
	Execute func(ctx context.Context) ([]Finding, error)
}

// Result wraps the output of a completed Job.
type Result struct {
	JobID    string
	Findings []Finding
	Err      error
	Duration time.Duration
}

// Orchestrator manages the full scan lifecycle.
// Create one per scan run with New(), then call Run().
type Orchestrator struct {
	cfg     *config.Config
	limiter *rate.Limiter
	jobs    []Job
	mu      sync.Mutex
}

// New creates a production-ready Orchestrator from the global config.
func New(cfg *config.Config) *Orchestrator {
	return &Orchestrator{
		cfg: cfg,
		// Token bucket: cfg.RateLimit tokens per second, burst of 1.
		// This prevents hammering cloud APIs and triggering rate-limit bans.
		limiter: rate.NewLimiter(rate.Limit(cfg.RateLimit), 1),
	}
}

// Submit adds a Job to the queue. Safe to call from multiple goroutines.
// Must be called before Run().
func (o *Orchestrator) Submit(job Job) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.jobs = append(o.jobs, job)
}

// Run executes all submitted jobs concurrently, respecting the configured
// concurrency limit and timeout. It blocks until all jobs complete or
// the context is cancelled/times out.
//
// Returns all results (including failed ones) so the output layer can
// report partial findings even if some scanners errored.
func (o *Orchestrator) Run(ctx context.Context) ([]Result, error) {
	if len(o.jobs) == 0 {
		return nil, fmt.Errorf("no jobs submitted — add at least one scan target")
	}

	// Apply the global timeout on top of any parent context deadline.
	ctx, cancel := context.WithTimeout(ctx, o.cfg.Timeout)
	defer cancel()

	jobCh := make(chan Job, len(o.jobs))
	resultCh := make(chan Result, len(o.jobs))

	// Seed the job channel.
	for _, job := range o.jobs {
		jobCh <- job
	}
	close(jobCh)

	// Spin up the worker pool.
	var wg sync.WaitGroup
	workerCount := min(o.cfg.Concurrency, len(o.jobs))

	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			o.worker(ctx, jobCh, resultCh)
		}()
	}

	// Close resultCh once all workers are done.
	go func() {
		wg.Wait()
		close(resultCh)
	}()

	// Collect results.
	var results []Result
	for r := range resultCh {
		results = append(results, r)
	}

	return results, ctx.Err()
}

// worker pulls jobs from jobCh, rate-limits, executes, and sends results.
// It exits when jobCh is closed or ctx is cancelled.
func (o *Orchestrator) worker(ctx context.Context, jobCh <-chan Job, resultCh chan<- Result) {
	for {
		select {
		case <-ctx.Done():
			return
		case job, ok := <-jobCh:
			if !ok {
				return
			}

			// Block until the rate limiter allows this operation.
			if err := o.limiter.Wait(ctx); err != nil {
				resultCh <- Result{
					JobID: job.ID,
					Err:   fmt.Errorf("rate limiter cancelled: %w", err),
				}
				continue
			}

			start := time.Now()
			findings, err := job.Execute(ctx)
			resultCh <- Result{
				JobID:    job.ID,
				Findings: findings,
				Err:      err,
				Duration: time.Since(start),
			}
		}
	}
}

// min returns the smaller of two ints.
// Replaces math.Min which operates on float64.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}