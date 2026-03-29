// Package tui provides terminal UI components for PQCAT.
// This file implements a lightweight progress reporter for CLI scans (GAP-08).
// Zero external dependencies — uses only ANSI escape sequences.
package tui

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// Progress provides a lightweight terminal progress indicator for CLI scans.
// Writes to stderr so stdout remains clean for JSON/machine output.
// Thread-safe for concurrent scanner use.
type Progress struct {
	mu       sync.Mutex
	total    int
	current  int
	label    string
	start    time.Time
	quiet    bool // suppress all output
	lastLine int  // length of last line (for clearing)
}

// NewProgress creates a new progress indicator.
// If quiet is true, all output is suppressed (for --quiet mode).
func NewProgress(label string, total int, quiet bool) *Progress {
	p := &Progress{
		label: label,
		total: total,
		start: time.Now(),
		quiet: quiet,
	}
	if !quiet && total > 0 {
		fmt.Fprintf(os.Stderr, "  ⏳ %s (%d items)...\r", label, total)
	}
	return p
}

// Update advances the progress counter and displays status.
func (p *Progress) Update(current int, detail string) {
	if p.quiet {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	p.current = current
	elapsed := time.Since(p.start)

	var line string
	if p.total > 0 {
		pct := float64(current) / float64(p.total) * 100
		// Calculate ETA
		var eta string
		if current > 0 {
			remaining := time.Duration(float64(elapsed) / float64(current) * float64(p.total-current))
			if remaining > time.Second {
				eta = fmt.Sprintf(" ETA %s", remaining.Round(time.Second))
			}
		}
		// Build progress bar (20 chars wide)
		barWidth := 20
		filled := int(pct / 100 * float64(barWidth))
		if filled > barWidth {
			filled = barWidth
		}
		bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)

		line = fmt.Sprintf("  %s %s %3.0f%% (%d/%d) %s%s",
			spinnerFrame(current), bar, pct, current, p.total, truncateStr(detail, 30), eta)
	} else {
		line = fmt.Sprintf("  %s %s: %d found — %s",
			spinnerFrame(current), p.label, current, truncateStr(detail, 40))
	}

	// Clear previous line and write new one
	if p.lastLine > len(line) {
		fmt.Fprintf(os.Stderr, "\r%s\r", strings.Repeat(" ", p.lastLine))
	}
	fmt.Fprintf(os.Stderr, "\r%s", line)
	p.lastLine = len(line)
}

// Done finalizes the progress indicator with a completion message.
func (p *Progress) Done(summary string) {
	if p.quiet {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	elapsed := time.Since(p.start).Round(time.Millisecond)

	// Clear the progress line
	if p.lastLine > 0 {
		fmt.Fprintf(os.Stderr, "\r%s\r", strings.Repeat(" ", p.lastLine+5))
	}
	fmt.Fprintf(os.Stderr, "\r  ✓ %s (%s)\n", summary, elapsed)
}

// spinnerFrame returns an animated spinner character based on counter.
var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

func spinnerFrame(n int) string {
	return spinnerFrames[n%len(spinnerFrames)]
}

// truncateStr truncates a string with ellipsis if too long.
func truncateStr(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max <= 3 {
		return s[:max]
	}
	return s[:max-1] + "…"
}
