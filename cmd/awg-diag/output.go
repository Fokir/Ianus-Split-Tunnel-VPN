//go:build windows

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// TestResult holds the outcome of a single diagnostic test.
type TestResult struct {
	Name      string `json:"name"`
	Success   bool   `json:"success"`
	LatencyMs int64  `json:"latency_ms,omitempty"`
	Details   string `json:"details,omitempty"`
	Error     string `json:"error,omitempty"`
}

// outputResult prints a single test result.
func outputResult(r TestResult) {
	if jsonOutput {
		outputJSON(r)
		return
	}
	status := "OK"
	if !r.Success {
		status = "FAIL"
	}
	diagLog.Printf("[%-4s] %s", status, r.Name)
	if r.LatencyMs > 0 {
		diagLog.Printf("       Latency: %d ms", r.LatencyMs)
	}
	if r.Details != "" {
		for _, line := range strings.Split(r.Details, "\n") {
			diagLog.Printf("       %s", line)
		}
	}
	if r.Error != "" {
		diagLog.Printf("       Error: %s", r.Error)
	}
}

// outputResults prints a table of results with a summary line.
func outputResults(results []TestResult) {
	if jsonOutput {
		outputJSON(results)
		return
	}

	passed := 0
	failed := 0
	for _, r := range results {
		if r.Success {
			passed++
		} else {
			failed++
		}
	}

	diagLog.Printf("%-25s %-6s %10s  %s", "TEST", "STATUS", "LATENCY", "DETAILS")
	diagLog.Printf("%s", strings.Repeat("-", 72))
	for _, r := range results {
		status := "OK"
		if !r.Success {
			status = "FAIL"
		}
		latency := ""
		if r.LatencyMs > 0 {
			latency = fmt.Sprintf("%d ms", r.LatencyMs)
		}
		detail := r.Details
		if r.Error != "" {
			detail = r.Error
		}
		// Truncate long details for table view.
		if len(detail) > 40 {
			detail = detail[:37] + "..."
		}
		diagLog.Printf("%-25s %-6s %10s  %s", r.Name, status, latency, detail)
	}
	diagLog.Printf("%s", strings.Repeat("-", 72))
	diagLog.Printf("Total: %d passed, %d failed, %d total", passed, failed, len(results))
}

// outputJSON writes any value as indented JSON to stdout.
func outputJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}
