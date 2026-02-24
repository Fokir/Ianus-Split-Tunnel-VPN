//go:build windows

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	vpnapi "awg-split-tunnel/api/gen"
	"awg-split-tunnel/internal/core"
	"awg-split-tunnel/internal/ipc"
	"awg-split-tunnel/internal/winsvc"

	"google.golang.org/protobuf/types/known/emptypb"
)

// SuiteResult holds the result of a single test suite.
type SuiteResult struct {
	Suite      string       `json:"suite"`
	Tests      []TestResult `json:"tests"`
	Passed     int          `json:"passed"`
	Failed     int          `json:"failed"`
	Skipped    int          `json:"skipped"`
	DurationMs int64        `json:"duration_ms"`
}

// TestReport holds the full test run report.
type TestReport struct {
	Timestamp    string        `json:"timestamp"`
	Version      string        `json:"version"`
	Suites       []SuiteResult `json:"suites"`
	TotalPassed  int           `json:"total_passed"`
	TotalFailed  int           `json:"total_failed"`
	TotalSkipped int           `json:"total_skipped"`
	DurationMs   int64         `json:"duration_ms"`
}

// allSuiteNames defines the default order of test suites.
var allSuiteNames = []string{"service", "connectivity", "dns", "tunnels", "exclusions"}

// suiteFunc is a function that runs a test suite and returns its result.
type suiteFunc func() SuiteResult

// runTest is the entry point for "awg-diag test".
func runTest(args []string) {
	// Parse --only flag.
	var onlyFilter []string
	for i := 0; i < len(args); i++ {
		if args[i] == "--only" && i+1 < len(args) {
			onlyFilter = strings.Split(args[i+1], ",")
			for j := range onlyFilter {
				onlyFilter[j] = strings.TrimSpace(onlyFilter[j])
			}
			i++
		}
	}

	// Map suite names to functions.
	suiteMap := map[string]suiteFunc{
		"service":      suiteService,
		"connectivity": suiteConnectivity,
		"dns":          suiteDNS,
		"tunnels":      suiteTunnels,
		"exclusions":   suiteExclusions,
	}

	// Determine which suites to run.
	suitesToRun := allSuiteNames
	if len(onlyFilter) > 0 {
		suitesToRun = nil
		for _, name := range onlyFilter {
			if _, ok := suiteMap[name]; ok {
				suitesToRun = append(suitesToRun, name)
			} else {
				fmt.Fprintf(os.Stderr, "Warning: unknown suite %q, skipping\n", name)
			}
		}
	}

	if len(suitesToRun) == 0 {
		fatal("no test suites to run")
	}

	totalStart := time.Now()
	diagLog.Printf("=== AWG Split Tunnel Test Runner ===")
	diagLog.Printf("Version: %s  Suites: %s", version, strings.Join(suitesToRun, ", "))
	diagLog.Printf("")

	var suites []SuiteResult
	totalPassed, totalFailed, totalSkipped := 0, 0, 0

	for _, name := range suitesToRun {
		fn := suiteMap[name]
		diagLog.Printf("--- Suite: %s ---", name)
		result := fn()
		suites = append(suites, result)

		totalPassed += result.Passed
		totalFailed += result.Failed
		totalSkipped += result.Skipped

		// Per-suite summary.
		diagLog.Printf("    %s: %d passed, %d failed, %d skipped (%d ms)",
			name, result.Passed, result.Failed, result.Skipped, result.DurationMs)
		diagLog.Printf("")
	}

	totalDuration := time.Since(totalStart).Milliseconds()

	// Build report.
	report := TestReport{
		Timestamp:    time.Now().Format(time.RFC3339),
		Version:      version,
		Suites:       suites,
		TotalPassed:  totalPassed,
		TotalFailed:  totalFailed,
		TotalSkipped: totalSkipped,
		DurationMs:   totalDuration,
	}

	// Save JSON report.
	saveTestReport(report)

	// Print final summary.
	diagLog.Printf("=== Results ===")
	diagLog.Printf("%-20s %8s %8s %8s %10s", "SUITE", "PASSED", "FAILED", "SKIPPED", "DURATION")
	diagLog.Printf("%s", strings.Repeat("-", 60))
	for _, s := range suites {
		diagLog.Printf("%-20s %8d %8d %8d %8d ms", s.Suite, s.Passed, s.Failed, s.Skipped, s.DurationMs)
	}
	diagLog.Printf("%s", strings.Repeat("-", 60))
	diagLog.Printf("%-20s %8d %8d %8d %8d ms", "TOTAL", totalPassed, totalFailed, totalSkipped, totalDuration)

	if jsonOutput {
		outputJSON(report)
	}

	if totalFailed > 0 {
		os.Exit(1)
	}
}

// saveTestReport writes the report JSON to test-results/<timestamp>.json.
func saveTestReport(report TestReport) {
	dir := filepath.Join(exeDirectory(), "test-results")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		diagLog.Printf("Warning: could not create test-results dir: %v", err)
		return
	}

	name := time.Now().Format("2006-01-02_15-04-05") + ".json"
	path := filepath.Join(dir, name)

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		diagLog.Printf("Warning: could not marshal report: %v", err)
		return
	}

	if err := os.WriteFile(path, data, 0o644); err != nil {
		diagLog.Printf("Warning: could not write report: %v", err)
		return
	}

	diagLog.Printf("Report saved: %s", path)
}

// runTestCase runs a single test and logs the result inline.
func runTestCase(result TestResult) TestResult {
	status := "PASS"
	if !result.Success {
		status = "FAIL"
	}
	detail := result.Details
	if result.Error != "" {
		detail = result.Error
	}
	if len(detail) > 60 {
		detail = detail[:57] + "..."
	}
	diagLog.Printf("  [%-4s] %-35s %s", status, result.Name, detail)
	return result
}

// skipTestCase creates a skipped test result.
func skipTestCase(name, reason string) TestResult {
	diagLog.Printf("  [SKIP] %-35s %s", name, reason)
	return TestResult{Name: name, Details: "skipped: " + reason}
}

// buildSuiteResult summarizes a list of test results into a SuiteResult.
func buildSuiteResult(suite string, tests []TestResult, start time.Time) SuiteResult {
	sr := SuiteResult{
		Suite:      suite,
		Tests:      tests,
		DurationMs: time.Since(start).Milliseconds(),
	}
	for _, t := range tests {
		switch {
		case strings.HasPrefix(t.Details, "skipped:"):
			sr.Skipped++
		case t.Success:
			sr.Passed++
		default:
			sr.Failed++
		}
	}
	return sr
}

// dialIPC creates an IPC client with the global timeout. Returns nil on failure.
func dialIPC() *ipc.Client {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	client, err := ipc.DialWithTimeout(ctx, timeout)
	if err != nil {
		return nil
	}
	return client
}

// ---------- Suite: service ----------

func suiteService() SuiteResult {
	start := time.Now()
	var tests []TestResult

	// Test: installed
	{
		r := TestResult{Name: "service-installed"}
		r.Success = winsvc.IsServiceInstalled()
		if r.Success {
			r.Details = winsvc.ServiceName + " is installed"
		} else {
			r.Error = winsvc.ServiceName + " is not installed"
		}
		tests = append(tests, runTestCase(r))
	}

	// Test: running
	{
		r := TestResult{Name: "service-running"}
		r.Success = winsvc.IsServiceRunning()
		if r.Success {
			r.Details = "service is running"
		} else {
			r.Error = "service is not running"
		}
		tests = append(tests, runTestCase(r))
	}

	// Test: IPC reachable
	client := dialIPC()
	{
		r := TestResult{Name: "ipc-reachable"}
		if client != nil {
			r.Success = true
			r.Details = "IPC connection established"
		} else {
			r.Error = "could not connect via IPC"
		}
		tests = append(tests, runTestCase(r))
	}

	if client != nil {
		defer client.Close()

		// Test: GetStatus
		{
			r := TestResult{Name: "service-get-status"}
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			status, err := client.Service.GetStatus(ctx, &emptypb.Empty{})
			cancel()
			if err != nil {
				r.Error = fmt.Sprintf("GetStatus: %v", err)
			} else {
				r.Success = true
				r.Details = fmt.Sprintf("v%s, uptime %ds, %d/%d tunnels active",
					status.GetVersion(), status.GetUptimeSeconds(),
					status.GetActiveTunnels(), status.GetTotalTunnels())
			}
			tests = append(tests, runTestCase(r))
		}

		// Test: ListTunnels
		{
			r := TestResult{Name: "service-list-tunnels"}
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			resp, err := client.Service.ListTunnels(ctx, &emptypb.Empty{})
			cancel()
			if err != nil {
				r.Error = fmt.Sprintf("ListTunnels: %v", err)
			} else {
				tunnels := resp.GetTunnels()
				r.Success = true
				var names []string
				for _, t := range tunnels {
					state := t.GetState().String()
					names = append(names, fmt.Sprintf("%s(%s)", t.GetId(), state))
				}
				r.Details = fmt.Sprintf("%d tunnels: %s", len(tunnels), strings.Join(names, ", "))
			}
			tests = append(tests, runTestCase(r))
		}
	} else {
		tests = append(tests, skipTestCase("service-get-status", "no IPC"))
		tests = append(tests, skipTestCase("service-list-tunnels", "no IPC"))
	}

	return buildSuiteResult("service", tests, start)
}

// ---------- Suite: connectivity ----------

func suiteConnectivity() SuiteResult {
	start := time.Now()
	var tests []TestResult

	// check-ip
	tests = append(tests, runTestCase(doCheckIP()))

	// DNS
	tests = append(tests, runTestCase(doDNS("google.com", "")))
	tests = append(tests, runTestCase(doDNS("cloudflare.com", "1.1.1.1")))

	// TCP
	tests = append(tests, runTestCase(doTCP("1.1.1.1:443")))
	tests = append(tests, runTestCase(doTCP("8.8.8.8:53")))
	tests = append(tests, runTestCase(doTCP("8.8.4.4:443")))

	// UDP
	tests = append(tests, runTestCase(doUDP("8.8.8.8:53", "")))
	tests = append(tests, runTestCase(doUDP("1.1.1.1:53", "")))

	// HTTP
	tests = append(tests, runTestCase(doHTTP("http://httpbin.org/ip")))
	tests = append(tests, runTestCase(doHTTP("https://httpbin.org/ip")))

	// HTTPS
	tests = append(tests, runTestCase(doHTTP("https://ifconfig.me/ip")))
	tests = append(tests, runTestCase(doHTTP("https://api.ipify.org")))
	tests = append(tests, runTestCase(doHTTP("https://www.google.com")))
	tests = append(tests, runTestCase(doHTTP("https://cloudflare.com")))

	// Unreachable (expected failures).
	{
		r := doTCP("192.0.2.1:80") // TEST-NET, should fail.
		r.Name = "tcp-unreachable(192.0.2.1:80)"
		if !r.Success {
			// Expected to fail.
			r.Success = true
			r.Details = "correctly failed: " + r.Error
			r.Error = ""
		} else {
			r.Success = false
			r.Error = "expected connection to fail, but it succeeded"
		}
		tests = append(tests, runTestCase(r))
	}
	{
		r := doUDP("192.0.2.1:53", "test")
		r.Name = "udp-unreachable(192.0.2.1:53)"
		if !r.Success {
			r.Success = true
			r.Details = "correctly failed: " + r.Error
			r.Error = ""
		} else {
			r.Success = false
			r.Error = "expected connection to fail, but it succeeded"
		}
		tests = append(tests, runTestCase(r))
	}

	return buildSuiteResult("connectivity", tests, start)
}

// ---------- Suite: dns ----------

func suiteDNS() SuiteResult {
	start := time.Now()
	var tests []TestResult

	// System resolver.
	tests = append(tests, runTestCase(doDNS("google.com", "")))

	// Specific DNS servers.
	tests = append(tests, runTestCase(doDNS("google.com", "8.8.8.8")))
	tests = append(tests, runTestCase(doDNS("google.com", "1.1.1.1")))
	tests = append(tests, runTestCase(doDNS("google.com", "9.9.9.9")))

	// Multi-domain.
	for _, domain := range []string{"github.com", "cloudflare.com", "amazon.com"} {
		tests = append(tests, runTestCase(doDNS(domain, "")))
	}

	// NXDOMAIN (expected failure).
	{
		r := doDNS("this-domain-does-not-exist-12345.test", "")
		if !r.Success {
			r.Success = true
			r.Details = "correctly got NXDOMAIN: " + r.Error
			r.Error = ""
		} else {
			r.Success = false
			r.Error = "expected NXDOMAIN but got: " + r.Details
		}
		r.Name = "dns-nxdomain"
		tests = append(tests, runTestCase(r))
	}

	return buildSuiteResult("dns", tests, start)
}

// ---------- Suite: tunnels ----------

func suiteTunnels() SuiteResult {
	start := time.Now()
	var tests []TestResult

	// Load config to get tunnel list.
	cfg, err := loadConfig()
	if err != nil {
		tests = append(tests, runTestCase(TestResult{
			Name: "load-config", Error: fmt.Sprintf("load config: %v", err),
		}))
		return buildSuiteResult("tunnels", tests, start)
	}

	// Need IPC for tunnel management.
	client := dialIPC()
	if client == nil {
		tests = append(tests, skipTestCase("tunnels", "no IPC connection - service not running?"))
		return buildSuiteResult("tunnels", tests, start)
	}
	defer client.Close()

	// Save original config for restore.
	origCfg := *cfg

	// Get currently active tunnels for restore.
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	origListResp, err := client.Service.ListTunnels(ctx, &emptypb.Empty{})
	cancel()
	var origActiveTunnels []string
	if err == nil {
		for _, t := range origListResp.GetTunnels() {
			if t.GetState() == vpnapi.TunnelState_TUNNEL_STATE_UP {
				origActiveTunnels = append(origActiveTunnels, t.GetId())
			}
		}
	}

	// Collect unique tunnel IDs.
	seen := make(map[string]bool)
	var tunnelIDs []string
	for _, t := range cfg.Tunnels {
		if !seen[t.ID] {
			seen[t.ID] = true
			tunnelIDs = append(tunnelIDs, t.ID)
		}
	}

	if len(tunnelIDs) == 0 {
		tests = append(tests, skipTestCase("tunnels", "no tunnels configured"))
		return buildSuiteResult("tunnels", tests, start)
	}

	// Defer: restore original rules via IPC and reconnect original tunnels.
	defer func() {
		diagLog.Printf("  [INFO] Restoring original rules and tunnels...")
		if err := saveRulesViaIPC(client, origCfg.Rules); err != nil {
			diagLog.Printf("  [WARN] Failed to restore rules via IPC: %v", err)
		}

		// Disconnect all first.
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		client.Service.Disconnect(ctx, &vpnapi.DisconnectRequest{TunnelId: ""})
		cancel()
		time.Sleep(2 * time.Second)

		// Reconnect original tunnels.
		for _, tid := range origActiveTunnels {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			client.Service.Connect(ctx, &vpnapi.ConnectRequest{TunnelId: tid})
			cancel()
		}
		if len(origActiveTunnels) > 0 {
			time.Sleep(3 * time.Second)
		}
		diagLog.Printf("  [INFO] Restore complete.")
	}()

	exeName := "awg-diag.exe"

	for _, tunnelID := range tunnelIDs {
		diagLog.Printf("  --- Testing tunnel: %s ---", tunnelID)

		// Step 1: Disconnect all tunnels.
		{
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			_, err := client.Service.Disconnect(ctx, &vpnapi.DisconnectRequest{TunnelId: ""})
			cancel()
			if err != nil {
				tests = append(tests, runTestCase(TestResult{
					Name: fmt.Sprintf("%s/disconnect-all", tunnelID), Error: err.Error(),
				}))
				continue
			}
			time.Sleep(2 * time.Second)
		}

		// Step 2: Add temp rule for awg-diag.exe -> this tunnel via IPC.
		{
			cfg, err = loadConfig()
			if err != nil {
				tests = append(tests, runTestCase(TestResult{
					Name: fmt.Sprintf("%s/reload-config", tunnelID), Error: err.Error(),
				}))
				continue
			}

			// Remove any existing rule for awg-diag.exe.
			var filtered []core.Rule
			for _, r := range cfg.Rules {
				if !strings.EqualFold(r.Pattern, exeName) {
					filtered = append(filtered, r)
				}
			}
			filtered = append(filtered, core.Rule{
				Pattern:  exeName,
				TunnelID: tunnelID,
			})
			if err := saveRulesViaIPC(client, filtered); err != nil {
				tests = append(tests, runTestCase(TestResult{
					Name: fmt.Sprintf("%s/save-rule", tunnelID), Error: err.Error(),
				}))
				continue
			}
		}

		// Step 3: Connect this tunnel.
		{
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			resp, err := client.Service.Connect(ctx, &vpnapi.ConnectRequest{TunnelId: tunnelID})
			cancel()
			r := TestResult{Name: fmt.Sprintf("%s/connect", tunnelID)}
			if err != nil {
				r.Error = err.Error()
			} else if !resp.GetSuccess() {
				r.Error = "connect failed: " + resp.GetError()
			} else {
				r.Success = true
				r.Details = "connected"
			}
			tests = append(tests, runTestCase(r))
			if !r.Success {
				continue
			}
		}

		// Wait for tunnel to stabilize.
		time.Sleep(3 * time.Second)

		// Step 4: Run network tests through this tunnel.
		{
			r := doCheckIP()
			r.Name = fmt.Sprintf("%s/check-ip", tunnelID)
			tests = append(tests, runTestCase(r))
		}
		{
			r := doDNS("google.com", "")
			r.Name = fmt.Sprintf("%s/dns", tunnelID)
			tests = append(tests, runTestCase(r))
		}
		{
			r := doTCP("1.1.1.1:443")
			r.Name = fmt.Sprintf("%s/tcp", tunnelID)
			tests = append(tests, runTestCase(r))
		}
		{
			r := doUDP("8.8.8.8:53", "")
			r.Name = fmt.Sprintf("%s/udp", tunnelID)
			tests = append(tests, runTestCase(r))
		}
		{
			r := doHTTP("https://httpbin.org/ip")
			r.Name = fmt.Sprintf("%s/https", tunnelID)
			tests = append(tests, runTestCase(r))
		}
	}

	return buildSuiteResult("tunnels", tests, start)
}

// ---------- Suite: exclusions ----------

func suiteExclusions() SuiteResult {
	start := time.Now()
	var tests []TestResult

	// Need IPC.
	client := dialIPC()
	if client == nil {
		tests = append(tests, skipTestCase("exclusions", "no IPC connection - service not running?"))
		return buildSuiteResult("exclusions", tests, start)
	}
	defer client.Close()

	// Load config.
	cfg, err := loadConfig()
	if err != nil {
		tests = append(tests, runTestCase(TestResult{
			Name: "load-config", Error: fmt.Sprintf("load config: %v", err),
		}))
		return buildSuiteResult("exclusions", tests, start)
	}

	// Save original config for restore.
	origCfg := *cfg
	defer func() {
		diagLog.Printf("  [INFO] Restoring original config via IPC...")
		if err := saveConfigViaIPC(client, &origCfg); err != nil {
			diagLog.Printf("  [WARN] Failed to restore config via IPC: %v", err)
		}
		time.Sleep(1 * time.Second)
		diagLog.Printf("  [INFO] Config restored.")
	}()

	exeName := "awg-diag.exe"

	// Step 1: Get current (VPN) IP.
	vpnIP := doCheckIP()
	vpnIP.Name = "exclusion/vpn-ip"
	tests = append(tests, runTestCase(vpnIP))
	if !vpnIP.Success {
		tests = append(tests, skipTestCase("exclusion/add-disallowed", "could not get VPN IP"))
		return buildSuiteResult("exclusions", tests, start)
	}

	// Step 2: Add awg-diag.exe to global disallowed_apps.
	{
		cfg, err = loadConfig()
		if err != nil {
			tests = append(tests, runTestCase(TestResult{
				Name: "exclusion/reload-config", Error: err.Error(),
			}))
			return buildSuiteResult("exclusions", tests, start)
		}

		// Check not already excluded.
		alreadyExcluded := false
		for _, app := range cfg.Global.DisallowedApps {
			if strings.EqualFold(app, exeName) {
				alreadyExcluded = true
				break
			}
		}

		if !alreadyExcluded {
			cfg.Global.DisallowedApps = append(cfg.Global.DisallowedApps, exeName)
			if err := saveConfigViaIPC(client, cfg); err != nil {
				tests = append(tests, runTestCase(TestResult{
					Name: "exclusion/save-disallowed", Error: err.Error(),
				}))
				return buildSuiteResult("exclusions", tests, start)
			}
		}

		r := TestResult{Name: "exclusion/add-disallowed", Success: true, Details: exeName + " added to disallowed_apps"}
		tests = append(tests, runTestCase(r))
	}

	// Brief wait for config propagation within the service.
	time.Sleep(1 * time.Second)

	// Step 3: Check IP changed (should be direct IP now).
	{
		directIP := doCheckIP()
		directIP.Name = "exclusion/direct-ip"
		tests = append(tests, runTestCase(directIP))

		r := TestResult{Name: "exclusion/ip-changed"}
		if directIP.Success && vpnIP.Success {
			if directIP.Details != vpnIP.Details {
				r.Success = true
				r.Details = fmt.Sprintf("IP changed: %s -> %s", vpnIP.Details, directIP.Details)
			} else {
				r.Error = fmt.Sprintf("IP did not change (still %s) - exclusion may not be working", vpnIP.Details)
			}
		} else {
			r.Error = "could not compare IPs"
		}
		tests = append(tests, runTestCase(r))
	}

	// Step 4: Remove exclusion - restore config.
	{
		cfg, err = loadConfig()
		if err != nil {
			tests = append(tests, runTestCase(TestResult{
				Name: "exclusion/reload-for-restore", Error: err.Error(),
			}))
			return buildSuiteResult("exclusions", tests, start)
		}

		var filtered []string
		for _, app := range cfg.Global.DisallowedApps {
			if !strings.EqualFold(app, exeName) {
				filtered = append(filtered, app)
			}
		}
		cfg.Global.DisallowedApps = filtered
		if err := saveConfigViaIPC(client, cfg); err != nil {
			tests = append(tests, runTestCase(TestResult{
				Name: "exclusion/restore-config", Error: err.Error(),
			}))
			return buildSuiteResult("exclusions", tests, start)
		}

		r := TestResult{Name: "exclusion/remove-disallowed", Success: true, Details: exeName + " removed from disallowed_apps"}
		tests = append(tests, runTestCase(r))
	}

	// Brief wait for config propagation within the service.
	time.Sleep(1 * time.Second)

	// Step 5: Verify IP restored back to VPN.
	{
		restoredIP := doCheckIP()
		restoredIP.Name = "exclusion/restored-ip"
		tests = append(tests, runTestCase(restoredIP))

		r := TestResult{Name: "exclusion/ip-restored"}
		if restoredIP.Success && vpnIP.Success {
			if restoredIP.Details == vpnIP.Details {
				r.Success = true
				r.Details = fmt.Sprintf("IP restored to %s", vpnIP.Details)
			} else {
				r.Error = fmt.Sprintf("IP not restored: expected %s, got %s", vpnIP.Details, restoredIP.Details)
			}
		} else {
			r.Error = "could not compare IPs"
		}
		tests = append(tests, runTestCase(r))
	}

	// Step 6: Test rule add/remove via IPC.
	{
		testPattern := "__test_runner_rule__"
		testTunnel := "__test__"

		cfg, err = loadConfig()
		if err != nil {
			tests = append(tests, runTestCase(TestResult{
				Name: "exclusion/rule-add", Error: err.Error(),
			}))
			return buildSuiteResult("exclusions", tests, start)
		}

		// Add rule via IPC.
		newRules := append(cfg.Rules, core.Rule{
			Pattern:  testPattern,
			TunnelID: testTunnel,
		})
		if err := saveRulesViaIPC(client, newRules); err != nil {
			tests = append(tests, runTestCase(TestResult{
				Name: "exclusion/rule-add", Error: err.Error(),
			}))
			return buildSuiteResult("exclusions", tests, start)
		}

		// Verify rule exists (reload from disk — SaveRules persists).
		cfg, _ = loadConfig()
		found := false
		for _, r := range cfg.Rules {
			if r.Pattern == testPattern && r.TunnelID == testTunnel {
				found = true
				break
			}
		}
		addResult := TestResult{Name: "exclusion/rule-add"}
		if found {
			addResult.Success = true
			addResult.Details = fmt.Sprintf("rule %s -> %s added", testPattern, testTunnel)
		} else {
			addResult.Error = "rule not found after save"
		}
		tests = append(tests, runTestCase(addResult))

		// Remove rule via IPC.
		var filteredRules []core.Rule
		for _, r := range cfg.Rules {
			if r.Pattern != testPattern {
				filteredRules = append(filteredRules, r)
			}
		}
		if err := saveRulesViaIPC(client, filteredRules); err != nil {
			tests = append(tests, runTestCase(TestResult{
				Name: "exclusion/rule-remove", Error: err.Error(),
			}))
			return buildSuiteResult("exclusions", tests, start)
		}

		// Verify rule removed.
		cfg, _ = loadConfig()
		found = false
		for _, r := range cfg.Rules {
			if r.Pattern == testPattern {
				found = true
				break
			}
		}
		removeResult := TestResult{Name: "exclusion/rule-remove"}
		if !found {
			removeResult.Success = true
			removeResult.Details = fmt.Sprintf("rule %s removed", testPattern)
		} else {
			removeResult.Error = "rule still exists after removal"
		}
		tests = append(tests, runTestCase(removeResult))
	}

	return buildSuiteResult("exclusions", tests, start)
}

// ─── IPC helpers for test suites ─────────────────────────────────────

// saveRulesViaIPC sends the given rules to the running service via SaveRules RPC.
// This updates both in-memory RuleEngine and persists to disk.
func saveRulesViaIPC(client *ipc.Client, rules []core.Rule) error {
	protoRules := make([]*vpnapi.Rule, 0, len(rules))
	for _, r := range rules {
		pr := &vpnapi.Rule{
			Pattern:  r.Pattern,
			TunnelId: r.TunnelID,
			Fallback: vpnapi.FallbackPolicy(r.Fallback),
		}
		if r.Priority != 0 {
			pr.Priority = r.Priority.String()
		}
		protoRules = append(protoRules, pr)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	resp, err := client.Service.SaveRules(ctx, &vpnapi.SaveRulesRequest{Rules: protoRules})
	if err != nil {
		return fmt.Errorf("SaveRules RPC: %w", err)
	}
	if !resp.GetSuccess() {
		return fmt.Errorf("SaveRules failed: %s", resp.GetError())
	}
	return nil
}

// saveConfigViaIPC sends the full config to the running service via SaveConfig RPC.
// This updates both in-memory config and persists to disk.
func saveConfigViaIPC(client *ipc.Client, cfg *core.Config) error {
	// Build tunnel configs.
	tunnels := make([]*vpnapi.TunnelConfig, 0, len(cfg.Tunnels))
	for _, t := range cfg.Tunnels {
		settings := make(map[string]string, len(t.Settings))
		for k, v := range t.Settings {
			settings[k] = fmt.Sprintf("%v", v)
		}
		tunnels = append(tunnels, &vpnapi.TunnelConfig{
			Id:             t.ID,
			Protocol:       t.Protocol,
			Name:           t.Name,
			Settings:       settings,
			AllowedIps:     t.AllowedIPs,
			DisallowedIps:  t.DisallowedIPs,
			DisallowedApps: t.DisallowedApps,
		})
	}

	// Build rules.
	rules := make([]*vpnapi.Rule, 0, len(cfg.Rules))
	for _, r := range cfg.Rules {
		pr := &vpnapi.Rule{
			Pattern:  r.Pattern,
			TunnelId: r.TunnelID,
			Fallback: vpnapi.FallbackPolicy(r.Fallback),
		}
		if r.Priority != 0 {
			pr.Priority = r.Priority.String()
		}
		rules = append(rules, pr)
	}

	// Build domain rules.
	domainRules := make([]*vpnapi.DomainRule, 0, len(cfg.DomainRules))
	for _, r := range cfg.DomainRules {
		domainRules = append(domainRules, &vpnapi.DomainRule{
			Pattern:  r.Pattern,
			TunnelId: r.TunnelID,
			Action:   vpnapi.DomainAction(r.Action),
		})
	}

	// Build subscriptions.
	subs := make([]*vpnapi.SubscriptionConfig, 0, len(cfg.Subscriptions))
	for name, sub := range cfg.Subscriptions {
		subs = append(subs, &vpnapi.SubscriptionConfig{
			Name:            name,
			Url:             sub.URL,
			RefreshInterval: sub.RefreshInterval,
			UserAgent:       sub.UserAgent,
			Prefix:          sub.Prefix,
		})
	}

	// Build DNS config.
	dnsEnabled := cfg.DNS.Cache.Enabled == nil || *cfg.DNS.Cache.Enabled
	dnsCfg := &vpnapi.DNSConfig{
		TunnelIds: cfg.DNS.TunnelIDs,
		Servers:  cfg.DNS.Servers,
		Cache: &vpnapi.DNSCacheConfig{
			Enabled: dnsEnabled,
			MaxSize: int32(cfg.DNS.Cache.MaxSize),
			MinTtl:  cfg.DNS.Cache.MinTTL,
			MaxTtl:  cfg.DNS.Cache.MaxTTL,
			NegTtl:  cfg.DNS.Cache.NegTTL,
		},
	}

	appConfig := &vpnapi.AppConfig{
		Global: &vpnapi.GlobalFilterConfig{
			AllowedIps:     cfg.Global.AllowedIPs,
			DisallowedIps:  cfg.Global.DisallowedIPs,
			DisallowedApps: cfg.Global.DisallowedApps,
			DisableLocal:   cfg.Global.DisableLocal,
		},
		Tunnels:       tunnels,
		Rules:         rules,
		DomainRules:   domainRules,
		Subscriptions: subs,
		Dns:           dnsCfg,
		Logging: &vpnapi.LogConfig{
			Level:      cfg.Logging.Level,
			Components: cfg.Logging.Components,
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	resp, err := client.Service.SaveConfig(ctx, &vpnapi.SaveConfigRequest{
		Config:             appConfig,
		RestartIfConnected: false,
	})
	if err != nil {
		return fmt.Errorf("SaveConfig RPC: %w", err)
	}
	if !resp.GetSuccess() {
		return fmt.Errorf("SaveConfig failed: %s", resp.GetError())
	}
	return nil
}
