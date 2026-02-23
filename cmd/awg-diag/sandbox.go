//go:build windows

package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"awg-split-tunnel/internal/core"

	"gopkg.in/yaml.v3"
)

// sandboxDirectory returns the path to sandbox/ folder next to exe.
func sandboxDirectory() string {
	return filepath.Join(exeDirectory(), "sandbox")
}

// sandboxSharedDirectory returns the path to sandbox/shared/ folder.
func sandboxSharedDirectory() string {
	return filepath.Join(sandboxDirectory(), "shared")
}

// runSandboxPrepare creates the .wsb file and init script for Windows Sandbox.
func runSandboxPrepare(tunnel string) {
	shared := sandboxSharedDirectory()
	if err := os.MkdirAll(shared, 0o755); err != nil {
		fatal("create sandbox/shared: %v", err)
	}

	buildDir := filepath.Join(exeDirectory(), "..")
	// If exe is inside build/, look for build/ relative to parent.
	// Otherwise, use the exe directory itself as source.
	if _, err := os.Stat(filepath.Join(exeDirectory(), "awg-split-tunnel.exe")); err == nil {
		buildDir = exeDirectory()
	}

	diagLog.Printf("Preparing sandbox in %s", sandboxDirectory())

	// Copy required binaries.
	binaries := []string{"awg-split-tunnel.exe", "awg-diag.exe", "wintun.dll"}
	for _, name := range binaries {
		src := filepath.Join(buildDir, name)
		if _, err := os.Stat(src); os.IsNotExist(err) {
			diagLog.Printf("Warning: %s not found at %s, skipping", name, src)
			continue
		}
		if err := copyFile(src, filepath.Join(shared, name)); err != nil {
			fatal("copy %s: %v", name, err)
		}
		diagLog.Printf("  Copied %s", name)
	}

	// Copy config.yaml.
	cfgSrc := configPath
	cfgDst := filepath.Join(shared, "config.yaml")
	if err := copyFile(cfgSrc, cfgDst); err != nil {
		fatal("copy config: %v", err)
	}
	diagLog.Printf("  Copied config.yaml")

	// Copy all .conf files and conf/ subdirectory from the config directory.
	cfgDir := filepath.Dir(cfgSrc)
	entries, _ := os.ReadDir(cfgDir)
	for _, e := range entries {
		srcPath := filepath.Join(cfgDir, e.Name())
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".conf") {
			dst := filepath.Join(shared, e.Name())
			if err := copyFile(srcPath, dst); err != nil {
				diagLog.Printf("Warning: could not copy %s: %v", e.Name(), err)
				continue
			}
			diagLog.Printf("  Copied %s", e.Name())
		}
		// Recursively copy conf/ directory (contains VPN tunnel configs).
		if e.IsDir() && e.Name() == "conf" {
			if err := copyDir(srcPath, filepath.Join(shared, "conf")); err != nil {
				diagLog.Printf("Warning: could not copy conf/ directory: %v", err)
			} else {
				diagLog.Printf("  Copied conf/ directory")
			}
		}
	}

	// If --tunnel specified, add awg-diag.exe rule to the sandbox config copy.
	if tunnel != "" {
		if err := addDiagRuleToConfig(cfgDst, tunnel); err != nil {
			fatal("add diag rule: %v", err)
		}
		diagLog.Printf("  Added rule: awg-diag.exe -> %s", tunnel)
	}

	// Generate sandbox-init.bat.
	initBat := filepath.Join(shared, "sandbox-init.bat")
	batContent := fmt.Sprintf(`@echo off
cd /d C:\Users\WDAGUtilityAccount\Desktop\shared

REM Install and start VPN service
awg-split-tunnel.exe install -config config.yaml
awg-split-tunnel.exe start
timeout /t 10 /nobreak

REM Run full diagnostic suite
awg-diag.exe full --json --config config.yaml > results.json 2>&1
awg-diag.exe check-ip >> results.json 2>&1

REM Copy service logs if exist
copy logs\*.log . 2>nul

REM Signal completion
echo DONE > completed.flag
`)
	if err := os.WriteFile(initBat, []byte(batContent), 0o644); err != nil {
		fatal("write sandbox-init.bat: %v", err)
	}
	diagLog.Printf("  Generated sandbox-init.bat")

	// Generate test.wsb.
	absShared, _ := filepath.Abs(shared)
	wsbContent := fmt.Sprintf(`<Configuration>
  <Networking>Default</Networking>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>%s</HostFolder>
      <SandboxFolder>C:\Users\WDAGUtilityAccount\Desktop\shared</SandboxFolder>
      <ReadOnly>false</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>C:\Users\WDAGUtilityAccount\Desktop\shared\sandbox-init.bat</Command>
  </LogonCommand>
</Configuration>
`, absShared)

	wsbPath := filepath.Join(sandboxDirectory(), "test.wsb")
	if err := os.WriteFile(wsbPath, []byte(wsbContent), 0o644); err != nil {
		fatal("write test.wsb: %v", err)
	}
	diagLog.Printf("  Generated test.wsb")
	diagLog.Printf("Sandbox prepared. Launch with: start %s", wsbPath)
}

// checkSandboxPrereqs validates that Windows Sandbox can run on this machine.
func checkSandboxPrereqs() {
	// Check WindowsSandbox.exe exists.
	if _, err := exec.LookPath("WindowsSandbox.exe"); err != nil {
		// Try absolute path.
		if _, err := os.Stat(`C:\Windows\System32\WindowsSandbox.exe`); err != nil {
			fatal("Windows Sandbox is not installed. Enable it via: Settings > Apps > Optional Features > Windows Sandbox")
		}
	}

	// Check hardware virtualization via PowerShell (best-effort).
	out, err := exec.Command(
		`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		"-Command", "(Get-CimInstance Win32_Processor).VirtualizationFirmwareEnabled",
	).Output()
	if err == nil {
		result := strings.TrimSpace(string(out))
		if strings.EqualFold(result, "false") {
			fatal("Hardware virtualization (VT-x/AMD-V) is disabled in BIOS/UEFI. Windows Sandbox requires it to be enabled.")
		}
	}
}

// runSandboxRun prepares and launches Windows Sandbox, then polls for completion.
func runSandboxRun(tunnel string) {
	checkSandboxPrereqs()
	runSandboxPrepare(tunnel)

	wsbPath := filepath.Join(sandboxDirectory(), "test.wsb")
	diagLog.Printf("Launching Windows Sandbox...")

	// Use PowerShell Invoke-Item for reliable .wsb file association launch.
	cmd := exec.Command(
		`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		"-Command", fmt.Sprintf("Invoke-Item '%s'", wsbPath),
	)
	if err := cmd.Run(); err != nil {
		fatal("launch sandbox: %v", err)
	}

	// Poll for completed.flag.
	flagPath := filepath.Join(sandboxSharedDirectory(), "completed.flag")
	diagLog.Printf("Waiting for sandbox to complete (polling %s)...", flagPath)

	pollInterval := 5 * time.Second
	pollTimeout := 120 * time.Second
	deadline := time.Now().Add(pollTimeout)

	for time.Now().Before(deadline) {
		time.Sleep(pollInterval)
		if _, err := os.Stat(flagPath); err == nil {
			diagLog.Printf("Sandbox completed!")
			runSandboxLogs()
			return
		}
	}

	diagLog.Printf("Timeout waiting for sandbox completion (%v).", pollTimeout)
	diagLog.Printf("You can check results manually: awg-diag sandbox logs")
}

// runSandboxLogs reads and displays results from the sandbox run.
func runSandboxLogs() {
	shared := sandboxSharedDirectory()

	// Read results.json.
	resultsPath := filepath.Join(shared, "results.json")
	data, err := os.ReadFile(resultsPath)
	if err != nil {
		if os.IsNotExist(err) {
			diagLog.Printf("No results.json found. Sandbox may not have completed.")
		} else {
			fatal("read results: %v", err)
		}
	} else {
		diagLog.Printf("=== Sandbox Results ===")
		fmt.Println(string(data))
	}

	// List any .log files in shared/.
	entries, _ := os.ReadDir(shared)
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".log") {
			diagLog.Printf("=== Log: %s ===", e.Name())
			logData, err := os.ReadFile(filepath.Join(shared, e.Name()))
			if err == nil {
				fmt.Println(string(logData))
			}
		}
	}
}

// addDiagRuleToConfig adds an awg-diag.exe routing rule to the sandbox config copy.
func addDiagRuleToConfig(cfgPath, tunnel string) error {
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		return err
	}
	var cfg core.Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return err
	}

	// Check if rule already exists.
	for _, r := range cfg.Rules {
		if strings.EqualFold(r.Pattern, "awg-diag.exe") {
			r.TunnelID = tunnel
			break
		}
	}

	cfg.Rules = append(cfg.Rules, core.Rule{
		Pattern:  "awg-diag.exe",
		TunnelID: tunnel,
	})

	out, err := yaml.Marshal(&cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(cfgPath, out, 0o644)
}

// copyDir recursively copies a directory from src to dst.
func copyDir(src, dst string) error {
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return err
	}
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	for _, e := range entries {
		srcPath := filepath.Join(src, e.Name())
		dstPath := filepath.Join(dst, e.Name())
		if e.IsDir() {
			if err := copyDir(srcPath, dstPath); err != nil {
				return err
			}
		} else {
			if err := copyFile(srcPath, dstPath); err != nil {
				return err
			}
		}
	}
	return nil
}

// copyFile copies a file from src to dst.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}
