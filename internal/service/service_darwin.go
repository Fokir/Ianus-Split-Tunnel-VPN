//go:build darwin

package service

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"text/template"
)

const (
	daemonLabel    = "com.awg.split-tunnel"
	daemonPlistDir = "/Library/LaunchDaemons"
	daemonPlist    = daemonPlistDir + "/" + daemonLabel + ".plist"
	daemonBinary   = "/usr/local/bin/awg-split-tunnel"
	configDir      = "/etc/awg-split-tunnel"
	configFile     = configDir + "/config.yaml"
	logFile        = "/var/log/awg-split-tunnel.log"
)

var daemonPlistTmpl = template.Must(template.New("plist").Parse(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>{{.Label}}</string>
	<key>ProgramArguments</key>
	<array>
		<string>{{.Binary}}</string>
		<string>-config</string>
		<string>{{.Config}}</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<dict>
		<key>SuccessfulExit</key>
		<false/>
	</dict>
	<key>StandardOutPath</key>
	<string>{{.Log}}</string>
	<key>StandardErrorPath</key>
	<string>{{.Log}}</string>
</dict>
</plist>
`))

type daemonPlistData struct {
	Label  string
	Binary string
	Config string
	Log    string
}

// InstallDaemon copies the running binary to /usr/local/bin/,
// writes the LaunchDaemon plist, and bootstraps the daemon.
func InstallDaemon() error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("get executable path: %w", err)
	}

	// Ensure config directory exists.
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	// Copy binary to install location.
	input, err := os.ReadFile(exe)
	if err != nil {
		return fmt.Errorf("read binary: %w", err)
	}
	if err := os.WriteFile(daemonBinary, input, 0755); err != nil {
		return fmt.Errorf("install binary: %w", err)
	}

	// Write plist.
	f, err := os.Create(daemonPlist)
	if err != nil {
		return fmt.Errorf("create plist: %w", err)
	}
	defer f.Close()

	data := daemonPlistData{
		Label:  daemonLabel,
		Binary: daemonBinary,
		Config: configFile,
		Log:    logFile,
	}
	if err := daemonPlistTmpl.Execute(f, data); err != nil {
		return fmt.Errorf("write plist: %w", err)
	}

	// Bootstrap the daemon (macOS 10.10+).
	out, err := exec.Command("launchctl", "bootstrap", "system", daemonPlist).CombinedOutput()
	if err != nil {
		// May fail if already bootstrapped — try kickstart instead.
		if strings.Contains(string(out), "already bootstrapped") || strings.Contains(string(out), "service already loaded") {
			return RestartDaemon()
		}
		return fmt.Errorf("launchctl bootstrap: %s: %w", strings.TrimSpace(string(out)), err)
	}

	return nil
}

// UninstallDaemon stops the daemon, removes the plist and binary.
func UninstallDaemon() error {
	// Bootout (stops and unloads the daemon).
	out, err := exec.Command("launchctl", "bootout", "system/"+daemonLabel).CombinedOutput()
	if err != nil {
		outStr := strings.TrimSpace(string(out))
		// Ignore "not found" errors.
		if !strings.Contains(outStr, "Could not find") && !strings.Contains(outStr, "No such process") {
			return fmt.Errorf("launchctl bootout: %s: %w", outStr, err)
		}
	}

	os.Remove(daemonPlist)
	os.Remove(daemonBinary)

	return nil
}

// IsDaemonInstalled checks if the LaunchDaemon plist exists.
func IsDaemonInstalled() bool {
	_, err := os.Stat(daemonPlist)
	return err == nil
}

// RestartDaemon restarts the running daemon via launchctl kickstart.
func RestartDaemon() error {
	out, err := exec.Command("launchctl", "kickstart", "-k", "system/"+daemonLabel).CombinedOutput()
	if err != nil {
		return fmt.Errorf("launchctl kickstart: %s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}
