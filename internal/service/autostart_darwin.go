//go:build darwin

package service

import (
	"fmt"
	"os"
	"path/filepath"
	"text/template"
)

const (
	guiAgentLabel = "com.awg.split-tunnel.gui"
	guiAppPath    = "/Applications/AWG Split Tunnel.app/Contents/MacOS/awg-split-tunnel-gui"
)

var guiAgentPlistTmpl = template.Must(template.New("agent").Parse(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>{{.Label}}</string>
	<key>ProgramArguments</key>
	<array>
		<string>{{.Binary}}</string>
		<string>--minimized</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>LimitLoadToSessionType</key>
	<string>Aqua</string>
</dict>
</plist>
`))

type agentPlistData struct {
	Label  string
	Binary string
}

// agentPlistPath returns the path to the GUI LaunchAgent plist for the current user.
func agentPlistPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Library", "LaunchAgents", guiAgentLabel+".plist")
}

// isAutostartEnabled checks if the GUI LaunchAgent plist exists.
func isAutostartEnabled() (bool, error) {
	// On macOS, also check if the daemon service is installed.
	if IsDaemonInstalled() {
		return true, nil
	}
	_, err := os.Stat(agentPlistPath())
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// setAutostartEnabled creates or removes the GUI LaunchAgent plist.
func setAutostartEnabled(enabled bool, guiExePath string) error {
	plistPath := agentPlistPath()

	if !enabled {
		err := os.Remove(plistPath)
		if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove agent plist: %w", err)
		}
		return nil
	}

	// Ensure LaunchAgents directory exists.
	dir := filepath.Dir(plistPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create LaunchAgents dir: %w", err)
	}

	binary := guiAppPath
	if guiExePath != "" {
		binary = guiExePath
	}

	f, err := os.Create(plistPath)
	if err != nil {
		return fmt.Errorf("create agent plist: %w", err)
	}
	defer f.Close()

	data := agentPlistData{
		Label:  guiAgentLabel,
		Binary: binary,
	}
	if err := guiAgentPlistTmpl.Execute(f, data); err != nil {
		return fmt.Errorf("write agent plist: %w", err)
	}

	return nil
}
