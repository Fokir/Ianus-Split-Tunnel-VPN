//go:build darwin

package main

import (
	"context"
	"embed"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"
	"google.golang.org/protobuf/types/known/emptypb"

	"awg-split-tunnel/internal/ipc"
)

//go:embed all:frontend/dist
var assets embed.FS

const serviceBinary = "awg-split-tunnel"

func main() {
	runtime.LockOSThread()

	// Try to connect to the VPN daemon; if not running, launch it.
	client, err := connectOrLaunchDaemon()
	if err != nil {
		log.Fatalf("Cannot connect to VPN daemon: %v", err)
	}
	defer client.Close()

	// Create the binding service that exposes gRPC methods to the frontend.
	binding := NewBindingService(client)

	// Restore previously active tunnel connections (if enabled in settings).
	if err := binding.RestoreConnections(); err != nil {
		log.Printf("[UI] RestoreConnections: %v", err)
	}

	// Create Wails application.
	app := application.New(application.Options{
		Name:        "AWG Split Tunnel",
		Description: "Multi-tunnel VPN client with per-process split tunneling",
		Icon:        trayIconPNG,
		Services: []application.Service{
			application.NewService(binding),
		},
		Assets: application.AssetOptions{
			Handler: application.AssetFileServerFS(assets),
		},
		Mac: application.MacOptions{
			ActivationPolicy: application.ActivationPolicyAccessory,
		},
	})

	// Create main window.
	mainWindow := app.Window.NewWithOptions(application.WebviewWindowOptions{
		Title:            "AWG Split Tunnel",
		Width:            950,
		Height:           700,
		MinWidth:         900,
		MinHeight:        500,
		URL:              "/",
		Frameless:        true,
		BackgroundColour: application.NewRGB(24, 24, 27), // zinc-900
		Mac: application.MacWindow{
			Backdrop:                application.MacBackdropTranslucent,
			TitleBar:                application.MacTitleBarHiddenInsetUnified,
			InvisibleTitleBarHeight: 50,
		},
	})

	// Hide window instead of closing when the user clicks the X button.
	mainWindow.RegisterHook(events.Common.WindowClosing, func(e *application.WindowEvent) {
		mainWindow.Hide()
		e.Cancel()
	})

	// Setup system tray.
	setupTray(app, mainWindow, binding)

	// Run the application.
	if err := app.Run(); err != nil {
		log.Fatal(err)
	}
}

// connectOrLaunchDaemon tries to connect to the VPN daemon.
// If the socket doesn't exist, it launches the daemon and retries.
func connectOrLaunchDaemon() (*ipc.Client, error) {
	ctx := context.Background()

	// First attempt — daemon may already be running.
	client, err := ipc.DialWithTimeout(ctx, 2*time.Second)
	if err == nil {
		if _, rpcErr := client.Service.GetStatus(ctx, &emptypb.Empty{}); rpcErr == nil {
			return client, nil
		}
		client.Close()
	}

	// Daemon not running — try to launch it.
	if launchErr := launchDaemon(); launchErr != nil {
		return nil, fmt.Errorf("failed to start VPN daemon: %w", launchErr)
	}

	// Wait for the daemon to become available.
	for i := 0; i < 30; i++ {
		time.Sleep(500 * time.Millisecond)
		client, err = ipc.DialWithTimeout(ctx, 2*time.Second)
		if err != nil {
			continue
		}
		if _, rpcErr := client.Service.GetStatus(ctx, &emptypb.Empty{}); rpcErr == nil {
			return client, nil
		}
		client.Close()
	}

	return nil, fmt.Errorf("VPN daemon did not start within 15 seconds")
}

// launchDaemon starts the VPN daemon.
// Prefers launchctl kickstart if the daemon is installed as a LaunchDaemon.
// Falls back to osascript with admin privileges for development mode.
func launchDaemon() error {
	// Option 1: launchctl kickstart (if daemon installed via install-daemon.sh).
	cmd := exec.Command("launchctl", "kickstart", "-k", "system/com.awg.split-tunnel")
	if err := cmd.Run(); err == nil {
		return nil
	}

	// Option 2: osascript with admin password prompt (dev mode).
	exe, _ := os.Executable()
	daemonPath := filepath.Join(filepath.Dir(exe), serviceBinary)
	if _, err := os.Stat(daemonPath); err != nil {
		daemonPath = "/usr/local/bin/" + serviceBinary
	}

	script := fmt.Sprintf(
		`do shell script "%s -config /etc/awg-split-tunnel/config.yaml &" with administrator privileges`,
		daemonPath,
	)
	return exec.Command("osascript", "-e", script).Run()
}
