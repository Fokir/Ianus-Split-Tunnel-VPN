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
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	vpnapi "awg-split-tunnel/api/gen"
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
// With socket activation, the socket always exists (launchd holds it),
// so a connect attempt will spawn the daemon automatically.
// Falls back to manual launch for dev mode.
func connectOrLaunchDaemon() (*ipc.Client, error) {
	ctx := context.Background()

	// First attempt — with socket activation, this triggers launchd to start the daemon.
	client, err := ipc.DialWithTimeout(ctx, 5*time.Second)
	if err == nil {
		status, rpcErr := client.Service.GetStatus(ctx, &emptypb.Empty{})
		if rpcErr == nil {
			// Connected. Check if daemon is idle and needs activation.
			if err := ensureActive(ctx, client, status); err != nil {
				client.Close()
				return nil, fmt.Errorf("activation failed: %w", err)
			}
			return client, nil
		}
		client.Close()
	}

	// Socket activation didn't work (not installed, or dev mode).
	// Fall back to manual launch.
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
		status, rpcErr := client.Service.GetStatus(ctx, &emptypb.Empty{})
		if rpcErr == nil {
			if err := ensureActive(ctx, client, status); err != nil {
				client.Close()
				return nil, fmt.Errorf("activation failed: %w", err)
			}
			return client, nil
		}
		client.Close()
	}

	return nil, fmt.Errorf("VPN daemon did not start within 15 seconds")
}

// ensureActive checks if the daemon is idle and sends Activate if needed.
// Handles both socket-activated (new) and legacy (old) daemons.
func ensureActive(ctx context.Context, client *ipc.Client, status *vpnapi.ServiceStatus) error {
	switch status.DaemonState {
	case vpnapi.DaemonState_DAEMON_STATE_ACTIVE:
		return nil

	case vpnapi.DaemonState_DAEMON_STATE_IDLE:
		// Attempt activation. If the daemon is legacy (doesn't support Activate RPC),
		// we'll get Unimplemented — that's fine, it means VPN is already running.
		log.Printf("[UI] Daemon is idle, sending Activate...")
		resp, err := client.Service.Activate(ctx, &vpnapi.ActivateRequest{})
		if err != nil {
			// Legacy daemon returns Unimplemented — treat as already active.
			if st, ok := grpcstatus.FromError(err); ok && st.Code() == codes.Unimplemented {
				log.Printf("[UI] Daemon does not support Activate (legacy mode), continuing")
				return nil
			}
			return fmt.Errorf("activate RPC: %w", err)
		}
		if !resp.Success {
			return fmt.Errorf("activate failed: %s", resp.Error)
		}
		// Poll until active (up to 30s).
		return waitForState(ctx, client, vpnapi.DaemonState_DAEMON_STATE_ACTIVE, 30*time.Second)

	default:
		// ACTIVATING or DEACTIVATING — wait for it to settle.
		return waitForState(ctx, client, vpnapi.DaemonState_DAEMON_STATE_ACTIVE, 30*time.Second)
	}
}

// waitForState polls GetStatus until the daemon reaches the desired state.
func waitForState(ctx context.Context, client *ipc.Client, want vpnapi.DaemonState, timeout time.Duration) error {
	deadline := time.After(timeout)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-deadline:
			return fmt.Errorf("daemon did not reach state %s within %s", want, timeout)
		case <-ticker.C:
			st, err := client.Service.GetStatus(ctx, &emptypb.Empty{})
			if err != nil {
				continue
			}
			if st.DaemonState == want {
				log.Printf("[UI] Daemon reached state %s", want)
				return nil
			}
			// If it went idle while we wanted active, try to activate again.
			if want == vpnapi.DaemonState_DAEMON_STATE_ACTIVE &&
				st.DaemonState == vpnapi.DaemonState_DAEMON_STATE_IDLE {
				return ensureActive(ctx, client, st)
			}
		}
	}
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
