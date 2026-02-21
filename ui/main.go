//go:build windows

package main

import (
	"context"
	"embed"
	_ "embed"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"
	"golang.org/x/sys/windows"
	"google.golang.org/protobuf/types/known/emptypb"

	"awg-split-tunnel/internal/ipc"
)

//go:embed all:frontend/dist
var assets embed.FS

const serviceBinary = "awg-split-tunnel.exe"

func main() {
	runtime.LockOSThread()

	// Try to connect to the VPN service; if not running, launch it elevated.
	client, err := connectOrLaunchService()
	if err != nil {
		log.Fatalf("Cannot connect to VPN service: %v", err)
	}
	defer client.Close()

	// Create the binding service that exposes gRPC methods to the frontend.
	binding := NewBindingService(client)

	// Create Wails application.
	app := application.New(application.Options{
		Name:        "AWG Split Tunnel",
		Description: "Multi-tunnel VPN client with per-process split tunneling",
		Services: []application.Service{
			application.NewService(binding),
		},
		Assets: application.AssetOptions{
			Handler: application.AssetFileServerFS(assets),
		},
	})

	// Create main window (hidden initially, shown from tray or on start).
	mainWindow := app.Window.NewWithOptions(application.WebviewWindowOptions{
		Title:            "AWG Split Tunnel",
		Width:            900,
		Height:           650,
		URL:              "/",
		Frameless:        true,
		BackgroundColour: application.NewRGB(24, 24, 27), // zinc-900
		Windows: application.WindowsWindow{
			Theme: application.SystemDefault,
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

// connectOrLaunchService tries to connect to the VPN service.
// If the pipe doesn't exist, it launches the service with elevation and retries.
func connectOrLaunchService() (*ipc.Client, error) {
	ctx := context.Background()

	// First attempt — service may already be running.
	client, err := ipc.DialWithTimeout(ctx, 2*time.Second)
	if err == nil {
		if _, rpcErr := client.Service.GetStatus(ctx, &emptypb.Empty{}); rpcErr == nil {
			return client, nil
		}
		client.Close()
	}

	// Service not running — launch it elevated.
	if launchErr := launchServiceElevated(); launchErr != nil {
		return nil, fmt.Errorf("failed to start VPN service: %w", launchErr)
	}

	// Wait for the service to become available.
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

	return nil, fmt.Errorf("VPN service did not start within 15 seconds")
}

// launchServiceElevated starts the VPN service binary with UAC elevation ("Run as administrator").
func launchServiceElevated() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	serviceExe := filepath.Join(filepath.Dir(exe), serviceBinary)

	if _, err := os.Stat(serviceExe); err != nil {
		return fmt.Errorf("%s not found next to UI executable: %w", serviceBinary, err)
	}

	verb, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString(serviceExe)
	cwd, _ := windows.UTF16PtrFromString(filepath.Dir(serviceExe))

	return windows.ShellExecute(0, verb, file, nil, cwd, windows.SW_HIDE)
}
