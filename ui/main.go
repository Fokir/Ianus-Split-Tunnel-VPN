//go:build windows

package main

import (
	"context"
	"embed"
	_ "embed"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"
	"golang.org/x/sys/windows"
	"google.golang.org/protobuf/types/known/emptypb"

	"awg-split-tunnel/internal/ipc"
	"awg-split-tunnel/internal/winsvc"
)

//go:embed all:frontend/dist
var assets embed.FS

const serviceBinary = "awg-split-tunnel.exe"

// Package-level state for window lifecycle (destroy/recreate pattern).
// SystemTray keeps the app alive; the window is destroyed on close to free
// WebView2 memory (~100-200 MB) and recreated on demand from tray.
var (
	mainWindow   *application.WebviewWindow
	mainWindowMu sync.Mutex
	mainApp      *application.App
	mainBinding  *BindingService
)

func main() {
	runtime.LockOSThread()

	minimized := flag.Bool("minimized", false, "Start minimized to system tray")
	flag.Parse()

	// Single-instance guard: only one UI process is allowed.
	if !acquireSingleInstance() {
		// Another instance is running — signal it to show its window and exit.
		notifyExistingInstance()
		return
	}

	// Try to connect to the VPN service; if not running, launch it elevated.
	client, err := connectOrLaunchService()
	if err != nil {
		log.Fatalf("Cannot connect to VPN service: %v", err)
	}
	defer client.Close()

	// Create the binding service that exposes gRPC methods to the frontend.
	mainBinding = NewBindingService(client)

	// Restore previously active tunnel connections (if enabled in settings).
	if err := mainBinding.RestoreConnections(); err != nil {
		log.Printf("[UI] RestoreConnections: %v", err)
	}

	// Create Wails application.
	mainApp = application.New(application.Options{
		Name:        "AWG Split Tunnel",
		Description: "Multi-tunnel VPN client with per-process split tunneling",
		Icon:        trayIconPNG,
		Services: []application.Service{
			application.NewService(mainBinding),
		},
		Assets: application.AssetOptions{
			Handler: application.AssetFileServerFS(assets),
		},
		Windows: application.WindowsOptions{
			DisableQuitOnLastWindowClosed: true,
		},
	})

	// Create initial window unless started minimized (e.g. after update).
	if !*minimized {
		mainWindow = createMainWindow()
	}

	// Listen for "show UI" messages from duplicate instances.
	registerWindowMessageHook(func() {
		showMainWindow("")
	})

	// Setup system tray (uses showMainWindow to create/show window on demand).
	setupTray(mainApp, mainBinding)

	// Run the application.
	if err := mainApp.Run(); err != nil {
		log.Fatal(err)
	}
}

// createMainWindow creates a WebView2 window with destroy-on-close hook.
// When closed, the window and its WebView2 processes are destroyed to free
// ~100-200 MB of memory. A fresh window is recreated on next tray click.
func createMainWindow() *application.WebviewWindow {
	w := mainApp.Window.NewWithOptions(application.WebviewWindowOptions{
		Title:            "AWG Split Tunnel",
		Width:            1000,
		Height:           700,
		MinWidth:         960,
		MinHeight:        500,
		URL:              "/",
		Frameless:        true,
		BackgroundColour: application.NewRGB(24, 24, 27), // zinc-900
		Windows: application.WindowsWindow{
			Theme: application.SystemDefault,
		},
	})

	// Let the window close naturally — Wails destroys the WebView2 runtime,
	// freeing browser/renderer/GPU processes (~100-200 MB).
	w.RegisterHook(events.Common.WindowClosing, func(e *application.WindowEvent) {
		mainWindowMu.Lock()
		mainWindow = nil
		mainWindowMu.Unlock()
		mainBinding.OnWindowHidden()
	})

	return w
}

// showMainWindow shows the existing window or creates a new one.
// Optional navigateTo path triggers a frontend route change.
func showMainWindow(navigateTo string) {
	mainWindowMu.Lock()
	defer mainWindowMu.Unlock()

	if mainWindow != nil {
		mainBinding.OnWindowShown()
		mainWindow.Show()
		mainWindow.Focus()
		if navigateTo != "" {
			mainApp.Event.Emit("navigate", navigateTo)
		}
		return
	}

	mainBinding.OnWindowShown()
	mainWindow = createMainWindow()
	mainWindow.Show()
	mainWindow.Focus()
	if navigateTo != "" {
		mainApp.Event.Emit("navigate", navigateTo)
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

// launchServiceElevated starts the VPN service.
// If the service is registered in the SCM, it starts via SCM (no UAC prompt).
// Otherwise, falls back to ShellExecute with elevation (dev mode).
func launchServiceElevated() error {
	// Prefer SCM start if the service is installed.
	if winsvc.IsServiceInstalled() {
		return winsvc.StartService()
	}

	// Fallback: launch as elevated process (development mode).
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
