//go:build windows

package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	platformWindows "awg-split-tunnel/internal/platform/windows"
	"awg-split-tunnel/internal/winsvc"
)

// stopCh is used to signal shutdown from SCM or OS signals.
var stopCh = make(chan struct{}, 1)

func main() {
	// Handle subcommands first (install, uninstall, start, stop).
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "install":
			handleInstall()
			return
		case "uninstall":
			handleUninstall()
			return
		case "start":
			handleStart()
			return
		case "stop":
			handleStop()
			return
		}
	}

	configPath := flag.String("config", "config.yaml", "Path to configuration file")
	showVersion := flag.Bool("version", false, "Print version and exit")
	serviceMode := flag.Bool("service", false, "Run as Windows Service (used by SCM)")
	flag.Parse()

	if *showVersion {
		fmt.Printf("awg-split-tunnel %s (commit=%s, built=%s)\n", version, commit, buildDate)
		os.Exit(0)
	}

	resolvedConfig := resolveRelativeToExe(*configPath)
	plat := platformWindows.NewPlatform()

	// Determine if running as a Windows Service.
	if *serviceMode || winsvc.IsWindowsService() {
		runFunc := func() error {
			return runVPN(resolvedConfig, plat, stopCh)
		}
		stopFunc := func() {
			close(stopCh)
		}
		if err := winsvc.RunService(runFunc, stopFunc); err != nil {
			log.Fatalf("[Core] Service failed: %v", err)
		}
		return
	}

	// Console mode (development / direct launch).
	if err := runVPN(resolvedConfig, plat, stopCh); err != nil {
		log.Fatalf("[Core] Fatal: %v", err)
	}
}

// handleInstall registers the service with the Windows SCM.
func handleInstall() {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	configPath := fs.String("config", "", "Path to configuration file (optional)")
	fs.Parse(os.Args[2:])

	exePath, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: cannot determine executable path: %v\n", err)
		os.Exit(1)
	}

	if err := winsvc.InstallService(exePath, *configPath); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Service installed successfully.")
}

// handleUninstall removes the service from the Windows SCM.
func handleUninstall() {
	if err := winsvc.UninstallService(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Service uninstalled successfully.")
}

// handleStart starts the service via SCM.
func handleStart() {
	if err := winsvc.StartService(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Service started successfully.")
}

// handleStop stops the service via SCM.
func handleStop() {
	if err := winsvc.StopService(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Service stopped successfully.")
}
