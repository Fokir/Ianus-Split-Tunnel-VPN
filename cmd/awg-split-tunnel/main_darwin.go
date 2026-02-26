//go:build darwin

package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	platformDarwin "awg-split-tunnel/internal/platform/darwin"
	"awg-split-tunnel/internal/service"
)

// stopCh is used to signal shutdown from OS signals.
var stopCh = make(chan struct{}, 1)

func main() {
	// Handle subcommands before flag parsing.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "install":
			if err := service.InstallDaemon(); err != nil {
				fmt.Fprintf(os.Stderr, "Install failed: %v\n", err)
				os.Exit(1)
			}
			fmt.Println("Daemon installed and started.")
			return
		case "uninstall":
			if err := service.UninstallDaemon(); err != nil {
				fmt.Fprintf(os.Stderr, "Uninstall failed: %v\n", err)
				os.Exit(1)
			}
			fmt.Println("Daemon uninstalled.")
			return
		case "restart":
			if err := service.RestartDaemon(); err != nil {
				fmt.Fprintf(os.Stderr, "Restart failed: %v\n", err)
				os.Exit(1)
			}
			fmt.Println("Daemon restarted.")
			return
		case "status":
			if service.IsDaemonInstalled() {
				fmt.Println("Daemon is installed.")
			} else {
				fmt.Println("Daemon is not installed.")
			}
			return
		case "version":
			fmt.Printf("awg-split-tunnel %s (commit=%s, built=%s)\n", version, commit, buildDate)
			return
		}
	}

	configPath := flag.String("config", "config.yaml", "Path to configuration file")
	showVersion := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("awg-split-tunnel %s (commit=%s, built=%s)\n", version, commit, buildDate)
		os.Exit(0)
	}

	resolvedConfig := resolveRelativeToExe(*configPath)
	plat := platformDarwin.NewPlatform()

	// Console / launchd daemon mode.
	if err := runVPN(resolvedConfig, plat, stopCh); err != nil {
		log.Fatalf("[Core] Fatal: %v", err)
	}
}
