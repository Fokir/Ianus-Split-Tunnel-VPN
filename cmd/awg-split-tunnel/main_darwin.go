//go:build darwin

package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	platformDarwin "awg-split-tunnel/internal/platform/darwin"
)

// stopCh is used to signal shutdown from OS signals.
var stopCh = make(chan struct{}, 1)

func main() {
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
