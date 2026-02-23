//go:build windows

package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
)

var (
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
)

// Global flags.
var (
	configPath string
	jsonOutput bool
	timeout    time.Duration
)

func main() {
	// Parse global flags from os.Args before dispatching.
	args := os.Args[1:]
	args = parseGlobalFlags(args)

	// Initialize logger (writes to stdout + logs/timestamp.log).
	logFile, err := initLogger()
	if err != nil {
		// Fallback: log to stdout only.
		diagLog = log.New(os.Stdout, "", log.LstdFlags)
		fmt.Fprintf(os.Stderr, "Warning: could not init file logger: %v\n", err)
	} else {
		defer logFile.Close()
	}

	if len(args) == 0 {
		printUsage()
		os.Exit(1)
	}

	cmd := args[0]
	cmdArgs := args[1:]

	switch cmd {
	// Network tests.
	case "check-ip":
		outputResult(doCheckIP())
	case "dns":
		if len(cmdArgs) < 1 {
			fatal("usage: awg-diag dns <domain> [--server IP]")
		}
		domain := cmdArgs[0]
		server := ""
		for i, a := range cmdArgs[1:] {
			if a == "--server" && i+2 < len(cmdArgs) {
				server = cmdArgs[i+2]
			}
		}
		outputResult(doDNS(domain, server))
	case "tcp":
		if len(cmdArgs) < 1 {
			fatal("usage: awg-diag tcp <host:port>")
		}
		outputResult(doTCP(cmdArgs[0]))
	case "udp":
		if len(cmdArgs) < 1 {
			fatal("usage: awg-diag udp <host:port> [payload]")
		}
		payload := ""
		if len(cmdArgs) > 1 {
			payload = cmdArgs[1]
		}
		outputResult(doUDP(cmdArgs[0], payload))
	case "http":
		if len(cmdArgs) < 1 {
			fatal("usage: awg-diag http <url>")
		}
		outputResult(doHTTP(cmdArgs[0]))
	case "full":
		runFull()

	// Config management.
	case "config":
		if len(cmdArgs) == 0 {
			fatal("usage: awg-diag config <add-rule|remove-rule|show-rules|list-tunnels>")
		}
		switch cmdArgs[0] {
		case "add-rule":
			runConfigAddRule(cmdArgs[1:])
		case "remove-rule":
			runConfigRemoveRule(cmdArgs[1:])
		case "show-rules":
			runConfigShowRules()
		case "list-tunnels":
			runConfigListTunnels()
		default:
			fatal("unknown config command: %s", cmdArgs[0])
		}

	// Tunnel management.
	case "tunnel":
		if len(cmdArgs) == 0 {
			fatal("usage: awg-diag tunnel <connect|disconnect|list|status> [tunnel_id]")
		}
		switch cmdArgs[0] {
		case "connect":
			tunnelID := ""
			if len(cmdArgs) > 1 {
				tunnelID = cmdArgs[1]
			}
			runTunnelConnect(tunnelID)
		case "disconnect":
			tunnelID := ""
			if len(cmdArgs) > 1 {
				tunnelID = cmdArgs[1]
			}
			runTunnelDisconnect(tunnelID)
		case "list":
			runTunnelList()
		case "status":
			if len(cmdArgs) < 2 {
				fatal("usage: awg-diag tunnel status <tunnel_id>")
			}
			runTunnelStatus(cmdArgs[1])
		default:
			fatal("unknown tunnel command: %s", cmdArgs[0])
		}

	// Service management.
	case "service":
		if len(cmdArgs) == 0 {
			fatal("usage: awg-diag service <start|stop|status>")
		}
		switch cmdArgs[0] {
		case "start":
			runServiceStart()
		case "stop":
			runServiceStop()
		case "status":
			runServiceStatus()
		default:
			fatal("unknown service command: %s", cmdArgs[0])
		}

	// Logs.
	case "logs":
		if len(cmdArgs) == 0 {
			fatal("usage: awg-diag logs <list|tail|clean>")
		}
		switch cmdArgs[0] {
		case "list":
			runLogsList()
		case "tail":
			lines := 50
			for i, a := range cmdArgs[1:] {
				if a == "--lines" && i+2 < len(cmdArgs) {
					fmt.Sscanf(cmdArgs[i+2], "%d", &lines)
				}
			}
			runLogsTail(lines)
		case "clean":
			keep := 5
			for i, a := range cmdArgs[1:] {
				if a == "--keep" && i+2 < len(cmdArgs) {
					fmt.Sscanf(cmdArgs[i+2], "%d", &keep)
				}
			}
			runLogsClean(keep)
		default:
			fatal("unknown logs command: %s", cmdArgs[0])
		}

	// Sandbox.
	case "sandbox":
		if len(cmdArgs) == 0 {
			fatal("usage: awg-diag sandbox <prepare|run|logs>")
		}
		tunnel := ""
		for i, a := range cmdArgs[1:] {
			if a == "--tunnel" && i+2 < len(cmdArgs) {
				tunnel = cmdArgs[i+2]
			}
		}
		switch cmdArgs[0] {
		case "prepare":
			runSandboxPrepare(tunnel)
		case "run":
			runSandboxRun(tunnel)
		case "logs":
			runSandboxLogs()
		default:
			fatal("unknown sandbox command: %s", cmdArgs[0])
		}

	case "version":
		fmt.Printf("awg-diag %s (commit: %s, built: %s)\n", version, commit, buildDate)

	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

// parseGlobalFlags extracts --config, --json, --timeout from args and returns remaining args.
func parseGlobalFlags(args []string) []string {
	var remaining []string
	timeout = 10 * time.Second

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--config":
			if i+1 < len(args) {
				configPath = args[i+1]
				i++
			}
		case "--json":
			jsonOutput = true
		case "--timeout":
			if i+1 < len(args) {
				d, err := time.ParseDuration(args[i+1])
				if err == nil {
					timeout = d
				}
				i++
			}
		default:
			remaining = append(remaining, args[i])
		}
	}

	// Default config path: config.yaml next to exe.
	if configPath == "" {
		configPath = resolveRelativeToExe("config.yaml")
	}

	return remaining
}

// resolveRelativeToExe resolves a filename relative to the executable's directory.
func resolveRelativeToExe(name string) string {
	if filepath.IsAbs(name) {
		return name
	}
	return filepath.Join(exeDirectory(), name)
}

func printUsage() {
	fmt.Println(`awg-diag — AWG Split Tunnel diagnostic tool

Usage: awg-diag [global flags] <command> [args]

Network Tests:
  check-ip                          Show external IP address
  dns <domain> [--server IP]        DNS resolution test
  tcp <host:port>                   TCP connection test
  udp <host:port> [payload]         UDP send/receive test
  http <url>                        HTTP GET test
  full                              Run all network tests

Config Management:
  config add-rule --pattern P --tunnel T [--fallback F] [--priority P]
  config remove-rule --pattern P
  config show-rules
  config list-tunnels

Tunnel Management:
  tunnel connect [tunnel_id]              Connect tunnel (or all if empty)
  tunnel disconnect [tunnel_id]           Disconnect tunnel (or all if empty)
  tunnel list                             List tunnels with live status
  tunnel status <tunnel_id>               Show specific tunnel status

Service Management:
  service start                     Start VPN service
  service stop                      Stop VPN service
  service status                    Show service status

Logs:
  logs list                         List log files
  logs tail [--lines N]             Show last N lines (default: 50)
  logs clean [--keep N]             Remove old logs, keep N newest (default: 5)

Sandbox:
  sandbox prepare [--tunnel T]      Prepare Windows Sandbox files
  sandbox run [--tunnel T]          Prepare and launch sandbox
  sandbox logs                      Show sandbox results

Global Flags:
  --config <path>      Path to config.yaml (default: config.yaml next to exe)
  --json               Output in JSON format
  --timeout <duration> Network test timeout (default: 10s)

Other:
  version              Show version info`)
}

func fatal(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if diagLog != nil {
		diagLog.Printf("FATAL: %s", msg)
	}
	fmt.Fprintf(os.Stderr, "Error: %s\n", msg)
	os.Exit(1)
}
