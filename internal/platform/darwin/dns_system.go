//go:build darwin

package darwin

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"awg-split-tunnel/internal/core"
)

const (
	// dnsBackupDir holds state across crashes so the daemon can restore
	// the user's original DNS configuration on next startup.
	dnsBackupDir  = "/var/db/awg-split-tunnel"
	dnsBackupFile = "dns-backup.json"

	// Sentinel used by networksetup to clear DNS servers for a service.
	networksetupEmpty = "Empty"
)

// dnsBackup persists per-service DNS state so it survives a daemon crash.
type dnsBackup struct {
	Services map[string][]string `json:"services"`
}

var dnsSystemMu sync.Mutex

// applySystemDNS backs up current DNS servers for every enabled network
// service, then forces them to use only `dnsIP` so DNS queries hit our
// resolver on 10.255.0.1:53. The backup is written to disk BEFORE we
// change anything, so a crash between backup and ClearDNS is recoverable.
func applySystemDNS(dnsIP string) error {
	dnsSystemMu.Lock()
	defer dnsSystemMu.Unlock()

	services, err := listNetworkServices()
	if err != nil {
		return fmt.Errorf("list network services: %w", err)
	}

	// A backup already on disk means SetDNS ran earlier without a matching
	// ClearDNS. Overwriting it would capture our own 10.255.0.1 as the
	// "original" and break the user's DNS forever after next ClearDNS.
	// Skip the capture step and just re-assert the override.
	haveBackup := false
	if _, err := os.Stat(filepath.Join(dnsBackupDir, dnsBackupFile)); err == nil {
		haveBackup = true
	}

	if !haveBackup {
		backup := &dnsBackup{Services: make(map[string][]string, len(services))}
		for _, svc := range services {
			current, err := getDNSServers(svc)
			if err != nil {
				core.Log.Warnf("DNS", "Read current DNS for %q: %v", svc, err)
				continue
			}
			// Defensive: filter our own IP so we never persist it as the
			// user's original — e.g. if a prior recovery run failed partway.
			current = filterOut(current, dnsIP)
			backup.Services[svc] = current
		}
		if err := writeDNSBackup(backup); err != nil {
			return fmt.Errorf("write DNS backup: %w", err)
		}
		for svc, prev := range backup.Services {
			if len(prev) == 0 {
				core.Log.Infof("DNS", "Backed up %q (previously empty)", svc)
			} else {
				core.Log.Infof("DNS", "Backed up %q: %s", svc, strings.Join(prev, ", "))
			}
		}
	}

	for _, svc := range services {
		if err := setDNSServers(svc, []string{dnsIP}); err != nil {
			core.Log.Warnf("DNS", "Set DNS for %q: %v", svc, err)
			continue
		}
		core.Log.Infof("DNS", "System DNS for %q set to %s", svc, dnsIP)
	}

	_ = flushSystemDNS()
	return nil
}

func filterOut(servers []string, skip string) []string {
	out := servers[:0]
	for _, s := range servers {
		if s != skip {
			out = append(out, s)
		}
	}
	return out
}

// restoreSystemDNS reads the on-disk backup and reapplies the previously
// saved DNS servers for each network service, then removes the backup.
func restoreSystemDNS() error {
	dnsSystemMu.Lock()
	defer dnsSystemMu.Unlock()

	backup, err := readDNSBackup()
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read DNS backup: %w", err)
	}

	for svc, servers := range backup.Services {
		if err := setDNSServers(svc, servers); err != nil {
			core.Log.Warnf("DNS", "Restore DNS for %q: %v", svc, err)
			continue
		}
		if len(servers) == 0 {
			core.Log.Infof("DNS", "Restored DNS for %q (cleared)", svc)
		} else {
			core.Log.Infof("DNS", "Restored DNS for %q: %s", svc, strings.Join(servers, ", "))
		}
	}

	_ = os.Remove(filepath.Join(dnsBackupDir, dnsBackupFile))
	_ = flushSystemDNS()
	return nil
}

// recoverStaleDNSBackup is called on daemon startup. If a backup file exists,
// it means the previous daemon process crashed without running ClearDNS —
// restore the user's DNS immediately so the system is in a clean state
// before we install our own DNS override again.
func recoverStaleDNSBackup() error {
	path := filepath.Join(dnsBackupDir, dnsBackupFile)
	if _, err := os.Stat(path); err != nil {
		return nil
	}
	core.Log.Warnf("DNS", "Stale DNS backup found at %s — recovering", path)
	return restoreSystemDNS()
}

func listNetworkServices() ([]string, error) {
	out, err := exec.Command("networksetup", "-listallnetworkservices").Output()
	if err != nil {
		return nil, err
	}
	var services []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// First line is an informational banner. Disabled services are
		// prefixed with "*"; skip those as networksetup refuses to modify them.
		if strings.HasPrefix(line, "An asterisk") || strings.HasPrefix(line, "*") {
			continue
		}
		services = append(services, line)
	}
	return services, nil
}

func getDNSServers(service string) ([]string, error) {
	out, err := exec.Command("networksetup", "-getdnsservers", service).Output()
	if err != nil {
		return nil, err
	}
	text := strings.TrimSpace(string(out))
	// When no DNS is configured, networksetup prints a sentence starting with
	// "There aren't any DNS Servers...". Treat that as an empty list.
	if strings.HasPrefix(text, "There aren't") {
		return nil, nil
	}
	var servers []string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			servers = append(servers, line)
		}
	}
	return servers, nil
}

func setDNSServers(service string, servers []string) error {
	args := []string{"-setdnsservers", service}
	if len(servers) == 0 {
		args = append(args, networksetupEmpty)
	} else {
		args = append(args, servers...)
	}
	out, err := exec.Command("networksetup", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

func writeDNSBackup(b *dnsBackup) error {
	if err := os.MkdirAll(dnsBackupDir, 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(dnsBackupDir, dnsBackupFile)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func readDNSBackup() (*dnsBackup, error) {
	path := filepath.Join(dnsBackupDir, dnsBackupFile)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var b dnsBackup
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, err
	}
	if b.Services == nil {
		b.Services = make(map[string][]string)
	}
	return &b, nil
}
