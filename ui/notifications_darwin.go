//go:build darwin

package main

import (
	"log"
	"os/exec"
	"sync"
	"time"
)

// NotificationManager sends macOS notifications via osascript with throttling.
type NotificationManager struct {
	mu        sync.Mutex
	enabled   bool
	tunnelErr bool // notify on tunnel errors
	updates   bool // notify on available updates
	lastNotif map[string]time.Time
	throttle  time.Duration
	appName   string
}

// NewNotificationManager creates a notification manager with default settings.
func NewNotificationManager() *NotificationManager {
	return &NotificationManager{
		enabled:   true,
		tunnelErr: true,
		updates:   true,
		lastNotif: make(map[string]time.Time),
		throttle:  30 * time.Second,
		appName:   "AWG Split Tunnel",
	}
}

// SetPreferences updates notification preferences.
func (nm *NotificationManager) SetPreferences(enabled, tunnelErr, updates bool) {
	nm.mu.Lock()
	defer nm.mu.Unlock()
	nm.enabled = enabled
	nm.tunnelErr = tunnelErr
	nm.updates = updates
}

// NotifyTunnelError sends a notification about a tunnel connection error.
func (nm *NotificationManager) NotifyTunnelError(tunnelID, message string) {
	nm.mu.Lock()
	if !nm.enabled || !nm.tunnelErr {
		nm.mu.Unlock()
		return
	}
	key := "tunnel_error:" + tunnelID
	if time.Since(nm.lastNotif[key]) < nm.throttle {
		nm.mu.Unlock()
		return
	}
	nm.lastNotif[key] = time.Now()
	nm.mu.Unlock()

	go nm.send("Ошибка подключения", tunnelID+": "+message)
}

// NotifyTunnelDisconnected sends a notification about unexpected tunnel disconnection.
func (nm *NotificationManager) NotifyTunnelDisconnected(tunnelID string) {
	nm.mu.Lock()
	if !nm.enabled || !nm.tunnelErr {
		nm.mu.Unlock()
		return
	}
	key := "tunnel_disconnect:" + tunnelID
	if time.Since(nm.lastNotif[key]) < nm.throttle {
		nm.mu.Unlock()
		return
	}
	nm.lastNotif[key] = time.Now()
	nm.mu.Unlock()

	go nm.send("Соединение потеряно", "Туннель "+tunnelID+" отключён")
}

// NotifyReconnected sends a notification when a tunnel is reconnected after failure.
func (nm *NotificationManager) NotifyReconnected(tunnelID string) {
	nm.mu.Lock()
	if !nm.enabled || !nm.tunnelErr {
		nm.mu.Unlock()
		return
	}
	key := "tunnel_reconnect:" + tunnelID
	if time.Since(nm.lastNotif[key]) < nm.throttle {
		nm.mu.Unlock()
		return
	}
	nm.lastNotif[key] = time.Now()
	nm.mu.Unlock()

	go nm.send("Переподключено", "Туннель "+tunnelID+" восстановлен")
}

// NotifyUpdateAvailable sends a notification about a new version.
func (nm *NotificationManager) NotifyUpdateAvailable(version string) {
	nm.mu.Lock()
	if !nm.enabled || !nm.updates {
		nm.mu.Unlock()
		return
	}
	key := "update:" + version
	if time.Since(nm.lastNotif[key]) < nm.throttle {
		nm.mu.Unlock()
		return
	}
	nm.lastNotif[key] = time.Now()
	nm.mu.Unlock()

	go nm.send("Доступно обновление", "Версия "+version+" готова к установке")
}

func (nm *NotificationManager) send(title, message string) {
	script := `display notification "` + escapeAppleScript(message) +
		`" with title "` + escapeAppleScript(title) +
		`" subtitle "` + escapeAppleScript(nm.appName) + `"`
	if err := exec.Command("osascript", "-e", script).Run(); err != nil {
		log.Printf("[UI] macOS notification failed: %v", err)
	}
}

// escapeAppleScript escapes double quotes and backslashes for AppleScript strings.
func escapeAppleScript(s string) string {
	var out []byte
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '"':
			out = append(out, '\\', '"')
		case '\\':
			out = append(out, '\\', '\\')
		default:
			out = append(out, s[i])
		}
	}
	return string(out)
}
