//go:build windows

package main

import (
	"log"
	"sync"
	"time"

	"github.com/go-toast/toast"
)

// NotificationManager sends Windows toast notifications with throttling.
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
// The toast is shown at most once per version (not throttled by time).
func (nm *NotificationManager) NotifyUpdateAvailable(version string) {
	nm.mu.Lock()
	if !nm.enabled || !nm.updates {
		nm.mu.Unlock()
		return
	}
	key := "update:" + version
	if _, seen := nm.lastNotif[key]; seen {
		nm.mu.Unlock()
		return
	}
	nm.lastNotif[key] = time.Now()
	nm.mu.Unlock()

	go nm.send("Доступно обновление", "Версия "+version+" готова к установке")
}

func (nm *NotificationManager) send(title, message string) {
	n := toast.Notification{
		AppID:   nm.appName,
		Title:   title,
		Message: message,
	}
	if err := n.Push(); err != nil {
		log.Printf("[UI] Toast notification failed: %v", err)
	}
}
