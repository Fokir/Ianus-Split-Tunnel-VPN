//go:build darwin

package main

import (
	"context"

	"github.com/wailsapp/wails/v3/pkg/application"

	vpnapi "awg-split-tunnel/api/gen"
	"google.golang.org/protobuf/types/known/emptypb"
)

func setupTray(app *application.App, mainWindow *application.WebviewWindow, binding *BindingService) {
	initTrayIcons()

	systray := app.SystemTray.New()
	systray.SetIcon(trayIconForStatus(trayStatusGray))

	// Left-click on tray icon opens the main window.
	systray.OnClick(func() {
		mainWindow.Show()
		mainWindow.Focus()
	})

	menu := app.Menu.New()

	// Tab navigation items — mirrors the GUI tab bar.
	tabItems := []struct {
		label string
		path  string
	}{
		{"Подключения", "/connections"},
		{"Подписки", "/subscriptions"},
		{"Правила", "/rules"},
		{"Домены", "/domains"},
		{"Настройки", "/settings"},
		{"Логи", "/logs"},
		{"О программе", "/about"},
	}

	for _, tab := range tabItems {
		t := tab
		menu.Add(t.label).OnClick(func(_ *application.Context) {
			mainWindow.Show()
			mainWindow.Focus()
			app.Event.Emit("navigate", t.path)
		})
	}

	menu.AddSeparator()

	// Exit — stop daemon and close GUI.
	menu.Add("Выйти").OnClick(func(_ *application.Context) {
		binding.Shutdown()
		_, _ = binding.client.Service.Shutdown(context.Background(), &emptypb.Empty{})
		app.Quit()
	})

	systray.SetMenu(menu)

	// Update tray state periodically based on VPN status.
	go updateTrayState(app, systray, binding)
}

func updateTrayState(app *application.App, systray *application.SystemTray, binding *BindingService) {
	stream, err := binding.client.Service.StreamStats(binding.ctx, &vpnapi.StatsStreamRequest{
		IntervalMs: 2000,
	})
	if err != nil {
		return
	}

	prev := trayStatus(-1)
	for {
		snap, err := stream.Recv()
		if err != nil {
			return
		}

		var hasActive, hasConnecting, hasError bool
		for _, t := range snap.Tunnels {
			switch t.State {
			case vpnapi.TunnelState_TUNNEL_STATE_UP:
				hasActive = true
			case vpnapi.TunnelState_TUNNEL_STATE_CONNECTING:
				hasConnecting = true
			case vpnapi.TunnelState_TUNNEL_STATE_ERROR:
				hasError = true
			}
		}

		var status trayStatus
		switch {
		case hasError:
			status = trayStatusRed
		case hasConnecting:
			status = trayStatusYellow
		case hasActive:
			status = trayStatusGreen
		default:
			status = trayStatusGray
		}

		if status != prev {
			systray.SetIcon(trayIconForStatus(status))
			prev = status
		}
	}
}
