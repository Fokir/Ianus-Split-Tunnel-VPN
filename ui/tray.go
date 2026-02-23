//go:build windows

package main

import (
	"context"

	"github.com/wailsapp/wails/v3/pkg/application"

	vpnapi "awg-split-tunnel/api/gen"
	"google.golang.org/protobuf/types/known/emptypb"
)

func setupTray(app *application.App, mainWindow *application.WebviewWindow, binding *BindingService) {
	systray := app.SystemTray.New()
	systray.SetIcon(trayIconPNG)

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

	// Exit — close GUI and signal VPN service to shut down.
	menu.Add("Выйти").OnClick(func(_ *application.Context) {
		// Cancel all streaming goroutines first so they don't block shutdown.
		binding.Shutdown()
		_, _ = binding.client.Service.Shutdown(context.Background(), &emptypb.Empty{})
		app.Quit()
	})

	systray.SetMenu(menu)

	// Update tray state periodically based on VPN status.
	go updateTrayState(app, systray, binding)
}

func updateTrayState(app *application.App, systray *application.SystemTray, binding *BindingService) {
	// Subscribe to stats stream to update tray icon.
	stream, err := binding.client.Service.StreamStats(binding.ctx, &vpnapi.StatsStreamRequest{
		IntervalMs: 2000,
	})
	if err != nil {
		return
	}

	for {
		snap, err := stream.Recv()
		if err != nil {
			return
		}

		hasActive := false
		hasError := false
		for _, t := range snap.Tunnels {
			if t.State == vpnapi.TunnelState_TUNNEL_STATE_UP {
				hasActive = true
			}
			if t.State == vpnapi.TunnelState_TUNNEL_STATE_ERROR {
				hasError = true
			}
		}

		if hasError {
			systray.SetLabel("AWG - Error")
		} else if hasActive {
			systray.SetLabel("AWG - Connected")
		} else {
			systray.SetLabel("AWG - Disconnected")
		}
	}
}
