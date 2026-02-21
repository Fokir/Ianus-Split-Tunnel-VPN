//go:build windows

package main

import (
	"context"

	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/icons"

	vpnapi "awg-split-tunnel/api/gen"
	"google.golang.org/protobuf/types/known/emptypb"
)

func setupTray(app *application.App, mainWindow *application.WebviewWindow, binding *BindingService) {
	systray := app.SystemTray.New()
	systray.SetIcon(icons.SystrayLight)

	// Left-click on tray icon opens the main window.
	systray.OnClick(func() {
		mainWindow.Show()
		mainWindow.Focus()
	})

	menu := app.Menu.New()

	// Connect/Disconnect toggle.
	connectItem := menu.Add("Подключить")
	connectItem.OnClick(func(_ *application.Context) {
		ctx := context.Background()
		status, err := binding.client.Service.GetStatus(ctx, &emptypb.Empty{})
		if err != nil {
			return
		}
		if status.ActiveTunnels > 0 {
			// Disconnect all.
			_, _ = binding.client.Service.Disconnect(ctx, &vpnapi.DisconnectRequest{})
			connectItem.SetLabel("Подключить")
		} else {
			// Connect all.
			_, _ = binding.client.Service.Connect(ctx, &vpnapi.ConnectRequest{})
			connectItem.SetLabel("Отключить")
			connectItem.SetChecked(true)
		}
	})

	menu.AddSeparator()

	// Settings — open main window on settings tab.
	menu.Add("Настройки").OnClick(func(_ *application.Context) {
		mainWindow.Show()
		mainWindow.Focus()
		app.Event.Emit("navigate", "/settings")
	})

	menu.AddSeparator()

	// Exit — close GUI and signal VPN service to shut down.
	menu.Add("Выйти").OnClick(func(_ *application.Context) {
		ctx := context.Background()
		_, _ = binding.client.Service.Shutdown(ctx, &emptypb.Empty{})
		app.Quit()
	})

	systray.SetMenu(menu)

	// Update tray state periodically based on VPN status.
	go updateTrayState(app, systray, connectItem, binding)
}

func updateTrayState(app *application.App, systray *application.SystemTray, connectItem *application.MenuItem, binding *BindingService) {
	ctx := context.Background()

	// Subscribe to stats stream to update tray icon.
	stream, err := binding.client.Service.StreamStats(ctx, &vpnapi.StatsStreamRequest{
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
			connectItem.SetLabel("Отключить")
			connectItem.SetChecked(true)
		} else {
			systray.SetLabel("AWG - Disconnected")
			connectItem.SetLabel("Подключить")
			connectItem.SetChecked(false)
		}
	}
}
