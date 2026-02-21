//go:build windows

package main

import (
	_ "embed"
)

//go:embed tray_icon.png
var trayIconPNG []byte
