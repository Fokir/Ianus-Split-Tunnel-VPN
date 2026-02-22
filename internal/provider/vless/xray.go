//go:build windows

package vless

// Register xray-core components required for VLESS + Reality.
// Selective imports to minimize binary size (instead of main/distro/all).
import (
	// Core infrastructure (required for StartInstance).
	_ "github.com/xtls/xray-core/app/dispatcher"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"

	// JSON config loader.
	_ "github.com/xtls/xray-core/main/json"

	// VLESS outbound protocol.
	_ "github.com/xtls/xray-core/proxy/vless/outbound"

	// Freedom outbound (direct, needed for routing fallback).
	_ "github.com/xtls/xray-core/proxy/freedom"

	// Transport: TCP + Reality + TLS.
	_ "github.com/xtls/xray-core/transport/internet/reality"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
	_ "github.com/xtls/xray-core/transport/internet/tls"

	// Transport: WebSocket (optional, for ws transport).
	_ "github.com/xtls/xray-core/transport/internet/websocket"

	// Transport: gRPC (optional, for grpc transport).
	_ "github.com/xtls/xray-core/transport/internet/grpc"
)
