//go:build windows

package service

import (
	"fmt"
	"strings"

	vpnapi "awg-split-tunnel/api/gen"
)

// StreamConnections streams active connection snapshots to the client.
func (s *Service) StreamConnections(req *vpnapi.ConnectionMonitorRequest, stream vpnapi.VPNService_StreamConnectionsServer) error {
	if s.connMonitor == nil {
		return fmt.Errorf("connection monitor not initialized")
	}

	ch := s.connMonitor.Subscribe()
	defer s.connMonitor.Unsubscribe(ch)

	tunnelFilter := strings.ToLower(req.GetTunnelFilter())
	processFilter := strings.ToLower(req.GetProcessFilter())

	for {
		select {
		case <-stream.Context().Done():
			return nil
		case snap, ok := <-ch:
			if !ok {
				return nil
			}
			if tunnelFilter != "" || processFilter != "" {
				filtered := make([]*vpnapi.ConnectionEntry, 0, len(snap.Connections))
				for _, e := range snap.Connections {
					if tunnelFilter != "" && !strings.Contains(strings.ToLower(e.TunnelId), tunnelFilter) {
						continue
					}
					if processFilter != "" && !strings.Contains(strings.ToLower(e.ProcessName), processFilter) {
						continue
					}
					filtered = append(filtered, e)
				}
				snap = &vpnapi.ConnectionSnapshot{Connections: filtered}
			}
			if err := stream.Send(snap); err != nil {
				return err
			}
		}
	}
}
