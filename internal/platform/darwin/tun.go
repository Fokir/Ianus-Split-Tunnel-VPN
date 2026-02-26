//go:build darwin

package darwin

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync"

	"golang.org/x/sys/unix"

	"awg-split-tunnel/internal/core"
)

const (
	// utun kernel control name.
	utunControlName = "com.apple.net.utun_control"

	// SYSPROTO_CONTROL for AF_SYSTEM sockets.
	sysProtoControl = 2
	// UTUN_OPT_IFNAME getsockopt option.
	utunOptIfname = 2

	// utun prepends a 4-byte address family header (network byte order).
	utunHeaderSize = 4

	// TUN configuration (matches Windows: 10.255.0.1/24, MTU 1400).
	tunIP        = "10.255.0.1"
	tunPrefixLen = 24
	tunMTU       = 1400

	// Maximum IP packet size.
	maxPacketSize = 65535
)

// writeBufPool avoids per-packet allocation in WritePacket.
var writeBufPool = sync.Pool{
	New: func() any {
		return make([]byte, maxPacketSize+utunHeaderSize)
	},
}

// TUNAdapter implements platform.TUNAdapter using macOS utun interfaces.
// Created via kernel control socket (AF_SYSTEM, SYSPROTO_CONTROL).
type TUNAdapter struct {
	name    string   // utun interface name (e.g. "utun5")
	file    *os.File // wraps the utun socket fd
	ifIndex uint32
	ip      netip.Addr
	readBuf []byte // pre-allocated read buffer (single-goroutine use)

	// DNS state: cached primary service and saved servers for restore.
	primaryService string
	savedDNS       []string
}

// NewTUNAdapter creates a macOS utun TUN adapter with IP 10.255.0.1/24, MTU 1400.
func NewTUNAdapter() (*TUNAdapter, error) {
	fd, ifName, err := openUtun()
	if err != nil {
		return nil, fmt.Errorf("[Gateway] create utun: %w", err)
	}

	a := &TUNAdapter{
		name:    ifName,
		file:    os.NewFile(uintptr(fd), ifName),
		ip:      netip.MustParseAddr(tunIP),
		readBuf: make([]byte, maxPacketSize+utunHeaderSize),
	}
	if a.file == nil {
		unix.Close(fd)
		return nil, fmt.Errorf("[Gateway] invalid utun fd")
	}

	// Resolve interface index.
	iface, err := net.InterfaceByName(ifName)
	if err != nil {
		a.Close()
		return nil, fmt.Errorf("[Gateway] interface lookup %s: %w", ifName, err)
	}
	a.ifIndex = uint32(iface.Index)

	// Configure IP address and MTU.
	if err := a.configureInterface(); err != nil {
		a.Close()
		return nil, fmt.Errorf("[Gateway] configure %s: %w", ifName, err)
	}

	// Cache primary network service for DNS operations (must run before default routes).
	if svc, err := primaryNetworkService(); err == nil {
		a.primaryService = svc
		core.Log.Debugf("DNS", "Primary network service: %s", svc)
	} else {
		core.Log.Warnf("DNS", "Could not determine primary network service: %v", err)
	}

	core.Log.Infof("Gateway", "utun adapter %s created (IP=%s, ifIndex=%d)", ifName, a.ip, a.ifIndex)
	return a, nil
}

// openUtun opens a new utun device via kernel control socket.
// Returns (fd, interface_name, error).
func openUtun() (int, string, error) {
	// Create AF_SYSTEM control socket.
	fd, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, sysProtoControl)
	if err != nil {
		return -1, "", fmt.Errorf("socket(AF_SYSTEM): %w", err)
	}

	// Resolve control ID for "com.apple.net.utun_control".
	ctlInfo := &unix.CtlInfo{}
	copy(ctlInfo.Name[:], utunControlName)
	if err := unix.IoctlCtlInfo(fd, ctlInfo); err != nil {
		unix.Close(fd)
		return -1, "", fmt.Errorf("CTLIOCGINFO: %w", err)
	}

	// Connect with unit=0 to let kernel assign next available utun number.
	sa := unix.SockaddrCtl{
		ID:   ctlInfo.Id,
		Unit: 0,
	}
	if err := unix.Connect(fd, &sa); err != nil {
		unix.Close(fd)
		return -1, "", fmt.Errorf("connect utun: %w", err)
	}

	// Retrieve assigned interface name (e.g. "utun5").
	ifName, err := unix.GetsockoptString(fd, sysProtoControl, utunOptIfname)
	if err != nil {
		unix.Close(fd)
		return -1, "", fmt.Errorf("get utun name: %w", err)
	}

	// Set non-blocking for Go runtime poller integration (kqueue).
	if err := unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return -1, "", fmt.Errorf("set nonblock: %w", err)
	}

	return fd, ifName, nil
}

// configureInterface assigns IP address, sets MTU, and brings the interface up.
func (a *TUNAdapter) configureInterface() error {
	// Assign IP address with peer address and bring up.
	out, err := exec.Command("ifconfig", a.name,
		"inet", fmt.Sprintf("%s/%d", tunIP, tunPrefixLen),
		tunIP, "up",
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ifconfig inet: %s: %w", strings.TrimSpace(string(out)), err)
	}

	// Set MTU.
	out, err = exec.Command("ifconfig", a.name,
		"mtu", fmt.Sprintf("%d", tunMTU),
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ifconfig mtu: %s: %w", strings.TrimSpace(string(out)), err)
	}

	return nil
}

// LUID returns the interface index as uint64 (macOS has no LUID; index serves the same role).
func (a *TUNAdapter) LUID() uint64 { return uint64(a.ifIndex) }

// InterfaceIndex returns the utun interface index.
func (a *TUNAdapter) InterfaceIndex() uint32 { return a.ifIndex }

// IP returns the adapter's assigned IP address (10.255.0.1).
func (a *TUNAdapter) IP() netip.Addr { return a.ip }

// ReadPacket reads one IP packet from the utun device, stripping the 4-byte AF header.
// Not safe for concurrent use — called from the single packet-loop goroutine.
func (a *TUNAdapter) ReadPacket(buf []byte) (int, error) {
	n, err := a.file.Read(a.readBuf)
	if err != nil {
		return 0, err
	}
	if n <= utunHeaderSize {
		return 0, fmt.Errorf("[Gateway] short utun read: %d bytes", n)
	}
	// Skip 4-byte AF header, copy clean IP packet to caller's buffer.
	return copy(buf, a.readBuf[utunHeaderSize:n]), nil
}

// WritePacket writes one IP packet to the utun device, prepending the 4-byte AF header.
// Uses a sync.Pool to avoid per-packet allocation. Safe for concurrent use.
func (a *TUNAdapter) WritePacket(pkt []byte) error {
	if len(pkt) == 0 {
		return nil
	}

	buf := writeBufPool.Get().([]byte)

	// AF header in network byte order (big endian).
	// macOS: AF_INET=2, AF_INET6=30 (NOT 10 as on Linux).
	switch pkt[0] >> 4 {
	case 4:
		binary.BigEndian.PutUint32(buf, unix.AF_INET)
	case 6:
		binary.BigEndian.PutUint32(buf, unix.AF_INET6)
	default:
		writeBufPool.Put(buf)
		return fmt.Errorf("[Gateway] unknown IP version: %d", pkt[0]>>4)
	}

	copy(buf[utunHeaderSize:], pkt)
	_, err := a.file.Write(buf[:utunHeaderSize+len(pkt)])
	writeBufPool.Put(buf)
	return err
}

// SetDNS configures system DNS to use the given servers via networksetup.
// Saves the current DNS configuration for later restore by ClearDNS.
func (a *TUNAdapter) SetDNS(servers []netip.Addr) error {
	if len(servers) == 0 {
		return nil
	}
	if a.primaryService == "" {
		return fmt.Errorf("no primary network service available for DNS configuration")
	}

	// Save current DNS for restore.
	a.savedDNS = currentDNSServers(a.primaryService)

	args := []string{"-setdnsservers", a.primaryService}
	for _, s := range servers {
		args = append(args, s.String())
	}

	out, err := exec.Command("networksetup", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("networksetup set DNS: %s: %w", strings.TrimSpace(string(out)), err)
	}

	_ = flushSystemDNS()
	core.Log.Infof("DNS", "System DNS set to %v on service %q", servers, a.primaryService)
	return nil
}

// ClearDNS restores the original DNS configuration saved by SetDNS.
func (a *TUNAdapter) ClearDNS() error {
	if a.primaryService == "" {
		return nil
	}

	args := []string{"-setdnsservers", a.primaryService}
	if len(a.savedDNS) > 0 {
		args = append(args, a.savedDNS...)
	} else {
		args = append(args, "empty") // restore DHCP/automatic
	}

	out, err := exec.Command("networksetup", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("networksetup clear DNS: %s: %w", strings.TrimSpace(string(out)), err)
	}

	a.savedDNS = nil
	_ = flushSystemDNS()
	core.Log.Infof("DNS", "System DNS restored on service %q", a.primaryService)
	return nil
}

// Close tears down the utun adapter. The kernel removes the utun interface when the fd is closed.
func (a *TUNAdapter) Close() error {
	if a.file != nil {
		if err := a.file.Close(); err != nil {
			return err
		}
		core.Log.Infof("Gateway", "utun adapter %s closed", a.name)
	}
	return nil
}

// primaryNetworkService finds the active network service name (e.g. "Wi-Fi")
// by resolving the default route interface and mapping it via networksetup.
func primaryNetworkService() (string, error) {
	// Get default route interface (e.g. "en0").
	out, err := exec.Command("route", "-n", "get", "default").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("route get default: %w", err)
	}

	var ifName string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "interface:") {
			ifName = strings.TrimSpace(line[len("interface:"):])
			break
		}
	}
	if ifName == "" {
		return "", fmt.Errorf("no default interface found")
	}

	// Map interface name to network service via hardware ports listing.
	out, err = exec.Command("networksetup", "-listallhardwareports").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("list hardware ports: %w", err)
	}

	var svc string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Hardware Port:") {
			svc = strings.TrimPrefix(line, "Hardware Port: ")
		} else if strings.HasPrefix(line, "Device:") {
			dev := strings.TrimSpace(strings.TrimPrefix(line, "Device:"))
			if dev == ifName {
				return svc, nil
			}
		}
	}

	return "", fmt.Errorf("no network service for interface %s", ifName)
}

// currentDNSServers returns the current DNS servers for the given network service.
// Returns nil if DNS is set to automatic/DHCP.
func currentDNSServers(service string) []string {
	out, err := exec.Command("networksetup", "-getdnsservers", service).CombinedOutput()
	if err != nil {
		return nil
	}
	text := strings.TrimSpace(string(out))
	if text == "" || strings.Contains(text, "any DNS Servers") {
		return nil
	}
	var servers []string
	for _, line := range strings.Split(text, "\n") {
		if s := strings.TrimSpace(line); s != "" {
			servers = append(servers, s)
		}
	}
	return servers
}
