//go:build windows

package gateway

import (
	"fmt"
	"net/netip"
	"os/exec"
	"runtime"
	"unsafe"

	"awg-split-tunnel/internal/core"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"
)

const (
	adapterName  = "AWG Gateway"
	adapterType  = "AWG"
	ringCapacity = 0x1000000 // 16 MiB ring buffer (was 8 MiB — reduces overflow under sustained upload)
	tunIP        = "10.255.0.1"
	tunPrefixLen = 24
	tunMetric    = 5
)

// Adapter wraps a WinTUN adapter with IP configuration.
type Adapter struct {
	wt       *wintun.Adapter
	session  wintun.Session
	readWait windows.Handle
	luid     uint64
	ifIndex  uint32
	ip       netip.Addr
}

// NewAdapter creates a WinTUN adapter, assigns IP 10.255.0.1/24, and sets low metric.
func NewAdapter() (*Adapter, error) {
	// Use a fixed GUID for repeatable adapter identity.
	guid := windows.GUID{
		Data1: 0xABCD1234,
		Data2: 0x5678,
		Data3: 0x9ABC,
		Data4: [8]byte{0xDE, 0xF0, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC},
	}

	wt, err := wintun.CreateAdapter(adapterName, adapterType, &guid)
	if err != nil {
		return nil, fmt.Errorf("[Gateway] create adapter: %w", err)
	}

	session, err := wt.StartSession(ringCapacity)
	if err != nil {
		wt.Close()
		return nil, fmt.Errorf("[Gateway] start session: %w", err)
	}

	luid := wt.LUID()
	ip := netip.MustParseAddr(tunIP)

	a := &Adapter{
		wt:       wt,
		session:  session,
		readWait: session.ReadWaitEvent(),
		luid:     luid,
		ip:       ip,
	}

	// Assign IP address via iphlpapi.
	if err := a.assignIP(); err != nil {
		session.End()
		wt.Close()
		return nil, fmt.Errorf("[Gateway] assign IP: %w", err)
	}

	// Set low metric to make this the preferred interface.
	if err := a.setMetric(); err != nil {
		core.Log.Warnf("Gateway", "Failed to set metric: %v", err)
	}

	core.Log.Infof("Gateway", "Adapter %q created (IP=%s, LUID=0x%x)", adapterName, ip, luid)
	return a, nil
}

// LUID returns the adapter's locally unique identifier.
func (a *Adapter) LUID() uint64 { return a.luid }

// InterfaceIndex returns the adapter's interface index.
func (a *Adapter) InterfaceIndex() uint32 { return a.ifIndex }

// IP returns the adapter's assigned IP address.
func (a *Adapter) IP() netip.Addr { return a.ip }

// ReadPacket reads one IP packet into buf and returns the number of bytes read.
// The caller must provide a buffer of at least maxPacketSize bytes.
// Blocks until a packet is available or the session is ended.
func (a *Adapter) ReadPacket(buf []byte) (int, error) {
	for {
		pkt, err := a.session.ReceivePacket()
		if err == nil {
			n := copy(buf, pkt)
			a.session.ReleaseReceivePacket(pkt)
			return n, nil
		}
		// ERROR_NO_MORE_ITEMS means the ring is empty — wait for data.
		if errno, ok := err.(windows.Errno); ok && errno == windows.ERROR_NO_MORE_ITEMS {
			r, _ := windows.WaitForSingleObject(a.readWait, windows.INFINITE)
			if r != windows.WAIT_OBJECT_0 {
				return 0, fmt.Errorf("[Gateway] wait failed: %d", r)
			}
			continue
		}
		return 0, fmt.Errorf("[Gateway] receive: %w", err)
	}
}

// WritePacket writes one IP packet to the TUN adapter.
// Retries once after a brief yield on ring buffer overflow.
func (a *Adapter) WritePacket(pkt []byte) error {
	buf, err := a.session.AllocateSendPacket(len(pkt))
	if err != nil {
		// Ring full — yield to let OS drain, then retry once.
		runtime.Gosched()
		buf, err = a.session.AllocateSendPacket(len(pkt))
		if err != nil {
			return err
		}
	}
	copy(buf, pkt)
	a.session.SendPacket(buf)
	return nil
}

// Close tears down the adapter and session.
func (a *Adapter) Close() error {
	a.session.End()
	a.wt.Close()
	core.Log.Infof("Gateway", "Adapter closed")
	return nil
}

// SetDNS configures DNS servers on the TUN adapter so that Windows DNS Client
// sends queries to these servers (through TUN) instead of ISP/default DNS.
// Also flushes the system DNS cache to clear stale entries.
func (a *Adapter) SetDNS(servers []netip.Addr) error {
	if len(servers) == 0 {
		return nil
	}

	// Set primary DNS server via netsh using interface index.
	out, err := exec.Command("netsh", "interface", "ipv4", "set", "dnsservers",
		fmt.Sprintf("name=%d", a.ifIndex), "static", servers[0].String(),
		"register=none", "validate=no",
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("set dns %s: %s: %w", servers[0], string(out), err)
	}

	// Add secondary DNS servers.
	for i := 1; i < len(servers); i++ {
		out, err := exec.Command("netsh", "interface", "ipv4", "add", "dnsservers",
			fmt.Sprintf("name=%d", a.ifIndex), servers[i].String(),
			fmt.Sprintf("index=%d", i+1), "validate=no",
		).CombinedOutput()
		if err != nil {
			core.Log.Warnf("DNS", "Failed to add secondary DNS %s: %s: %v", servers[i], string(out), err)
		}
	}

	// Flush DNS cache to clear stale/blocked entries.
	exec.Command("ipconfig", "/flushdns").Run()

	return nil
}

// ClearDNS removes DNS server configuration from the TUN adapter, restoring
// default system DNS resolution via the real NIC.
func (a *Adapter) ClearDNS() error {
	out, err := exec.Command("netsh", "interface", "ipv4", "set", "dnsservers",
		fmt.Sprintf("name=%d", a.ifIndex), "dhcp",
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("clear dns: %s: %w", string(out), err)
	}

	// Flush DNS cache to apply immediately.
	exec.Command("ipconfig", "/flushdns").Run()
	core.Log.Infof("DNS", "TUN adapter DNS cleared")
	return nil
}

// ---------------------------------------------------------------------------
// IP configuration via iphlpapi.dll
// ---------------------------------------------------------------------------

var (
	modIPHlpAPI = windows.NewLazySystemDLL("iphlpapi.dll")

	procInitializeUnicastIpAddressEntry = modIPHlpAPI.NewProc("InitializeUnicastIpAddressEntry")
	procCreateUnicastIpAddressEntry     = modIPHlpAPI.NewProc("CreateUnicastIpAddressEntry")
	procGetIpInterfaceEntry             = modIPHlpAPI.NewProc("GetIpInterfaceEntry")
	procSetIpInterfaceEntry             = modIPHlpAPI.NewProc("SetIpInterfaceEntry")
)

// MIB_UNICASTIPADDRESS_ROW (simplified for IPv4).
// Size: 80 bytes on x64. We use a fixed-size byte array and poke fields at known offsets.
type mibUnicastIPAddressRow struct {
	data [80]byte
}

// Offsets within MIB_UNICASTIPADDRESS_ROW (x64, 80 bytes).
//
// Layout:
//   0:  SOCKADDR_INET   Address            (28 + 4 pad = 32)
//       0:  si_family (2), 2: sin_port (2), 4: sin_addr (4)
//  32:  NET_LUID        InterfaceLuid      (8)
//  40:  NET_IFINDEX     InterfaceIndex     (4)
//  44:  NL_PREFIX_ORIGIN PrefixOrigin      (4)
//  48:  NL_SUFFIX_ORIGIN SuffixOrigin      (4)
//  52:  ULONG           ValidLifetime      (4)
//  56:  ULONG           PreferredLifetime  (4)
//  60:  UINT8           OnLinkPrefixLength (1)
//  61:  BOOLEAN         SkipAsSource       (1 + 2 pad)
//  64:  NL_DAD_STATE    DadState           (4)
//  68:  SCOPE_ID        ScopeId            (4)
//  72:  LARGE_INTEGER   CreationTimeStamp  (8)
const (
	unicastAddrFamily       = 0   // si_family (AF_INET = 2)
	unicastAddr             = 4   // sin_addr offset within SOCKADDR_INET
	unicastInterfaceLUID    = 32  // NET_LUID
	unicastInterfaceIndex   = 40  // IF_INDEX
	unicastPrefixOrigin     = 44  // NL_PREFIX_ORIGIN
	unicastSuffixOrigin     = 48  // NL_SUFFIX_ORIGIN
	unicastOnLinkPrefixLen  = 60  // UINT8 (after ValidLifetime@52 + PreferredLifetime@56)
	unicastDadState         = 64  // NL_DAD_STATE (after OnLinkPrefixLen + SkipAsSource + pad)
)

func (a *Adapter) assignIP() error {
	var row mibUnicastIPAddressRow
	procInitializeUnicastIpAddressEntry.Call(uintptr(unsafe.Pointer(&row)))

	// Address family: AF_INET
	*(*uint16)(unsafe.Pointer(&row.data[unicastAddrFamily])) = windows.AF_INET
	// sin_family
	*(*uint16)(unsafe.Pointer(&row.data[unicastAddrFamily+2])) = 0 // sin_port
	// sin_addr
	ip4 := a.ip.As4()
	copy(row.data[unicastAddr:unicastAddr+4], ip4[:])

	// Interface LUID
	*(*uint64)(unsafe.Pointer(&row.data[unicastInterfaceLUID])) = a.luid
	// Prefix origin: Manual (1)
	*(*int32)(unsafe.Pointer(&row.data[unicastPrefixOrigin])) = 1
	// Suffix origin: Manual (1)
	*(*int32)(unsafe.Pointer(&row.data[unicastSuffixOrigin])) = 1
	// OnLinkPrefixLength
	row.data[unicastOnLinkPrefixLen] = tunPrefixLen
	// DadState: Preferred (4)
	*(*int32)(unsafe.Pointer(&row.data[unicastDadState])) = 4

	r, _, _ := procCreateUnicastIpAddressEntry.Call(uintptr(unsafe.Pointer(&row)))
	if r != 0 && r != 0x80071392 { // ERROR_OBJECT_ALREADY_EXISTS
		return fmt.Errorf("CreateUnicastIpAddressEntry failed: 0x%x", r)
	}

	// Retrieve interface index.
	a.ifIndex = a.lookupInterfaceIndex()

	return nil
}

// MIB_IPINTERFACE_ROW (x64).
// Use 256-byte buffer for forward-compatibility with newer Windows versions.
//
// Layout (key fields):
//   0:   ADDRESS_FAMILY  Family             (2 + 6 pad)
//   8:   NET_LUID        InterfaceLuid      (8)
//  16:   NET_IFINDEX     InterfaceIndex     (4)
//  20:   ULONG           MaxReassemblySize  (4)
//  24:   ULONG64         InterfaceIdentifier(8)
//  32:   ULONG           MinRouterAdvInterval(4)
//  36:   ULONG           MaxRouterAdvInterval(4)
//  40:   BOOLEAN         AdvertisingEnabled (1)
//  41:   BOOLEAN         ForwardingEnabled  (1)
//  42:   BOOLEAN         WeakHostSend       (1)
//  43:   BOOLEAN         WeakHostReceive    (1)
//  44:   BOOLEAN         UseAutomaticMetric (1)
//  ...
//  80:   ULONG[16]       ZoneIndices        (64)
// 144:   ULONG           SitePrefixLength   (4)
// 148:   ULONG           Metric             (4)
// 152:   ULONG           NlMtu              (4)
// ...
type mibIPInterfaceRow struct {
	data [256]byte
}

const (
	ipIfFamily        = 0
	ipIfLUID          = 8
	ipIfIndex         = 16
	ipIfUseAutometric = 44  // BOOLEAN (after 9 BOOLEANs starting at offset 40)
	ipIfMetric        = 148 // ULONG (after ZoneIndices[16] at 80 + SitePrefixLength at 144)
	ipIfNlMtu         = 152 // ULONG NlMtu
)

func (a *Adapter) setMetric() error {
	var row mibIPInterfaceRow
	*(*uint16)(unsafe.Pointer(&row.data[ipIfFamily])) = windows.AF_INET
	*(*uint64)(unsafe.Pointer(&row.data[ipIfLUID])) = a.luid

	r, _, _ := procGetIpInterfaceEntry.Call(uintptr(unsafe.Pointer(&row)))
	if r != 0 {
		return fmt.Errorf("GetIpInterfaceEntry failed: 0x%x", r)
	}

	// Disable automatic metric, set our metric value, and set MTU.
	row.data[ipIfUseAutometric] = 0
	*(*uint32)(unsafe.Pointer(&row.data[ipIfMetric])) = tunMetric
	*(*uint32)(unsafe.Pointer(&row.data[ipIfNlMtu])) = tunInterfaceMTU

	r, _, _ = procSetIpInterfaceEntry.Call(uintptr(unsafe.Pointer(&row)))
	if r != 0 {
		return fmt.Errorf("SetIpInterfaceEntry failed: 0x%x", r)
	}

	core.Log.Infof("Gateway", "Interface MTU set to %d", tunInterfaceMTU)
	return nil
}

func (a *Adapter) lookupInterfaceIndex() uint32 {
	var row mibIPInterfaceRow
	*(*uint16)(unsafe.Pointer(&row.data[ipIfFamily])) = windows.AF_INET
	*(*uint64)(unsafe.Pointer(&row.data[ipIfLUID])) = a.luid

	r, _, _ := procGetIpInterfaceEntry.Call(uintptr(unsafe.Pointer(&row)))
	if r != 0 {
		return 0
	}
	return *(*uint32)(unsafe.Pointer(&row.data[ipIfIndex]))
}
