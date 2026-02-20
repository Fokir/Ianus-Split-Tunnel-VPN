//go:build windows

package gateway

import (
	"encoding/binary"
	"fmt"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ProcessIdentifier finds the owning PID for TCP/UDP connections by source port.
// On the TUN adapter, source IP is always 10.255.0.1, so port uniquely identifies
// the connection in the GetExtendedTcpTable / GetExtendedUdpTable.
type ProcessIdentifier struct {
	tcpBufPool sync.Pool
	udpBufPool sync.Pool
}

// NewProcessIdentifier creates a new process identifier.
func NewProcessIdentifier() *ProcessIdentifier {
	return &ProcessIdentifier{
		tcpBufPool: sync.Pool{
			New: func() any {
				b := make([]byte, 64*1024)
				return &b
			},
		},
		udpBufPool: sync.Pool{
			New: func() any {
				b := make([]byte, 64*1024)
				return &b
			},
		},
	}
}

var (
	modIPHlpAPIProc = windows.NewLazySystemDLL("iphlpapi.dll")

	procGetExtendedTcpTable = modIPHlpAPIProc.NewProc("GetExtendedTcpTable")
	procGetExtendedUdpTable = modIPHlpAPIProc.NewProc("GetExtendedUdpTable")
)

const (
	// TCP_TABLE_OWNER_PID_CONNECTIONS = 4
	tcpTableOwnerPIDConn = 4
	// UDP_TABLE_OWNER_PID = 1
	udpTableOwnerPID = 1
)

// FindPIDByPort finds the PID owning a connection with the given local port.
// isUDP selects between TCP and UDP tables.
func (pi *ProcessIdentifier) FindPIDByPort(srcPort uint16, isUDP bool) (uint32, error) {
	if isUDP {
		return pi.findUDPPID(srcPort)
	}
	return pi.findTCPPID(srcPort)
}

func (pi *ProcessIdentifier) findTCPPID(srcPort uint16) (uint32, error) {
	bp := pi.tcpBufPool.Get().(*[]byte)
	defer pi.tcpBufPool.Put(bp)
	buf := *bp

	size := uint32(len(buf))
	r, _, _ := procGetExtendedTcpTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		0,                             // bOrder = false
		uintptr(windows.AF_INET),      // AF_INET
		uintptr(tcpTableOwnerPIDConn), // TCP_TABLE_OWNER_PID_CONNECTIONS
		0,
	)

	if r == 122 { // ERROR_INSUFFICIENT_BUFFER
		bigger := make([]byte, size)
		*bp = bigger
		buf = bigger
		r, _, _ = procGetExtendedTcpTable.Call(
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&size)),
			0,
			uintptr(windows.AF_INET),
			uintptr(tcpTableOwnerPIDConn),
			0,
		)
	}
	if r != 0 {
		return 0, fmt.Errorf("GetExtendedTcpTable: 0x%x", r)
	}

	// Structure: DWORD dwNumEntries + MIB_TCPROW_OWNER_PID[N]
	// Each row (24 bytes): dwState(4), dwLocalAddr(4), dwLocalPort(4),
	//                      dwRemoteAddr(4), dwRemotePort(4), dwOwningPid(4)
	numEntries := binary.LittleEndian.Uint32(buf[0:4])
	const rowSize = 24
	offset := 4

	for i := uint32(0); i < numEntries; i++ {
		rowOff := offset + int(i)*rowSize
		if rowOff+rowSize > int(size) {
			break
		}
		// dwLocalPort is at row offset 8, stored as DWORD in network byte order.
		localPort := ntohs(*(*uint32)(unsafe.Pointer(&buf[rowOff+8])))
		if localPort == srcPort {
			pid := binary.LittleEndian.Uint32(buf[rowOff+20 : rowOff+24])
			if pid != 0 {
				return pid, nil
			}
		}
	}

	return 0, fmt.Errorf("no TCP PID for port %d", srcPort)
}

func (pi *ProcessIdentifier) findUDPPID(srcPort uint16) (uint32, error) {
	bp := pi.udpBufPool.Get().(*[]byte)
	defer pi.udpBufPool.Put(bp)
	buf := *bp

	size := uint32(len(buf))
	r, _, _ := procGetExtendedUdpTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		0,
		uintptr(windows.AF_INET),
		uintptr(udpTableOwnerPID),
		0,
	)

	if r == 122 { // ERROR_INSUFFICIENT_BUFFER
		bigger := make([]byte, size)
		*bp = bigger
		buf = bigger
		r, _, _ = procGetExtendedUdpTable.Call(
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&size)),
			0,
			uintptr(windows.AF_INET),
			uintptr(udpTableOwnerPID),
			0,
		)
	}
	if r != 0 {
		return 0, fmt.Errorf("GetExtendedUdpTable: 0x%x", r)
	}

	// Structure: DWORD dwNumEntries + MIB_UDPROW_OWNER_PID[N]
	// Each row (12 bytes): dwLocalAddr(4), dwLocalPort(4), dwOwningPid(4)
	numEntries := binary.LittleEndian.Uint32(buf[0:4])
	const rowSize = 12
	offset := 4

	for i := uint32(0); i < numEntries; i++ {
		rowOff := offset + int(i)*rowSize
		if rowOff+rowSize > int(size) {
			break
		}
		localPort := ntohs(*(*uint32)(unsafe.Pointer(&buf[rowOff+4])))
		if localPort == srcPort {
			pid := binary.LittleEndian.Uint32(buf[rowOff+8 : rowOff+12])
			if pid != 0 {
				return pid, nil
			}
		}
	}

	return 0, fmt.Errorf("no UDP PID for port %d", srcPort)
}

// ntohs converts a DWORD stored in network byte order to a host uint16 port.
func ntohs(v uint32) uint16 {
	return uint16(v & 0xFF)<<8 | uint16((v>>8)&0xFF)
}
