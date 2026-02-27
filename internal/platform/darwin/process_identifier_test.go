//go:build darwin

package darwin

import (
	"net"
	"os"
	"testing"
)

func TestFindPIDByPort_TCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	myPID := uint32(os.Getpid())

	pi := NewProcessIdentifier()
	gotPID, err := pi.FindPIDByPort(port, false)
	if err != nil {
		t.Fatalf("FindPIDByPort(TCP port %d): %v", port, err)
	}
	if gotPID != myPID {
		t.Errorf("got PID %d, want %d", gotPID, myPID)
	}
}

func TestFindPIDByPort_UDP(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	port := uint16(conn.LocalAddr().(*net.UDPAddr).Port)
	myPID := uint32(os.Getpid())

	pi := NewProcessIdentifier()
	gotPID, err := pi.FindPIDByPort(port, true)
	if err != nil {
		t.Fatalf("FindPIDByPort(UDP port %d): %v", port, err)
	}
	if gotPID != myPID {
		t.Errorf("got PID %d, want %d", gotPID, myPID)
	}
}

func TestScanPortPIDs_NonEmpty(t *testing.T) {
	m, err := scanPortPIDs()
	if err != nil {
		t.Fatal(err)
	}
	if len(m) == 0 {
		t.Error("scanPortPIDs returned empty map; expected at least some active sockets")
	}
}

func TestPcbStructSize(t *testing.T) {
	if pcbStructSize != 384 && pcbStructSize != 408 {
		t.Errorf("unexpected pcbStructSize=%d, want 384 or 408", pcbStructSize)
	}
	t.Logf("pcbStructSize=%d (detected from kern.osrelease)", pcbStructSize)
}

func TestParsePCBList_BothProtocols(t *testing.T) {
	m, err := scanPortPIDs()
	if err != nil {
		t.Fatal(err)
	}

	hasTCP, hasUDP := false, false
	for k := range m {
		if k.isUDP {
			hasUDP = true
		} else {
			hasTCP = true
		}
	}
	t.Logf("scanPortPIDs: %d entries (TCP=%v, UDP=%v)", len(m), hasTCP, hasUDP)
	if !hasTCP {
		t.Log("warning: no TCP entries found")
	}
	if !hasUDP {
		t.Log("warning: no UDP entries found")
	}
	if !hasTCP && !hasUDP {
		t.Error("no entries found for either protocol")
	}
}

func BenchmarkScanPortPIDs(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := scanPortPIDs()
		if err != nil {
			b.Fatal(err)
		}
	}
}
