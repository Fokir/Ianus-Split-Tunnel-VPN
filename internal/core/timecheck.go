package core

import (
	"encoding/binary"
	"net"
	"time"
)

// ntpEpochOffset is the number of seconds between NTP epoch (1900-01-01)
// and Unix epoch (1970-01-01). Both are UTC-based, so no timezone issues.
const ntpEpochOffset = 2208988800

// maxClockDrift is the threshold above which we warn the user.
const maxClockDrift = 2 * time.Minute

// ntpServers is a list of NTP servers to try in order.
var ntpServers = []string{
	"pool.ntp.org:123",
	"time.google.com:123",
	"time.cloudflare.com:123",
	"time.windows.com:123",
}

// CheckSystemTime queries an NTP server and compares the response with
// the local clock. All arithmetic uses UTC internally, so the local
// timezone setting has no effect on the result.
//
// Logs a warning if the drift exceeds maxClockDrift.
// Runs best-effort: errors are logged at debug level and do not block startup.
func CheckSystemTime() {
	drift, err := measureClockDrift()
	if err != nil {
		Log.Debugf("Core", "System time check skipped: %v", err)
		return
	}

	absDrift := drift
	if absDrift < 0 {
		absDrift = -absDrift
	}

	if absDrift > maxClockDrift {
		Log.Warnf("Core", "System clock is off by %v — TLS certificates, WireGuard handshakes "+
			"and other time-sensitive operations may fail. Please synchronize your system clock.",
			drift.Truncate(time.Second))
	} else {
		Log.Infof("Core", "System clock drift: %v (OK)", drift.Truncate(time.Millisecond))
	}
}

// measureClockDrift queries NTP servers and returns (local - NTP) difference.
// Positive means local clock is ahead; negative means behind.
// Uses raw NTP v3 packet over UDP — no TLS, no HTTP, no external dependencies.
func measureClockDrift() (time.Duration, error) {
	var lastErr error
	for _, server := range ntpServers {
		drift, err := queryNTP(server)
		if err != nil {
			lastErr = err
			continue
		}
		return drift, nil
	}
	return 0, lastErr
}

// queryNTP sends a minimal NTP v3 request and returns the clock offset.
// All NTP timestamps are in UTC by definition (RFC 5905), so the result
// is timezone-independent.
func queryNTP(server string) (time.Duration, error) {
	conn, err := net.DialTimeout("udp", server, 3*time.Second)
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return 0, err
	}

	// NTP v3 client request (48 bytes).
	// Byte 0: LI=0, VN=3, Mode=3 (client) → 0x1B.
	req := make([]byte, 48)
	req[0] = 0x1B

	// Record local time just before sending (UTC via time.Now().UTC()).
	t1 := time.Now().UTC()

	if _, err := conn.Write(req); err != nil {
		return 0, err
	}

	resp := make([]byte, 48)
	if _, err := conn.Read(resp); err != nil {
		return 0, err
	}

	// Record local time just after receiving.
	t4 := time.Now().UTC()

	// Extract transmit timestamp from response (bytes 40-47).
	// NTP timestamp: 32-bit seconds since 1900-01-01 UTC + 32-bit fraction.
	secs := binary.BigEndian.Uint32(resp[40:44])
	frac := binary.BigEndian.Uint32(resp[44:48])

	// Convert NTP timestamp to time.Time (UTC).
	ntpTime := time.Unix(int64(secs)-ntpEpochOffset, (int64(frac)*1e9)>>32).UTC()

	// Simple offset: assume symmetric delay.
	// offset = ntpTime - midpoint(t1, t4)
	roundTrip := t4.Sub(t1)
	localMid := t1.Add(roundTrip / 2)
	drift := localMid.Sub(ntpTime)

	return drift, nil
}
