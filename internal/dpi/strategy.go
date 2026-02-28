package dpi

import "time"

// DesyncMode identifies the TLS ClientHello desynchronization technique.
type DesyncMode string

const (
	DesyncNone          DesyncMode = "none"          // pass-through, no desync
	DesyncFake          DesyncMode = "fake"           // inject fake packet with short TTL
	DesyncMultisplit    DesyncMode = "multisplit"     // split ClientHello into small TCP segments
	DesyncFakedsplit    DesyncMode = "fakedsplit"     // fake + split combination
	DesyncMultidisorder DesyncMode = "multidisorder"  // out-of-order split segments
)

// FoolMethod describes how a fake packet is made to look invalid
// to the destination server while still being processed by DPI middleboxes.
type FoolMethod string

const (
	FoolBadSum FoolMethod = "badsum" // incorrect TCP checksum
	FoolBadSeq FoolMethod = "badseq" // wrong TCP sequence number
	FoolTTL    FoolMethod = "ttl"    // short TTL (packet expires before destination)
	FoolMD5Sig FoolMethod = "md5sig" // TCP MD5 signature option
)

// SplitPosAutoSNI is a sentinel value meaning "split at the SNI offset".
const SplitPosAutoSNI = 0

// DesyncOp describes a single desync operation applied to matching TCP connections.
type DesyncOp struct {
	// FilterPorts limits this op to specific TCP destination ports. Empty = all.
	FilterPorts []int `json:"filter_ports,omitempty"`
	// FilterProtocol is "tcp" or "udp". Default "tcp".
	FilterProtocol string `json:"filter_protocol,omitempty"`
	// Mode is the desync technique.
	Mode DesyncMode `json:"mode"`
	// FakeTTL is the IP TTL for fake packets (default 1).
	FakeTTL int `json:"fake_ttl,omitempty"`
	// Fool describes fool methods for fake packet injection.
	Fool []FoolMethod `json:"fool,omitempty"`
	// Repeats is how many fake packets to inject (default 1).
	Repeats int `json:"repeats,omitempty"`
	// SplitPos lists byte offsets where the ClientHello is split.
	// 0 = auto (SNI boundary). Negative values count from end.
	SplitPos []int `json:"split_pos,omitempty"`
	// SplitSeqOvl is the TCP sequence overlap for split segments (disorder mode).
	SplitSeqOvl int `json:"split_seq_ovl,omitempty"`
	// FakeTLS is raw bytes for the fake TLS ClientHello payload.
	FakeTLS []byte `json:"fake_tls,omitempty"`
	// Cutoff stops desync after N-th packet, e.g. "n3" = after 3rd packet.
	Cutoff string `json:"cutoff,omitempty"`
}

// Strategy is a named collection of desync operations, typically parsed
// from a zapret .bat file or discovered by the parameter searcher.
type Strategy struct {
	Name       string     `json:"name"`
	Source     string     `json:"source"` // "zapret", "user", "search"
	Ops        []DesyncOp `json:"ops"`
	LastTested time.Time  `json:"last_tested,omitempty"`
	NetworkID  string     `json:"network_id,omitempty"` // ISP/network identifier (gateway IP)
}

// MatchesPort returns true if the operation should apply to the given TCP port.
func (op *DesyncOp) MatchesPort(port int) bool {
	if len(op.FilterPorts) == 0 {
		return true
	}
	for _, p := range op.FilterPorts {
		if p == port {
			return true
		}
	}
	return false
}

// Defaults fills in zero-value fields with sensible defaults.
func (op *DesyncOp) Defaults() {
	if op.FilterProtocol == "" {
		op.FilterProtocol = "tcp"
	}
	if op.Mode == "" {
		op.Mode = DesyncMultisplit
	}
	if op.FakeTTL == 0 {
		op.FakeTTL = 1
	}
	if op.Repeats == 0 {
		op.Repeats = 1
	}
}
