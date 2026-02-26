package gateway

const (
	// tunInterfaceMTU is the MTU configured on the TUN adapter.
	// Used by helpers.go for TCP MSS clamping calculations.
	tunInterfaceMTU = 1400

	// maxPacketSize is the max IPv4 packet size; used for pre-allocated read buffers.
	maxPacketSize = 65535
)
