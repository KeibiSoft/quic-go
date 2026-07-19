//go:build !darwin

package quic

import "github.com/quic-go/quic-go/internal/protocol"

// batchSend declines on non-darwin platforms; the caller falls back to per-packet
// WritePacket. On Linux the equivalent batching is UDP GSO, already done inside
// WritePacket, so there is nothing to add here.
func (c *sconn) batchSend(_ [][]byte, _ *remoteAddrInfo, _ protocol.ECN) (bool, error) {
	return false, nil
}
