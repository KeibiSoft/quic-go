//go:build linux || freebsd

package quic

// newRecvmsgXBatchConn is darwin-only. On Linux the receive path already batches via
// recvmmsg (through x/net), and freebsd keeps the default path, so returning nil leaves
// the existing batchConn selection untouched.
func newRecvmsgXBatchConn(OOBCapablePacketConn) batchConn { return nil }
