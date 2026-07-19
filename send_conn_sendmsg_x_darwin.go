//go:build darwin

package quic

import (
	"errors"
	"net"
	"syscall"

	"github.com/quic-go/quic-go/internal/protocol"
)

// darwinBatch caches the per-connection state for sendmsg_x batching: the destination
// sockaddr (rebuilt when the remote address changes, e.g. on migration) and reusable
// msghdr/iovec scratch. Held on the sconn and touched only from the sendQueue.Run
// goroutine, so it needs no locking.
type darwinBatch struct {
	dest     *sendmsgXDest
	destAddr string
	family   int // socket address family (AF_INET / AF_INET6), from getsockname
	msgs     []msghdrX
	iovs     []syscall.Iovec
}

func (b *darwinBatch) scratch(n int) ([]msghdrX, []syscall.Iovec) {
	if cap(b.msgs) < n {
		b.msgs = make([]msghdrX, n)
		b.iovs = make([]syscall.Iovec, n)
	}
	return b.msgs[:n], b.iovs[:n]
}

// batchSend coalesces bufs (all sharing ecn, gsoSize 0) into ONE sendmsg_x to the
// connection's remote address — the darwin analog of the Linux GSO path, cutting the
// per-packet sendmsg cost that caps QUIC throughput on macOS (no UDP GSO). Returns
// handled=false to let the caller fall back to per-packet WritePacket: a single packet,
// a non-UDP address, or a socket whose fd we cannot reach.
func (c *sconn) batchSend(bufs [][]byte, ai *remoteAddrInfo, ecn protocol.ECN) (bool, error) {
	if len(bufs) < 2 {
		return false, nil
	}
	udpAddr, ok := ai.addr.(*net.UDPAddr)
	if !ok {
		return false, nil
	}
	rc, ok := c.rawConn.(interface {
		SyscallConn() (syscall.RawConn, error)
	})
	if !ok {
		return false, nil
	}
	raw, err := rc.SyscallConn()
	if err != nil {
		return false, nil
	}

	bs, _ := c.batch.(*darwinBatch)
	if bs == nil {
		bs = &darwinBatch{}
		c.batch = bs
	}
	if bs.family == 0 { // determine the socket's address family once
		var fam int
		_ = raw.Control(func(fd uintptr) {
			if sa, err := syscall.Getsockname(int(fd)); err == nil {
				switch sa.(type) {
				case *syscall.SockaddrInet4:
					fam = syscall.AF_INET
				case *syscall.SockaddrInet6:
					fam = syscall.AF_INET6
				}
			}
		})
		if fam == 0 {
			return false, nil // unknown family: fall back to per-packet WritePacket
		}
		bs.family = fam
	}
	if bs.dest == nil || bs.destAddr != udpAddr.String() {
		bs.dest = newSendmsgXDest(udpAddr, bs.family)
		bs.destAddr = udpAddr.String()
	}

	// Build the control message the way WritePacket does. gsoSize is 0 here, so there is
	// no UDP_SEGMENT cmsg; add the ECN cmsg if ECN is in use. It is constant across the
	// batch (one remote, one ecn), so build it once.
	oob := ai.oob
	if ecn != protocol.ECNUnsupported {
		if udpAddr.IP.To4() != nil {
			oob = appendIPv4ECNMsg(oob, ecn)
		} else {
			oob = appendIPv6ECNMsg(oob, ecn)
		}
	}

	msgs, iovs := bs.scratch(len(bufs))
	remaining := bufs
	var sendErr error
	werr := raw.Write(func(fd uintptr) bool {
		// sendmsg_x may accept FEWER datagrams than offered when the socket buffer
		// fills mid-batch. Advance past the accepted ones and resend the rest, or wait
		// for the socket to become writable — never silently drop the tail (that stalls
		// the QUIC connection).
		for len(remaining) > 0 {
			sent, err := sendmsgXBatchTo(int(fd), remaining, bs.dest.name(), bs.dest.namelen, oob, msgs, iovs)
			if sent > 0 {
				remaining = remaining[sent:]
				continue
			}
			if err == nil || errors.Is(err, syscall.EAGAIN) {
				return false // no progress: wait for writable, then resume from remaining
			}
			sendErr = err
			return true // a real send error
		}
		return true // whole batch sent
	})
	if werr != nil {
		return true, werr
	}
	return true, sendErr
}
