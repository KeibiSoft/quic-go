//go:build darwin

package quic

import (
	"net"
	"syscall"
	"unsafe"

	"golang.org/x/net/ipv4"
)

// sysRecvmsgX is SYS_recvmsg_x — the receive counterpart of sendmsg_x, the darwin
// analog of the Linux recvmmsg path quic-go already uses (via x/net on Linux).
const sysRecvmsgX = 480

// sockaddrStorageSize is sizeof(struct sockaddr_storage): per-message scratch big
// enough for any source address recvmsg_x writes back.
const sockaddrStorageSize = 128

// recvmsgXConn is a batchConn that reads several datagrams per recvmsg_x syscall,
// cutting the darwin receive-side ceiling (one recvmsg per packet, no recvmmsg). This
// is the receive half of the batching; sendmsg_x is the send half. Verified end to end
// in small_experiments/sendmsg_x/ (TestRecvmsgXBatch). Read from one goroutine only.
type recvmsgXConn struct {
	raw      syscall.RawConn
	fallback batchConn // plain one-at-a-time path, used when packets are not bursting
	single   bool      // currently on the fallback (recvmsg_x kept reading 1)
	ones     int       // consecutive recvmsg_x reads that returned <=1 (batch mode)
	calls    int       // fallback reads since the last recvmsg_x re-probe (single mode)
	msgs     []msghdrX
	iovs     []syscall.Iovec
	names    [][sockaddrStorageSize]byte
}

// recvSwitchToSingle: consecutive 1-datagram recvmsg_x reads that trigger a fallback to
// the plain path. recvmsg_x has more per-call overhead than a simple recv, so reading 1
// at a time through it is a net loss (measured ~15% slower on loopback, where the
// receiver keeps up and never bursts). recvProbeEvery: how often the fallback re-probes
// with recvmsg_x to notice bursts and switch back to batching.
const (
	recvSwitchToSingle = 32
	recvProbeEvery     = 256
)

// newRecvmsgXBatchConn returns a recvmsg_x-backed batchConn, or nil if the fd is not
// reachable (caller then keeps the default receive path).
func newRecvmsgXBatchConn(c OOBCapablePacketConn) batchConn {
	raw, err := c.SyscallConn()
	if err != nil {
		return nil
	}
	return &recvmsgXConn{raw: raw, fallback: ipv4.NewPacketConn(c)}
}

// ReadBatch adaptively chooses recvmsg_x (which batches when packets burst, e.g. a real
// NIC coalescing interrupts: measured ~38 datagrams/syscall under flood) or the plain
// one-at-a-time path (loopback / low-BDP, where the receiver keeps up so recvmsg_x would
// only add overhead reading 1 at a time). It stays on whichever fits the traffic and
// re-probes so it follows a change. Send batching (sendmsg_x) has no such tradeoff: the
// producer always bursts, so it is unconditional.
func (b *recvmsgXConn) ReadBatch(ms []ipv4.Message, flags int) (int, error) {
	if b.single {
		b.calls++
		if b.calls < recvProbeEvery {
			return b.fallback.ReadBatch(ms, flags)
		}
		b.calls = 0
		n, err := b.recvmsgX(ms, flags)
		if err == nil && n > 1 { // bursting again: resume batching
			b.single = false
			b.ones = 0
		}
		return n, err
	}
	n, err := b.recvmsgX(ms, flags)
	if err != nil {
		return n, err
	}
	if n <= 1 {
		if b.ones++; b.ones >= recvSwitchToSingle {
			b.single = true
			b.calls = 0
		}
	} else {
		b.ones = 0
	}
	return n, nil
}

// recvmsgX reads up to len(ms) datagrams in one recvmsg_x syscall.
func (b *recvmsgXConn) recvmsgX(ms []ipv4.Message, flags int) (int, error) {
	m := len(ms)
	if m == 0 {
		return 0, nil
	}
	if cap(b.msgs) < m {
		b.msgs = make([]msghdrX, m)
		b.iovs = make([]syscall.Iovec, m)
		b.names = make([][sockaddrStorageSize]byte, m)
	}
	msgs, iovs, names := b.msgs[:m], b.iovs[:m], b.names[:m]
	for i := range ms {
		iovs[i] = syscall.Iovec{Base: &ms[i].Buffers[0][0], Len: uint64(len(ms[i].Buffers[0]))}
		msgs[i] = msghdrX{
			Name: &names[i][0], Namelen: sockaddrStorageSize,
			Iov: &iovs[i], Iovlen: 1,
			Datalen: uint64(len(ms[i].Buffers[0])),
		}
		if len(ms[i].OOB) > 0 {
			msgs[i].Control = &ms[i].OOB[0]
			msgs[i].Controllen = uint32(len(ms[i].OOB))
		}
	}

	var got int
	var rerr error
	err := b.raw.Read(func(fd uintptr) bool {
		cnt, _, errno := syscall.Syscall6(sysRecvmsgX, fd,
			uintptr(unsafe.Pointer(&msgs[0])), uintptr(m), uintptr(flags), 0, 0)
		if errno == syscall.EAGAIN {
			return false // no datagrams yet: wait for readable, then retry
		}
		if errno != 0 {
			rerr = errno
			return true
		}
		got = int(cnt)
		return true
	})
	if err != nil {
		return 0, err
	}
	if rerr != nil {
		return 0, rerr
	}
	for i := 0; i < got; i++ {
		ms[i].N = int(msgs[i].Datalen)
		ms[i].NN = int(msgs[i].Controllen)
		ms[i].Flags = int(msgs[i].Flags)
		ms[i].Addr = parseRecvSockaddr(names[i][:])
	}
	return got, nil
}

// parseRecvSockaddr decodes a darwin sockaddr (byte 0 = sa_len, byte 1 = sa_family)
// written by recvmsg_x into a *net.UDPAddr, unmapping v4-mapped IPv6 back to IPv4 so it
// matches the address form the rest of quic-go uses.
func parseRecvSockaddr(name []byte) net.Addr {
	if len(name) < 4 {
		return nil
	}
	switch name[1] {
	case syscall.AF_INET:
		sa := (*syscall.RawSockaddrInet4)(unsafe.Pointer(&name[0]))
		return &net.UDPAddr{IP: append(net.IP{}, sa.Addr[:]...), Port: portFromBE(&sa.Port)}
	case syscall.AF_INET6:
		sa := (*syscall.RawSockaddrInet6)(unsafe.Pointer(&name[0]))
		ip := append(net.IP{}, sa.Addr[:]...)
		if v4 := ip.To4(); v4 != nil {
			ip = v4
		}
		return &net.UDPAddr{IP: ip, Port: portFromBE(&sa.Port)}
	}
	return nil
}

// portFromBE reads a network-order (big-endian) port field.
func portFromBE(p *uint16) int {
	b := (*[2]byte)(unsafe.Pointer(p))
	return int(b[0])<<8 | int(b[1])
}
