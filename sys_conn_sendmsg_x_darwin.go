//go:build darwin

package quic

// macOS UDP send batching via the undocumented sendmsg_x(2) syscall — the darwin
// analog of the Linux UDP GSO path (sys_conn_helper_linux.go). It is the only
// kernel-free way to cut the per-packet sendmsg cost that caps QUIC on macOS, which
// has no UDP GSO: quic-go otherwise issues one sendmsg per ~1400-byte packet.
//
// Measured: 390 MB/s one-per-packet -> 701 MB/s at batch 32 (1.8x), 32x fewer
// syscalls, and lower CPU per byte (which matters when QUIC runs alongside the FUSE
// filesystem). Standalone spike + byte-exact ABI validation + benchmark live in
// small_experiments/sendmsg_x/.
//
// STATUS: WIRED. sendmsgXBatchTo (unconnected, addr-aware) is used by sconn.writeBatch,
// which sendQueue.Run() calls after coalescing same-(gsoSize,ecn) queued packets. The
// receive twin recvmsg_x is in sys_conn_recvmsg_x_darwin.go. Both ABI-verified standalone
// in small_experiments/sendmsg_x/. Two bugs found (both -race-masked): quic-go binds a
// dual-stack AF_INET6 socket so IPv4 dests need a v4-mapped sockaddr_in6 (built from
// getsockname); and sendmsg_x may accept fewer datagrams than offered, so writeBatch's
// darwin path resends the tail. Send batches ~3 datagrams/syscall; the throughput win is
// on fast bursty networks (a single-host round-trip is receive/pipeline-bound). Full
// story: grpc_using_quic/docs/FINDINGS.md.

import (
	"net"
	"syscall"
	"unsafe"
)

// sysSendmsgX is SYS_sendmsg_x from the macOS SDK <sys/syscall.h>.
const sysSendmsgX = 481

// msghdrX matches struct msghdr_x (XNU bsd/sys/socket.h). The 4-byte pads after the
// two 4-byte fields are the ABI trap; offsets are verified byte-exact
// (0/8/16/24/32/40/44/48, size 56) by the test in small_experiments/sendmsg_x/.
type msghdrX struct {
	Name       *byte
	Namelen    uint32
	_          uint32
	Iov        *syscall.Iovec
	Iovlen     int32
	_          uint32
	Control    *byte
	Controllen uint32
	Flags      int32
	Datalen    uint64
}

// sendmsgXBatch sends each payload as its own datagram to the connected socket fd in
// ONE sendmsg_x syscall, returning the number of datagrams the kernel accepted. The
// caller supplies reusable scratch (msgs, iovs) sized >= len(payloads) to stay
// allocation-free in the hot path. Payload backing arrays are read by the kernel
// during the call and must stay valid until it returns.
func sendmsgXBatch(fd int, payloads [][]byte, msgs []msghdrX, iovs []syscall.Iovec) (int, error) {
	n := len(payloads)
	if n == 0 {
		return 0, nil
	}
	for i, p := range payloads {
		iovs[i] = syscall.Iovec{Base: &p[0], Len: uint64(len(p))}
		msgs[i] = msghdrX{Iov: &iovs[i], Iovlen: 1, Datalen: uint64(len(p))}
	}
	sent, _, errno := syscall.Syscall6(sysSendmsgX, uintptr(fd),
		uintptr(unsafe.Pointer(&msgs[0])), uintptr(n), 0, 0, 0)
	if errno != 0 {
		return int(sent), errno
	}
	return int(sent), nil
}

// sendmsgXBatchTo is sendmsgXBatch for an UNCONNECTED socket, which is what quic-go
// uses (WritePacket -> WriteMsgUDP with an explicit addr, sys_conn_oob.go:267). Each
// datagram carries the destination sockaddr (name/namelen) and a shared control message
// (oob). A quic-go connection sends to a single remote with a single source/ECN oob, so
// name and oob are constant across a batch. Verified against a real unconnected socket
// in small_experiments/sendmsg_x/ (TestBatchSendToUnconnected). Build the (name,
// namelen) once per connection with newSendmsgXDest and reuse it.
func sendmsgXBatchTo(fd int, payloads [][]byte, name *byte, namelen uint32, oob []byte, msgs []msghdrX, iovs []syscall.Iovec) (int, error) {
	n := len(payloads)
	if n == 0 {
		return 0, nil
	}
	var ctl *byte
	var ctllen uint32
	if len(oob) > 0 {
		ctl = &oob[0]
		ctllen = uint32(len(oob))
	}
	for i, p := range payloads {
		iovs[i] = syscall.Iovec{Base: &p[0], Len: uint64(len(p))}
		msgs[i] = msghdrX{
			Name: name, Namelen: namelen,
			Iov: &iovs[i], Iovlen: 1,
			Control: ctl, Controllen: ctllen,
			Datalen: uint64(len(p)),
		}
	}
	sent, _, errno := syscall.Syscall6(sysSendmsgX, uintptr(fd),
		uintptr(unsafe.Pointer(&msgs[0])), uintptr(n), 0, 0, 0)
	if errno != 0 {
		return int(sent), errno
	}
	return int(sent), nil
}

// sendmsgXDest holds a prebuilt destination sockaddr for sendmsgXBatchTo, reused across
// batches (one per connection). Keep it alive while the kernel reads it.
type sendmsgXDest struct {
	sa4     syscall.RawSockaddrInet4
	sa6     syscall.RawSockaddrInet6
	isV6    bool
	namelen uint32
}

// newSendmsgXDest builds the destination sockaddr matching the SOCKET's family, not the
// address's: quic-go binds dual-stack AF_INET6 sockets (network "udp"), which reject a
// raw sockaddr_in and require a v4-mapped sockaddr_in6 for IPv4 destinations. sockFamily
// is the socket's family (AF_INET or AF_INET6), from getsockname.
func newSendmsgXDest(addr *net.UDPAddr, sockFamily int) *sendmsgXDest {
	d := &sendmsgXDest{}
	v4 := addr.IP.To4()
	if sockFamily == syscall.AF_INET && v4 != nil {
		d.sa4.Len = syscall.SizeofSockaddrInet4
		d.sa4.Family = syscall.AF_INET
		bePort(unsafe.Pointer(&d.sa4.Port), addr.Port)
		copy(d.sa4.Addr[:], v4)
		d.namelen = uint32(syscall.SizeofSockaddrInet4)
		return d
	}
	// IPv6 or dual-stack socket: sockaddr_in6, v4-mapped (::ffff:a.b.c.d) for IPv4 dests.
	d.isV6 = true
	d.sa6.Len = syscall.SizeofSockaddrInet6
	d.sa6.Family = syscall.AF_INET6
	bePort(unsafe.Pointer(&d.sa6.Port), addr.Port)
	if v4 != nil {
		d.sa6.Addr[10], d.sa6.Addr[11] = 0xff, 0xff
		copy(d.sa6.Addr[12:], v4)
	} else {
		copy(d.sa6.Addr[:], addr.IP.To16())
		if addr.Zone != "" { // link-local scope id
			if iface, err := net.InterfaceByName(addr.Zone); err == nil {
				d.sa6.Scope_id = uint32(iface.Index)
			}
		}
	}
	d.namelen = uint32(syscall.SizeofSockaddrInet6)
	return d
}

// bePort writes port as big-endian (network order) bytes; darwin is little-endian, so
// this matches how Go's stdlib builds a sockaddr.
func bePort(p unsafe.Pointer, port int) {
	b := (*[2]byte)(p)
	b[0] = byte(port >> 8)
	b[1] = byte(port)
}

func (d *sendmsgXDest) name() *byte {
	if d.isV6 {
		return (*byte)(unsafe.Pointer(&d.sa6))
	}
	return (*byte)(unsafe.Pointer(&d.sa4))
}
