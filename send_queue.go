package quic

import (
	"net"

	"github.com/quic-go/quic-go/internal/protocol"
)

type sender interface {
	Send(p *packetBuffer, gsoSize uint16, ecn protocol.ECN)
	SendProbe(*packetBuffer, net.Addr, packetInfo)
	Run() error
	WouldBlock() bool
	Available() <-chan struct{}
	Close()
}

type queueEntry struct {
	buf     *packetBuffer
	gsoSize uint16
	ecn     protocol.ECN
}

type sendQueue struct {
	queue       chan queueEntry
	closeCalled chan struct{} // runStopped when Close() is called
	runStopped  chan struct{} // runStopped when the run loop returns
	available   chan struct{}
	conn        sendConn

	// Scratch for coalescing queued packets into one batched send (reused across Run
	// iterations; Run is single-goroutine so no locking).
	batch []queueEntry
	bufs  [][]byte
}

// batchWriter is an optional capability: a conn that can send several datagrams that
// share (gsoSize, ecn) in one call. On darwin this is one sendmsg_x, the analog of the
// Linux GSO path; a conn that does not implement it just gets one Write per packet.
type batchWriter interface {
	writeBatch(bufs [][]byte, gsoSize uint16, ecn protocol.ECN) error
}

var _ sender = &sendQueue{}

const sendQueueCapacity = 8

// maxSendBatch caps how many queued packets one batched send coalesces. The queue holds
// at most sendQueueCapacity, so this is a safe upper bound with headroom.
const maxSendBatch = 16

func newSendQueue(conn sendConn) sender {
	return &sendQueue{
		conn:        conn,
		runStopped:  make(chan struct{}),
		closeCalled: make(chan struct{}),
		available:   make(chan struct{}, 1),
		queue:       make(chan queueEntry, sendQueueCapacity),
	}
}

// Send sends out a packet. It's guaranteed to not block.
// Callers need to make sure that there's actually space in the send queue by calling WouldBlock.
// Otherwise Send will panic.
func (h *sendQueue) Send(p *packetBuffer, gsoSize uint16, ecn protocol.ECN) {
	select {
	case h.queue <- queueEntry{buf: p, gsoSize: gsoSize, ecn: ecn}:
		// clear available channel if we've reached capacity
		if len(h.queue) == sendQueueCapacity {
			select {
			case <-h.available:
			default:
			}
		}
	case <-h.runStopped:
	default:
		panic("sendQueue.Send would have blocked")
	}
}

func (h *sendQueue) SendProbe(p *packetBuffer, addr net.Addr, info packetInfo) {
	h.conn.WriteTo(p.Data, addr, info)
}

func (h *sendQueue) WouldBlock() bool {
	return len(h.queue) == sendQueueCapacity
}

func (h *sendQueue) Available() <-chan struct{} {
	return h.available
}

func (h *sendQueue) Run() error {
	defer close(h.runStopped)
	var shouldClose bool
	for {
		if shouldClose && len(h.queue) == 0 {
			return nil
		}
		select {
		case <-h.closeCalled:
			h.closeCalled = nil // prevent this case from being selected again
			// make sure that all queued packets are actually sent out
			shouldClose = true
		case e := <-h.queue:
			batch := append(h.batch[:0], e)
			// Opportunistically coalesce packets already queued that share the same
			// (gsoSize, ecn) into one batched send. A packet that differs flushes the
			// current batch and starts a new one.
			for len(h.queue) > 0 && len(batch) < maxSendBatch {
				n := <-h.queue
				if n.gsoSize != batch[0].gsoSize || n.ecn != batch[0].ecn {
					if err := h.flush(batch); err != nil {
						h.batch = batch[:0]
						return err
					}
					batch = append(h.batch[:0], n)
					continue
				}
				batch = append(batch, n)
			}
			err := h.flush(batch)
			h.batch = batch[:0]
			if err != nil {
				return err
			}
		}
	}
}

// flush sends a group of queued packets that share (gsoSize, ecn), as one batched send
// when the conn supports it (and gsoSize is 0, i.e. darwin), else one Write each. It
// releases every packet buffer afterward and signals availability. The size-error check
// is preserved: a "datagram too large" reply drives path MTU discovery rather than
// tearing the connection down.
func (h *sendQueue) flush(batch []queueEntry) error {
	var sendErr error
	if bw, ok := h.conn.(batchWriter); ok && len(batch) > 1 && batch[0].gsoSize == 0 {
		bufs := h.bufs[:0]
		for _, e := range batch {
			bufs = append(bufs, e.buf.Data)
		}
		sendErr = bw.writeBatch(bufs, batch[0].gsoSize, batch[0].ecn)
		h.bufs = bufs[:0]
	} else {
		for _, e := range batch {
			if err := h.conn.Write(e.buf.Data, e.gsoSize, e.ecn); err != nil {
				sendErr = err
				break
			}
		}
	}
	for _, e := range batch {
		e.buf.Release()
	}
	select {
	case h.available <- struct{}{}:
	default:
	}
	if sendErr != nil && !isSendMsgSizeErr(sendErr) {
		return sendErr
	}
	return nil
}

func (h *sendQueue) Close() {
	close(h.closeCalled)
	// wait until the run loop returned
	<-h.runStopped
}
