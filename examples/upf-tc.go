package main

import (
	"net"
	"time"
	"unsafe"

	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/packet"
	"github.com/intel-go/nff-go/types"
)

type q struct {
	q    []uintptr
	head int
	tail int
	size int
}

func newQ(size int) q {
	q := q{}
	q.q = make([]uintptr, size, size)
	q.head = 0
	q.tail = 0
	q.size = size
	return q
}

func (q *q) enq(p uintptr) error {
	/*
		if q.qlen() == q.size-1 {
			return errors.New("q full")
		}
	*/
	q.q[q.tail] = p
	if q.tail == q.size-1 {
		q.tail = 0
	} else {
		q.tail += 1
	}
	return nil
}

func (q *q) deq() (uintptr, error) {
	/*
		if q.qlen() == 0 {
			return 0, errors.New("q empty")
		}
	*/
	p := q.q[q.head]
	if q.head == q.size-1 {
		q.head = 0
	} else {
		q.head += 1
	}
	return p, nil
}

func (q *q) qlen() int {
	if q.head <= q.tail {
		return q.tail - q.head
	}
	return q.size + q.tail - q.head
}

var macdut0 [types.EtherAddrLen]uint8
var macdut1 [types.EtherAddrLen]uint8
var mactst0 [types.EtherAddrLen]uint8
var mactst1 [types.EtherAddrLen]uint8

var t0 = time.Now()
var t1 = time.Now()

var pid uint16

type GTP5GHdr struct {
	HeaderType            uint8
	MessageType           uint8
	MessageLength         uint16
	TEID                  uint32
	SequenceNumber        uint16
	NPDUNumber            uint8
	NextExtensionHeader1  uint8
	ExtensionHeaderLength uint8
	PDUType               uint8
	QFI                   uint8
	NextExtensionHeader2  uint8
}

type GTP5GCork struct {
	ipv4  packet.IPv4Hdr
	udp   packet.UDPHdr
	gtp5g GTP5GHdr
}

var cork GTP5GCork

func ulHandler(pkt *packet.Packet) bool {
	pkt.ParseL3()
	ipv4 := pkt.GetIPv4()
	if ipv4 == nil {
		return false
	}
	pkt.ParseL4ForIPv4()
	udp := pkt.GetUDPForIPv4()
	if udp == nil || udp.DstPort != packet.SwapUDPPortGTPU {
		return false
	}
	if !pkt.DecapsulateHead(types.EtherLen, types.IPv4MinLen+types.UDPLen+16) {
		return false
	}
	pkt.Ether.DAddr = mactst1
	pkt.Ether.SAddr = macdut1
	return true
}

func dlHandler(pkt *packet.Packet) bool {
	pkt.ParseL3()
	ipv4 := pkt.GetIPv4()
	if ipv4 == nil {
		return false
	}
	totalLength := packet.SwapBytesUint16(ipv4.TotalLength)
	if !pkt.EncapsulateHead(types.EtherLen, types.IPv4MinLen+types.UDPLen+16) {
		return false
	}
	corkp := (*GTP5GCork)(unsafe.Pointer(uintptr(unsafe.Pointer(pkt.Ether)) + types.EtherLen))
	*corkp = cork
	gtp5g := (*GTP5GHdr)(unsafe.Pointer(uintptr(unsafe.Pointer(pkt.Ether)) + types.EtherLen + types.IPv4MinLen + types.UDPLen))
	//gtp5g.HeaderType = 0x34
	//gtp5g.MessageType = 0xff
	gtp5g.MessageLength = packet.SwapBytesUint16(totalLength + 8)
	//gtp5g.TEID = packet.SwapBytesUint32(87)
	//gtp5g.SequenceNumber = 0x0000
	//gtp5g.NPDUNumber = 0x00
	//gtp5g.NextExtensionHeader1 = 0x85
	//gtp5g.ExtensionHeaderLength = 0x01
	//gtp5g.PDUType = 0x00
	//gtp5g.QFI = 0x01
	//gtp5g.NextExtensionHeader2 = 0x00
	udp := (*packet.UDPHdr)(unsafe.Pointer(uintptr(unsafe.Pointer(pkt.Ether)) + types.EtherLen + types.IPv4MinLen))
	//udp.SrcPort = packet.SwapUDPPortGTPU
	//udp.DstPort = packet.SwapUDPPortGTPU
	udp.DgramLen = packet.SwapBytesUint16(totalLength + 8 + 16)
	//udp.DgramCksum = 0x0000
	ipv4 = (*packet.IPv4Hdr)(unsafe.Pointer(uintptr(unsafe.Pointer(pkt.Ether)) + types.EtherLen))
	//ipv4.VersionIhl = 0x45
	//ipv4.TypeOfService = 0x00
	ipv4.TotalLength = packet.SwapBytesUint16(totalLength + 8 + 16 + 20)
	pid += 1
	ipv4.PacketID = pid
	//ipv4.FragmentOffset = 0x0000
	//ipv4.TimeToLive = 64
	//ipv4.NextProtoID = 17
	//ipv4.SrcAddr = 0x010110ac
	//ipv4.DstAddr =  0x020110ac
	ipv4.HdrChecksum = packet.SwapBytesUint16(packet.CalculateIPv4Checksum(ipv4))
	pkt.Ether.DAddr = mactst0
	pkt.Ether.SAddr = macdut0
	return true
}

var ulFifo = newQ(1024)
var ulNext = time.Now()
var ulPps time.Duration = 100000
var ulDelta = time.Second/ulPps - t1.Sub(t0)

func ulEnq(buf uintptr, enqed *bool) {
	pkt := packet.ExtractPacket(buf)
	ok := ulHandler(pkt)
	if !ok {
		*enqed = false
		return
	}
	if ulFifo.qlen() < ulFifo.size-1 {
		ulFifo.enq(buf)
		*enqed = true
		return
	}
	*enqed = false
}

func ulDeq(buf *uintptr, deqed *bool) {
	now := time.Now()
	if ulFifo.qlen() > 0 && now.After(ulNext) {
		*buf, _ = ulFifo.deq()
		*deqed = true
		ulNext = now.Add(ulDelta)
		return
	}
	*deqed = false
}

var dlFifo = newQ(1024)
var dlNext = time.Now()
var dlPps time.Duration = 100000
var dlDelta = time.Second/dlPps - t1.Sub(t0)

func dlEnq(buf uintptr, enqed *bool) {
	pkt := packet.ExtractPacket(buf)
	ok := dlHandler(pkt)
	if !ok {
		*enqed = false
		return
	}
	if dlFifo.qlen() < dlFifo.size-1 {
		dlFifo.enq(buf)
		*enqed = true
		return
	}
	*enqed = false
}

func dlDeq(buf *uintptr, deqed *bool) {
	now := time.Now()
	if dlFifo.qlen() > 0 && now.After(dlNext) {
		*buf, _ = dlFifo.deq()
		*deqed = true
		dlNext = now.Add(dlDelta)
		return
	}
	*deqed = false
}

func main() {
	cork.gtp5g.HeaderType = 0x34
	cork.gtp5g.MessageType = 0xff
	//cork.gtp5g.MessageLength = packet.SwapBytesUint16(totalLength + 8)
	cork.gtp5g.TEID = packet.SwapBytesUint32(87)
	cork.gtp5g.SequenceNumber = 0x0000
	cork.gtp5g.NPDUNumber = 0x00
	cork.gtp5g.NextExtensionHeader1 = 0x85
	cork.gtp5g.ExtensionHeaderLength = 0x01
	cork.gtp5g.PDUType = 0x00
	cork.gtp5g.QFI = 0x01
	cork.gtp5g.NextExtensionHeader2 = 0x00
	cork.udp.SrcPort = packet.SwapUDPPortGTPU
	cork.udp.DstPort = packet.SwapUDPPortGTPU
	//cork.udp.DgramLen = packet.SwapBytesUint16(totalLength + 8 + 16)
	cork.udp.DgramCksum = 0x0000
	cork.ipv4.VersionIhl = 0x45
	cork.ipv4.TypeOfService = 0x00
	//cork.ipv4.TotalLength = packet.SwapBytesUint16(totalLength + 8 + 16 + 20)
	//pid += 1
	//cork.ipv4.PacketID = pid
	cork.ipv4.FragmentOffset = 0x0000
	cork.ipv4.TimeToLive = 64
	cork.ipv4.NextProtoID = 17
	cork.ipv4.SrcAddr = 0x010110ac
	cork.ipv4.DstAddr = 0x020110ac
	//cork.ipv4.HdrChecksum = packet.SwapBytesUint16(packet.CalculateIPv4Checksum(ipv4))

	hwdut0, _ := net.ParseMAC("01:02:03:04:05:0a") // Port 0 of DUT
	hwdut1, _ := net.ParseMAC("01:02:03:04:05:0b") // Port 1 of DUT
	hwtst0, _ := net.ParseMAC("01:02:03:04:05:0c") // Port 0 of Tester
	hwtst1, _ := net.ParseMAC("01:02:03:04:05:0d") // Port 1 of Tester
	copy(macdut0[:], hwdut0)
	copy(macdut1[:], hwdut1)
	copy(mactst0[:], hwtst0)
	copy(mactst1[:], hwtst1)

	config := flow.Config{
		CPUList: "10-19",
	}
	flow.CheckFatal(flow.SystemInit(&config))

	ulFlow, err := flow.SetReceiver(0)
	flow.CheckFatal(err)
	dlFlow, err := flow.SetReceiver(1)
	flow.CheckFatal(err)

	flow.CheckFatal(flow.SetEnqerDeqer(ulFlow, ulEnq, ulDeq))
	flow.CheckFatal(flow.SetEnqerDeqer(dlFlow, dlEnq, dlDeq))

	flow.CheckFatal(flow.SetSender(ulFlow, 1))
	flow.CheckFatal(flow.SetSender(dlFlow, 0))

	flow.CheckFatal(flow.SystemStart())
}
