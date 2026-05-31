package process

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/rykth/tir/internal/conn"
)

// bpf2go compiles socket_track.c with clang and writes per-arch objects plus
// Go bindings, e.g. socketTrack_x86_bpfel.{go,o}. All generated files are
// committed so contributors without clang can still build.
//
// `-target amd64` (not the lower-level `bpfel`) makes bpf2go define
// __TARGET_ARCH_x86 before invoking clang, which libbpf's bpf_tracing.h
// macros require to pick the right pt_regs register names.
//
// arm64 is intentionally omitted - the host's <asm/ptrace.h> only has the
// x86 pt_regs layout. An arm64 contributor can extend bpf/vmlinux.h and
// regenerate on their host.
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target amd64 socketTrack ./bpf/socket_track.c -- -I./bpf -I/usr/include -Wall -O2 -g

// Event types must match the enum in socket_track.c.
const (
	bpfEvtTCPConnect uint8 = 1
	bpfEvtTCPAccept  uint8 = 2
)

const (
	afInet  uint8 = 2
	afInet6 uint8 = 10
)

// bpfEvent mirrors `struct event` in socket_track.c. Field order, sizes, and
// alignment must match exactly - Go reads the ring buffer bytes directly
// into this struct via binary.Read.
//
// Layout (little-endian, total = 64 bytes):
//
//	u8  event_type
//	u8  family
//	u16 _pad
//	u32 pid
//	u32 saddr4   (network byte order, big-endian)
//	u32 daddr4   (network byte order)
//	u8  saddr6[16]
//	u8  daddr6[16]
//	u16 sport    (host byte order)
//	u16 dport    (host byte order, already ntohs'd in BPF)
//	char comm[16]
type bpfEvent struct {
	EventType uint8
	Family    uint8
	_         uint16
	PID       uint32
	SAddr4    uint32
	DAddr4    uint32
	SAddr6    [16]uint8
	DAddr6    [16]uint8
	SPort     uint16
	DPort     uint16
	Comm      [16]byte
}

// EBPFResolver attaches kprobes that fire on TCP connect / accept and emits
// the resulting (PID, comm, 5-tuple) tuples on a ring buffer.
type EBPFResolver struct {
	objs   socketTrackObjects
	links  []link.Link
	reader *ringbuf.Reader
}

// NewEBPFResolver loads the embedded BPF object, applies CO-RE relocations
// against the running kernel's BTF, and attaches the kprobes. Returns an
// error if the kernel doesn't support what we need or if capabilities are
// missing - the caller is expected to fall back to procfs in that case.
func NewEBPFResolver() (*EBPFResolver, error) {
	// Lift RLIMIT_MEMLOCK so kernels older than 5.11 (where memcg accounting
	// replaced the rlimit) can still allocate BPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock rlimit: %w", err)
	}

	r := &EBPFResolver{}
	if err := loadSocketTrackObjects(&r.objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return nil, fmt.Errorf("load BPF: %w (verifier log: %v)", err, ve)
		}
		return nil, fmt.Errorf("load BPF: %w", err)
	}

	attach := []struct {
		section string
		prog    *ebpf.Program
		kretp   bool
		symbol  string
	}{
		{"kprobe/tcp_v4_connect", r.objs.KprobeTcpV4Connect, false, "tcp_v4_connect"},
		{"kretprobe/tcp_v4_connect", r.objs.KretprobeTcpV4Connect, true, "tcp_v4_connect"},
		{"kprobe/tcp_v6_connect", r.objs.KprobeTcpV6Connect, false, "tcp_v6_connect"},
		{"kretprobe/tcp_v6_connect", r.objs.KretprobeTcpV6Connect, true, "tcp_v6_connect"},
		{"kretprobe/inet_csk_accept", r.objs.KretprobeInetCskAccept, true, "inet_csk_accept"},
	}
	for _, a := range attach {
		var l link.Link
		var err error
		if a.kretp {
			l, err = link.Kretprobe(a.symbol, a.prog, nil)
		} else {
			l, err = link.Kprobe(a.symbol, a.prog, nil)
		}
		if err != nil {
			r.closePartial()
			return nil, fmt.Errorf("attach %s: %w", a.section, err)
		}
		r.links = append(r.links, l)
	}

	reader, err := ringbuf.NewReader(r.objs.Events)
	if err != nil {
		r.closePartial()
		return nil, fmt.Errorf("open ringbuf: %w", err)
	}
	r.reader = reader
	return r, nil
}

// Method returns the resolvers status-bar label
func (*EBPFResolver) Method() string {
	return "ebpf"
}

// Run reads events from the ring buffer and emits updates
func (r *EBPFResolver) Run(ctx context.Context, out chan<- Update) error {
	defer close(out)

	// close the reader on cancellation - that unblocks reader.Read and lets
	// the loop exit cleanly
	go func() {
		<-ctx.Done()
		_ = r.reader.Close()
	}()

	for {
		rec, err := r.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("ringbuf read: %w", err)
		}
		evt, ok := decodeEvent(rec.RawSample)
		if !ok {
			continue
		}
		select {
		case <-ctx.Done():
			return nil
		case out <- evt:
		}
	}
}

// Close detaches all attached programs and releases the BPF resources
func (r *EBPFResolver) Close() error {
	if r.reader != nil {
		_ = r.reader.Close()
		r.reader = nil
	}
	r.closePartial()
	return nil
}

func (r *EBPFResolver) closePartial() {
	for _, l := range r.links {
		_ = l.Close()
	}
	r.links = nil
	_ = r.objs.Close()
}

func decodeEvent(raw []byte) (Update, bool) {
	var e bpfEvent
	if len(raw) < binary.Size(e) {
		return Update{}, false
	}
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &e); err != nil {
		return Update{}, false
	}

	var local, remote netip.Addr
	switch e.Family {
	case afInet:
		// The kernel stores skc_rcv_saddr / skc_daddr as __be32 (the IPv4
		// address in network byte order). BPF copies the 4 bytes verbatim;
		// binary.LittleEndian.Uint32 then reads them as a little-endian
		// integer above. So byte 0 of the original address is the low byte
		// of e.SAddr4. Reverse to recover the network-order byte sequence.
		local = netip.AddrFrom4([4]byte{
			byte(e.SAddr4), byte(e.SAddr4 >> 8), byte(e.SAddr4 >> 16), byte(e.SAddr4 >> 24),
		})
		remote = netip.AddrFrom4([4]byte{
			byte(e.DAddr4), byte(e.DAddr4 >> 8), byte(e.DAddr4 >> 16), byte(e.DAddr4 >> 24),
		})
	case afInet6:
		local = netip.AddrFrom16(e.SAddr6).Unmap()
		remote = netip.AddrFrom16(e.DAddr6).Unmap()
	default:
		return Update{}, false
	}

	return Update{
		Key: conn.ConnKey{
			Proto:      conn.ProtoTCP,
			LocalAddr:  local,
			LocalPort:  e.SPort,
			RemoteAddr: remote,
			RemotePort: e.DPort,
		},
		PID:  int32(e.PID),
		Name: nullTerm(e.Comm[:]),
	}, true
}

// nullTerm returns the prefix of b up to the first NUL
func nullTerm(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}
