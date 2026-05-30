package capture

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
)

// Config controls how packets are captured
type Config struct {
	Interface     string        // device to capture on (empty means autodetect)
	BPFFilter     string        // if non-empty it's applied at the kernel using pcap-filter(7) syntax
	SnapLen       int           // per-packet byte limit(65535 captures full frames)
	Promisc       bool          // enables promiscuous mode on the interface
	BufferSize    int           // the kernel ring buffer in bytes (0 = pcap default)
	Timeout       time.Duration // the poll timeout for the handle
	ChannelBuffer int           // the size of the output packet channel

	// Tap, if non-nil, is invoked for every captured packet before it is
	// forwarded on the output channel. Used by --pcap-export to stream
	// packets straight to disk. Errors are the tap's own problem; capture
	// keeps running. The tap MUST be cheap - it runs on the capture
	// goroutine and any latency here backs up the kernel ring buffer.
	Tap func(gopacket.Packet)
}

func DefaultConfig() Config {
	return Config{
		SnapLen: 65535,
		Promisc: false,
		// 2MiB gives the kernel room to queue packets while Go's scheduler is
		// busy. The default pcap buffer is too small for burst traffic.
		BufferSize:    2 * 1024 * 1024,
		Timeout:       pcap.BlockForever,
		ChannelBuffer: 4096,
	}
}

// Source wraps a pcap handle and emits captured packets on a channel
type Source struct {
	handle    *pcap.Handle
	iface     string
	out       chan gopacket.Packet
	tap       func(gopacket.Packet)
	closeOnce sync.Once
}

// LinkLayerType returns the pcap link type
func (s *Source) LinkLayerType() layers.LinkType {
	return s.handle.LinkType()
}

// SetTap installs (or replaces) the per-packet tap
//
// must be called before Run starts(concurrent calls during capture are unsafe)
func (s *Source) SetTap(fn func(gopacket.Packet)) {
	s.tap = fn
}

// Interface returns the name of the interface that was opened
func (s *Source) Interface() string {
	return s.iface
}

// LinkType returns the link layer type of the capture, e.g. Ethernet
func (s *Source) LinkType() gopacket.Decoder {
	return s.handle.LinkType()
}

// Packets returns the channel of captured packets
func (s *Source) Packets() <-chan gopacket.Packet {
	return s.out
}

// Open builds a Source ready to be Run
func Open(cfg Config) (*Source, error) {
	if cfg.SnapLen <= 0 {
		cfg.SnapLen = 65535
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = pcap.BlockForever
	}
	if cfg.ChannelBuffer <= 0 {
		cfg.ChannelBuffer = 4096
	}

	iface := cfg.Interface
	if iface == "" {
		var err error
		iface, err = defaultInterface()
		if err != nil {
			return nil, fmt.Errorf("auto-detect interface: %w", err)
		}
	}

	inactive, err := pcap.NewInactiveHandle(iface)
	if err != nil {
		return nil, fmt.Errorf("create handle for %q: %w", iface, err)
	}
	defer inactive.CleanUp()

	if err := inactive.SetSnapLen(cfg.SnapLen); err != nil {
		return nil, fmt.Errorf("set snaplen: %w", err)
	}
	if err := inactive.SetPromisc(cfg.Promisc); err != nil {
		return nil, fmt.Errorf("set promisc: %w", err)
	}
	if err := inactive.SetTimeout(cfg.Timeout); err != nil {
		return nil, fmt.Errorf("set timeout: %w", err)
	}
	// packets are delivered to userspace as soon as they arrive, rather than
	// batched by the kernel(this is critical for a real-time monitor)
	if err := inactive.SetImmediateMode(true); err != nil {
		return nil, fmt.Errorf("set immediate mode: %w", err)
	}
	if cfg.BufferSize > 0 {
		if err := inactive.SetBufferSize(cfg.BufferSize); err != nil {
			return nil, fmt.Errorf("set buffer size: %w", err)
		}
	}

	handle, err := inactive.Activate()
	if err != nil {
		return nil, fmt.Errorf("activate %q: %w", iface, err)
	}
	if cfg.BPFFilter != "" {
		if err := handle.SetBPFFilter(cfg.BPFFilter); err != nil {
			handle.Close()
			return nil, fmt.Errorf("set BPF filter %q: %w", cfg.BPFFilter, err)
		}
	}

	return &Source{
		handle: handle,
		iface:  iface,
		tap:    cfg.Tap,
		out:    make(chan gopacket.Packet, cfg.ChannelBuffer),
	}, nil
}

// Run drives the capture loop
func (s *Source) Run(ctx context.Context) error {
	defer close(s.out)
	defer s.close()

	go func() {
		<-ctx.Done()
		s.close()
	}()

	src := gopacket.NewPacketSource(s.handle, s.handle.LinkType())
	src.DecodeOptions.Lazy = true

	for pkt := range src.Packets() {
		if s.tap != nil {
			s.tap(pkt)
		}
		select {
		case s.out <- pkt:
		case <-ctx.Done():
			return nil
		}
	}
	return nil
}

func (s *Source) close() {
	s.closeOnce.Do(func() { s.handle.Close() })
}
