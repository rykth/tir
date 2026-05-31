package process

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/rykth/tir/internal/conn"
)

const procSweepInterval = 2 * time.Second

// ProcfsResolver maps connections to PIDs by parsing /proc/net/{tcp,udp,tcp6,udp6}
// and walking /proc/<pid>/fd to find the owning socket inode
type ProcfsResolver struct {
	interval time.Duration
	root     string // proc root, normally "/proc" (overridable for tests)
}

// NewProcfsResolver returns a Resolver that uses /proc
func NewProcfsResolver() (*ProcfsResolver, error) {
	if _, err := os.Stat("/proc/net/tcp"); err != nil {
		return nil, fmt.Errorf("procfs unavailable: %w", err)
	}
	return &ProcfsResolver{interval: procSweepInterval, root: "/proc"}, nil
}

// Method returns the resolvers label for the status bar
func (r *ProcfsResolver) Method() string {
	return "procfs"
}

// Run drives the resolver loop
func (r *ProcfsResolver) Run(ctx context.Context, out chan<- Update) error {
	defer close(out)

	r.sweep(ctx, out)

	tick := time.NewTicker(r.interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
			r.sweep(ctx, out)
		}
	}
}

func (r *ProcfsResolver) sweep(ctx context.Context, out chan<- Update) {
	inodeMap, err := buildInodePIDMap(r.root)
	if err != nil || len(inodeMap) == 0 {
		return
	}

	// dedup name lookups within this sweep
	nameCache := make(map[int32]string, len(inodeMap))

	for _, src := range procNetSources {
		path := filepath.Join(r.root, "net", src.file)
		entries, err := readProcNet(path, src.v6)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.Inode == 0 {
				// listening sockets and sockets without an owning file have inode 0
				continue
			}
			pid, ok := inodeMap[e.Inode]
			if !ok {
				continue
			}
			name, ok := nameCache[pid]
			if !ok {
				name = readProcessName(r.root, pid)
				nameCache[pid] = name
			}
			update := Update{
				Key: conn.ConnKey{
					Proto:      src.proto,
					LocalAddr:  e.Local.Addr(),
					LocalPort:  e.Local.Port(),
					RemoteAddr: e.Remote.Addr(),
					RemotePort: e.Remote.Port(),
				},
				PID:  pid,
				Name: name,
			}
			select {
			case <-ctx.Done():
				return
			case out <- update:
			}
		}
	}
}

// procNetSource describes one /proc/net file we parse
type procNetSource struct {
	file  string
	proto conn.Proto
	v6    bool
}

var procNetSources = []procNetSource{
	{"tcp", conn.ProtoTCP, false},
	{"tcp6", conn.ProtoTCP, true},
	{"udp", conn.ProtoUDP, false},
	{"udp6", conn.ProtoUDP, true},
}

// procNetEntry is one parsed row from /proc/net/{tcp,udp,...}
type procNetEntry struct {
	Local  netip.AddrPort
	Remote netip.AddrPort
	Inode  uint64
}

func readProcNet(path string, v6 bool) ([]procNetEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseProcNet(f, v6)
}

// parseProcNet decodes /proc/net/{tcp,udp,tcp6,udp6} - we only need fields 1
// (local), 2 (remote), 9 (inode)
func parseProcNet(r io.Reader, v6 bool) ([]procNetEntry, error) {
	sc := bufio.NewScanner(r)
	// lines can be long with full IPv6 addresses - the default 64 KiB buffer
	// is plenty but be explicit so we dont silently truncate on huge boxes
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	// skip header
	if !sc.Scan() {
		return nil, sc.Err()
	}

	var out []procNetEntry
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 10 {
			continue
		}
		local, err := parseProcNetAddr(fields[1], v6)
		if err != nil {
			continue
		}
		remote, err := parseProcNetAddr(fields[2], v6)
		if err != nil {
			continue
		}
		inode, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil {
			continue
		}
		out = append(out, procNetEntry{Local: local, Remote: remote, Inode: inode})
	}
	return out, sc.Err()
}

// parseProcNetAddr decodes an "ADDR:PORT" pair from /proc/net
//
// The kernel printfs the raw struct memory, so each 32-bit word in the
// address is in CPU byte order (little-endian on x86_64). IPv4 is one
// little-endian word; IPv6 is four little-endian words.
func parseProcNetAddr(s string, v6 bool) (netip.AddrPort, error) {
	addrHex, portHex, ok := strings.Cut(s, ":")
	if !ok {
		return netip.AddrPort{}, errors.New("missing colon")
	}

	port, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("port: %w", err)
	}

	if v6 {
		if len(addrHex) != 32 {
			return netip.AddrPort{}, fmt.Errorf("v6 addr: want 32 hex chars, got %d", len(addrHex))
		}
		var addr [16]byte
		for i := range 4 {
			word, err := hex.DecodeString(addrHex[i*8 : (i+1)*8])
			if err != nil {
				return netip.AddrPort{}, fmt.Errorf("v6 addr word %d: %w", i, err)
			}
			// each 4-byte word is little-endian (reverse to get network order)
			addr[i*4+0] = word[3]
			addr[i*4+1] = word[2]
			addr[i*4+2] = word[1]
			addr[i*4+3] = word[0]
		}
		a, ok := netip.AddrFromSlice(addr[:])
		if !ok {
			return netip.AddrPort{}, errors.New("v6 addr: build failed")
		}
		return netip.AddrPortFrom(a.Unmap(), uint16(port)), nil
	}

	if len(addrHex) != 8 {
		return netip.AddrPort{}, fmt.Errorf("v4 addr: want 8 hex chars, got %d", len(addrHex))
	}
	b, err := hex.DecodeString(addrHex)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("v4 addr: %w", err)
	}
	a := netip.AddrFrom4([4]byte{b[3], b[2], b[1], b[0]})
	return netip.AddrPortFrom(a, uint16(port)), nil
}

// scans /proc/<pid>/fd for socket inodes and returns the reverse map
// (inode -> PID)
//
// best-effort: permission errors on individual PIDs are silently skipped (other
// users processes are unreadable without CAP_SYS_PTRACE)
func buildInodePIDMap(root string) (map[uint64]int32, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	out := make(map[uint64]int32, 1024)
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid64, err := strconv.ParseInt(e.Name(), 10, 32)
		if err != nil {
			continue // non-pid directory
		}
		pid := int32(pid64)
		fdDir := filepath.Join(root, e.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			target, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			inode, ok := parseSocketLink(target)
			if !ok {
				continue
			}
			out[inode] = pid
		}
	}
	return out, nil
}

// parseSocketLink extracts the inode from a "socket:[12345]" symlink target
func parseSocketLink(link string) (uint64, bool) {
	const prefix = "socket:["
	rest, ok := strings.CutPrefix(link, prefix)
	if !ok {
		return 0, false
	}
	num, _, ok := strings.Cut(rest, "]")
	if !ok {
		return 0, false
	}
	inode, err := strconv.ParseUint(num, 10, 64)
	if err != nil {
		return 0, false
	}
	return inode, true
}

// readProcessName returns argv[0]s basename from /proc/<pid>/cmdline, falling
// back to /proc/<pid>/comm (kernel-truncated to TASK_COMM_LEN-1 = 15 chars)
// when cmdline is empty or unreadable
func readProcessName(root string, pid int32) string {
	cmdline, err := os.ReadFile(filepath.Join(root, strconv.Itoa(int(pid)), "cmdline"))
	if err == nil && len(cmdline) > 0 {
		// argv is null-separated (argv[0] runs up to the first 0x00)
		if i := bytes.IndexByte(cmdline, 0); i > 0 {
			cmdline = cmdline[:i]
		}
		name := filepath.Base(strings.TrimSpace(string(cmdline)))
		if name != "" && name != "." && name != "/" {
			return name
		}
	}

	comm, err := os.ReadFile(filepath.Join(root, strconv.Itoa(int(pid)), "comm"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(comm))
}
