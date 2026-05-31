package process

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/rykth/tir/internal/conn"
)

func TestParseProcNetAddrIPv4(t *testing.T) {
	// 0100007F is 127.0.0.1 in /proc encoding (4 bytes little-endian)
	got, err := parseProcNetAddr("0100007F:1F90", false)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 8080)
	if got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestParseProcNetAddrIPv4Generic(t *testing.T) {
	// C0A80001 is 192.168.0.1, 0050 is 80
	got, err := parseProcNetAddr("0100A8C0:0050", false)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := netip.AddrPortFrom(netip.MustParseAddr("192.168.0.1"), 80)
	if got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestParseProcNetAddrIPv6Loopback(t *testing.T) {
	// ::1 in /proc encoding: 32 zeros except last byte 0x01, written as four
	// little-endian 32-bit words
	//
	// The four words for ::1 are {0, 0, 0, 0x01000000}
	// which printf as 00000000 00000000 00000000 01000000
	got, err := parseProcNetAddr("00000000000000000000000001000000:0050", true)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := netip.AddrPortFrom(netip.MustParseAddr("::1"), 80)
	if got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestParseProcNetAddrInvalid(t *testing.T) {
	cases := []string{
		"",
		"nocolon",
		"GGGGGGGG:0050",     // invalid hex
		"0100007F:NOTAPORT", // invalid port
		"0100007F",          // missing port
	}
	for _, c := range cases {
		if _, err := parseProcNetAddr(c, false); err == nil {
			t.Errorf("parseProcNetAddr(%q) returned no error", c)
		}
	}
}

func TestParseProcNet(t *testing.T) {
	fixture := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 11111 1 ffff 100 0 0 10 0
   1: 0100007F:CCCC 0100007F:1F90 01 00000000:00000000 00:00000000 00000000  1000        0 22222 1 ffff 100 0 0 10 0
   2: 0100007F:1F90 0100007F:CCCC 01 00000000:00000000 00:00000000 00000000  1000        0 33333 1 ffff 100 0 0 10 0
`
	entries, err := parseProcNet(strings.NewReader(fixture), false)
	if err != nil {
		t.Fatalf("parseProcNet: %v", err)
	}
	if got := len(entries); got != 3 {
		t.Fatalf("entries = %d, want 3", got)
	}
	// listening socket (state 0A, remote zero)
	if entries[0].Local.Port() != 8080 || entries[0].Inode != 11111 {
		t.Errorf("entry[0] = %+v", entries[0])
	}
	// two halves of the same loopback connection (different inodes)
	if entries[1].Inode != 22222 || entries[2].Inode != 33333 {
		t.Errorf("inodes = %d/%d, want 22222/33333", entries[1].Inode, entries[2].Inode)
	}
}

func TestParseProcNetSkipsShortLines(t *testing.T) {
	fixture := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
short line
`
	entries, err := parseProcNet(strings.NewReader(fixture), false)
	if err != nil {
		t.Fatalf("parseProcNet: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("entries = %d, want 0", len(entries))
	}
}

func TestParseSocketLink(t *testing.T) {
	cases := []struct {
		in    string
		inode uint64
		ok    bool
	}{
		{"socket:[12345]", 12345, true},
		{"socket:[0]", 0, true},
		{"socket:[", 0, false},
		{"pipe:[12345]", 0, false},
		{"/dev/null", 0, false},
		{"", 0, false},
	}
	for _, tc := range cases {
		gotInode, gotOK := parseSocketLink(tc.in)
		if gotOK != tc.ok || gotInode != tc.inode {
			t.Errorf("parseSocketLink(%q) = (%d, %v), want (%d, %v)",
				tc.in, gotInode, gotOK, tc.inode, tc.ok)
		}
	}
}

func TestReadProcessName(t *testing.T) {
	root := t.TempDir()
	pidDir := filepath.Join(root, "4242")
	if err := os.MkdirAll(pidDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pidDir, "cmdline"), []byte("/usr/bin/curl\x00-v\x00https://example.com\x00"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pidDir, "comm"), []byte("curl\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := readProcessName(root, 4242); got != "curl" {
		t.Errorf("readProcessName = %q, want curl", got)
	}
}

func TestReadProcessNameFallsBackToComm(t *testing.T) {
	root := t.TempDir()
	pidDir := filepath.Join(root, "1")
	if err := os.MkdirAll(pidDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// empty cmdline (kernel threads have this)
	if err := os.WriteFile(filepath.Join(pidDir, "cmdline"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pidDir, "comm"), []byte("kthreadd\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := readProcessName(root, 1); got != "kthreadd" {
		t.Errorf("readProcessName = %q, want kthreadd", got)
	}
}

func TestBuildInodePIDMapFromFakeRoot(t *testing.T) {
	root := t.TempDir()
	// PID 100: fd/0 -> socket:[7777], fd/1 -> /dev/null (ignored)
	mustMkSocketLink(t, root, 100, "0", "socket:[7777]")
	mustMkSocketLink(t, root, 100, "1", "/dev/null")
	// PID 200: fd/0 → socket:[9999]
	mustMkSocketLink(t, root, 200, "0", "socket:[9999]")

	m, err := buildInodePIDMap(root)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := m[7777], int32(100); got != want {
		t.Errorf("inode 7777 -> pid %d, want %d", got, want)
	}
	if got, want := m[9999], int32(200); got != want {
		t.Errorf("inode 9999 -> pid %d, want %d", got, want)
	}
	if _, ok := m[0]; ok {
		t.Errorf("/dev/null fd produced a map entry")
	}
}

func mustMkSocketLink(t *testing.T, root string, pid int, fd, target string) {
	t.Helper()
	fdDir := filepath.Join(root, strconv.Itoa(pid), "fd")
	if err := os.MkdirAll(fdDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(fdDir, fd)); err != nil {
		t.Fatal(err)
	}
}

func TestNewProcfsResolverOK(t *testing.T) {
	r, err := NewProcfsResolver()
	if err != nil {
		t.Skipf("procfs not available in this test env: %v", err)
	}
	if r.Method() != "procfs" {
		t.Errorf("Method = %q, want procfs", r.Method())
	}
}

func TestProcfsResolverSweep(t *testing.T) {
	root := t.TempDir()

	// /proc/net/tcp
	netDir := filepath.Join(root, "net")
	if err := os.MkdirAll(netDir, 0o755); err != nil {
		t.Fatal(err)
	}
	tcp := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:CCCC 0100007F:1F90 01 00000000:00000000 00:00000000 00000000  1000        0 22222 1 ffff 100 0 0 10 0
`
	if err := os.WriteFile(filepath.Join(netDir, "tcp"), []byte(tcp), 0o644); err != nil {
		t.Fatal(err)
	}
	// /proc/333/fd/0 → socket:[22222]; /proc/333/comm → "curl"
	pidDir := filepath.Join(root, "333")
	fdDir := filepath.Join(pidDir, "fd")
	if err := os.MkdirAll(fdDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("socket:[22222]", filepath.Join(fdDir, "0")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pidDir, "cmdline"), []byte("curl\x00-v\x00"), 0o644); err != nil {
		t.Fatal(err)
	}

	r := &ProcfsResolver{interval: 1, root: root}
	out := make(chan Update, 8)
	// drive a single synchronous sweep so we don't have to manage ticker timing
	r.sweep(context.Background(), out)
	close(out)

	var got []Update
	for u := range out {
		got = append(got, u)
	}
	if len(got) != 1 {
		t.Fatalf("updates = %d, want 1: %+v", len(got), got)
	}
	u := got[0]
	if u.PID != 333 || u.Name != "curl" {
		t.Errorf("update = %+v, want pid=333 name=curl", u)
	}
	if u.Key.Proto != conn.ProtoTCP || u.Key.LocalPort != 0xCCCC || u.Key.RemotePort != 8080 {
		t.Errorf("update.Key = %+v", u.Key)
	}
}
