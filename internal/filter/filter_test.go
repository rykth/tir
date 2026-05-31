package filter

import (
	"net/netip"
	"testing"

	"github.com/rykth/tir/internal/conn"
)

func mkRow(proto conn.Proto, la string, lp uint16, ra string, rp uint16, state conn.State, process, app, host string) conn.ConnView {
	return conn.ConnView{
		Key: conn.ConnKey{
			Proto:      proto,
			LocalAddr:  netip.MustParseAddr(la),
			LocalPort:  lp,
			RemoteAddr: netip.MustParseAddr(ra),
			RemotePort: rp,
		},
		State:       state,
		ProcessName: process,
		DPI:         conn.DPIInfo{Protocol: app, Host: host},
	}
}

func mustParse(t *testing.T, q string) *Filter {
	t.Helper()
	f, err := Parse(q)
	if err != nil {
		t.Fatalf("Parse(%q): %v", q, err)
	}
	return f
}

func TestEmptyFilterMatchesEverything(t *testing.T) {
	for _, q := range []string{"", "   ", "\t"} {
		f, err := Parse(q)
		if err != nil {
			t.Fatalf("Parse(%q): %v", q, err)
		}
		if !f.IsEmpty() {
			t.Errorf("Parse(%q) not empty", q)
		}
		if !f.Match(conn.ConnView{}) {
			t.Errorf("empty filter rejected zero row")
		}
	}
}

func TestNilFilterMatches(t *testing.T) {
	var f *Filter
	if !f.Match(conn.ConnView{}) {
		t.Errorf("nil filter rejected row")
	}
}

func TestPortExactMatch(t *testing.T) {
	row := mkRow(conn.ProtoTCP, "10.0.0.1", 12345, "10.0.0.2", 443, conn.StateEstablished, "curl", "HTTPS", "example.com")

	if !mustParse(t, "port:443").Match(row) {
		t.Errorf("port:443 should match 443")
	}
	if mustParse(t, "port:44").Match(row) {
		t.Errorf("port:44 should NOT match 443 (exact only)")
	}
	if !mustParse(t, "port:/44/").Match(row) {
		t.Errorf("port:/44/ should match 443")
	}
}

func TestSportDportSplit(t *testing.T) {
	row := mkRow(conn.ProtoTCP, "10.0.0.1", 12345, "10.0.0.2", 443, conn.StateEstablished, "curl", "HTTPS", "example.com")

	if !mustParse(t, "sport:12345").Match(row) {
		t.Errorf("sport miss")
	}
	if mustParse(t, "sport:443").Match(row) {
		t.Errorf("sport matched dport")
	}
	if !mustParse(t, "dport:443").Match(row) {
		t.Errorf("dport miss")
	}
	if mustParse(t, "dport:12345").Match(row) {
		t.Errorf("dport matched sport")
	}
	if !mustParse(t, "dport:443 sport:12345").Match(row) {
		t.Errorf("combined sport+dport should match")
	}
}

func TestKeywordAliases(t *testing.T) {
	row := mkRow(conn.ProtoTCP, "192.168.1.1", 1, "10.0.0.2", 80, conn.StateEstablished, "ssh", "SSH", "")

	cases := []string{
		"source:192.168",
		"src:192.168",
		"srcport:1",
		"sport:1",
		"dest:10.0.0.2",
		"destination:10.0.0.2",
		"proc:ssh",
		"process:ssh",
		"protocol:tcp",
		"proto:tcp",
		"application:ssh",
		"app:ssh",
	}
	for _, q := range cases {
		if !mustParse(t, q).Match(row) {
			t.Errorf("alias %q did not match", q)
		}
	}
}

func TestStateProtoAppCaseInsensitive(t *testing.T) {
	row := mkRow(conn.ProtoTCP, "10.0.0.1", 1, "10.0.0.2", 443, conn.StateEstablished, "", "HTTPS", "example.com")

	cases := []string{
		"state:established",
		"state:ESTABLISHED",
		"state:Est",
		"proto:tcp",
		"proto:TCP",
		"app:HTTPS",
		"app:https",
	}
	for _, q := range cases {
		if !mustParse(t, q).Match(row) {
			t.Errorf("%q did not match", q)
		}
	}
}

func TestSniSubstring(t *testing.T) {
	row := mkRow(conn.ProtoTCP, "10.0.0.1", 1, "10.0.0.2", 443, conn.StateEstablished, "", "HTTPS", "api.github.com")

	if !mustParse(t, "sni:github").Match(row) {
		t.Errorf("sni substring miss")
	}
	if !mustParse(t, "host:github.com").Match(row) {
		t.Errorf("host alias miss")
	}
	if mustParse(t, "sni:gitlab").Match(row) {
		t.Errorf("non-matching sni produced match")
	}
}

func TestRegexGlobal(t *testing.T) {
	row := mkRow(conn.ProtoTCP, "192.168.1.42", 1, "10.0.0.2", 443, conn.StateEstablished, "firefox", "HTTPS", "github.com")

	if !mustParse(t, `/192\.168\..*/`).Match(row) {
		t.Errorf("global regex miss")
	}
	if !mustParse(t, "/fire/").Match(row) {
		t.Errorf("global regex on process miss")
	}
}

func TestRegexPerKeyword(t *testing.T) {
	row := mkRow(conn.ProtoTCP, "10.0.0.1", 1, "10.0.0.2", 443, conn.StateEstablished, "chromium", "HTTPS", "")

	if !mustParse(t, "process:/chrom(e|ium)/").Match(row) {
		t.Errorf("regex on process miss")
	}
	row2 := mkRow(conn.ProtoTCP, "10.0.0.1", 1, "10.0.0.2", 443, conn.StateEstablished, "firefox", "HTTPS", "")
	if mustParse(t, "process:/chrom(e|ium)/").Match(row2) {
		t.Errorf("regex matched firefox")
	}
}

func TestAndCombination(t *testing.T) {
	row := mkRow(conn.ProtoTCP, "10.0.0.1", 12345, "10.0.0.2", 443, conn.StateEstablished, "firefox", "HTTPS", "github.com")

	if !mustParse(t, "process:firefox dport:443 sni:github").Match(row) {
		t.Errorf("combined match failed")
	}
	if mustParse(t, "process:firefox dport:80 sni:github").Match(row) {
		t.Errorf("combined match should fail when one token mismatches")
	}
}

func TestPlainTextSubstringAcrossFields(t *testing.T) {
	row := mkRow(conn.ProtoTCP, "10.0.0.1", 1, "10.0.0.2", 443, conn.StateEstablished, "firefox", "HTTPS", "github.com")

	if !mustParse(t, "github").Match(row) {
		t.Errorf("plain text 'github' should match host")
	}
	if !mustParse(t, "fox").Match(row) {
		t.Errorf("plain text 'fox' should match firefox")
	}
	if mustParse(t, "nope").Match(row) {
		t.Errorf("non-matching plain text returned match")
	}
}

func TestInvalidRegexReturnsError(t *testing.T) {
	if _, err := Parse("/(invalid/"); err == nil {
		t.Errorf("expected error from bad regex")
	}
	if _, err := Parse("process:/(invalid/"); err == nil {
		t.Errorf("expected error from bad keyword regex")
	}
}

func TestUnknownKeywordFallsBackToSubstring(t *testing.T) {
	row := mkRow(conn.ProtoTCP, "10.0.0.1", 1, "10.0.0.2", 443, conn.StateEstablished, "fakecmd", "", "")
	if mustParse(t, "cmd:fakecmd").Match(row) {
		t.Errorf("unknown keyword matched when it shouldn't")
	}

	row.ProcessName = "cmd:fakecmd"
	if !mustParse(t, "cmd:fakecmd").Match(row) {
		t.Errorf("fallback substring should match when literal appears in a field")
	}
}
